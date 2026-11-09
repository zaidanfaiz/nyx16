import SwiftUI
import Foundation
import UIKit
import Darwin
import CryptoKit

// Nyx16 J1–J3 measures only normal signed-app capabilities.
// No private API, protected-path probing, kernel payload, or sandbox bypass.

private enum LabPalette {
    static let midnight = Color(red: 0.025, green: 0.044, blue: 0.085)
    static let panel = Color(red: 0.060, green: 0.092, blue: 0.155)
    static let cyan = Color(red: 0.31, green: 0.88, blue: 0.99)
    static let blue = Color(red: 0.23, green: 0.48, blue: 0.99)
    static let mint = Color(red: 0.29, green: 0.93, blue: 0.71)
    static let muted = Color(red: 0.63, green: 0.70, blue: 0.80)
}

enum CheckStatus: String {
    case passed = "PASS"
    case partial = "INCONCLUSIVE"
    case failed = "FAIL"

    var tint: Color {
        switch self {
        case .passed: return LabPalette.mint
        case .partial: return .orange
        case .failed: return Color(red: 1.0, green: 0.40, blue: 0.47)
        }
    }

    var symbol: String {
        switch self {
        case .passed: return "checkmark.circle.fill"
        case .partial: return "minus.circle.fill"
        case .failed: return "xmark.circle.fill"
        }
    }
}

struct LabObservation: Identifiable {
    let id = UUID()
    let title: String
    let value: String
}

struct LabStage: Identifiable {
    let id: String
    let title: String
    let subtitle: String
    let status: CheckStatus
    let observations: [LabObservation]
}

@MainActor
final class LabViewModel: ObservableObject {
    @Published private(set) var stages: [LabStage] = []
    @Published private(set) var reportText = ""
    @Published private(set) var isRunning = false
    @Published var clipboardNotice = ""

    var hasReport: Bool { !reportText.isEmpty }
    var passedCount: Int { stages.filter { $0.status == .passed }.count }

    func runAllDiagnostics() {
        guard !isRunning else { return }
        isRunning = true
        clipboardNotice = ""
        // One run, one report. Each stage is independently classified.
        let finished = [runJ1(), runJ2(), runJ3()]
        stages = finished
        reportText = buildReport(finished)
        isRunning = false
    }

    func copyReport() {
        guard hasReport else {
            clipboardNotice = "Run diagnostics first."
            return
        }
        UIPasteboard.general.string = reportText
        clipboardNotice = "Copied on iPhone. Paste on Mac with ⌘V using Handoff."
    }

    private func observation(_ title: String, _ value: String) -> LabObservation {
        LabObservation(title: title, value: value)
    }

    private func runJ1() -> LabStage {
        let manager = FileManager.default
        guard let documents = manager.urls(for: .documentDirectory, in: .userDomainMask).first else {
            return LabStage(
                id: "J1", title: "Sandbox Baseline", subtitle: "App container file operations",
                status: .partial,
                observations: [observation("Documents", "UNAVAILABLE")]
            )
        }

        let file = documents.appendingPathComponent(".nyx16-j1-\(UUID().uuidString).tmp")
        let payload = Data("Nyx16 owned sandbox read/write baseline".utf8)
        var rows = [observation("Documents", "AVAILABLE")]
        var readMatched = false
        var cleaned = false
        do {
            try payload.write(to: file, options: .atomic)
            readMatched = try Data(contentsOf: file) == payload
        } catch {
            rows.append(observation("Local file operation", "ERROR"))
        }
        if manager.fileExists(atPath: file.path) {
            do {
                try manager.removeItem(at: file)
                cleaned = true
            } catch {
                cleaned = false
            }
        }
        rows.append(observation("Own file write/read", readMatched ? "PASS" : "FAIL"))
        rows.append(observation("Temporary cleanup", cleaned ? "PASS" : "FAIL"))

        return LabStage(
            id: "J1", title: "Sandbox Baseline", subtitle: "App container file operations",
            status: readMatched && cleaned ? .passed : .partial, observations: rows
        )
    }

    private func runJ2() -> LabStage {
        let manager = FileManager.default
        let home = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
            .resolvingSymlinksInPath().standardizedFileURL.path
        let documents = manager.urls(for: .documentDirectory, in: .userDomainMask).first
        let locations: [(String, URL?)] = [
            ("Documents", documents),
            ("Library", manager.urls(for: .libraryDirectory, in: .userDomainMask).first),
            ("Caches", manager.urls(for: .cachesDirectory, in: .userDomainMask).first),
            ("tmp", manager.temporaryDirectory)
        ]
        var rows: [LabObservation] = []
        var allReadable = true
        for (name, url) in locations {
            guard let url else {
                allReadable = false
                rows.append(observation(name, "UNAVAILABLE"))
                continue
            }
            let normalized = url.resolvingSymlinksInPath().standardizedFileURL.path
            let inside = normalized.hasPrefix(home + "/")
            let readable = inside && manager.isReadableFile(atPath: normalized)
            if !readable { allReadable = false }
            rows.append(observation(name, readable ? "EXISTS / READABLE" : "NOT VERIFIED"))
        }

        rows.append(observation("Protected data available",
                                UIApplication.shared.isProtectedDataAvailable ? "YES" : "NO"))
        var attributeMatched = false
        var contentMatched = false
        var cleaned = false
        if let documents,
           documents.resolvingSymlinksInPath().standardizedFileURL.path.hasPrefix(home + "/") {
            let file = documents.appendingPathComponent(".nyx16-j2-\(UUID().uuidString).tmp")
            let payload = Data("Nyx16 own-file Data Protection test".utf8)
            do {
                try payload.write(to: file, options: .atomic)
                try manager.setAttributes(
                    [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                    ofItemAtPath: file.path
                )
                let attrs = try manager.attributesOfItem(atPath: file.path)
                let observed = attrs[.protectionKey] as? FileProtectionType
                attributeMatched = observed == .completeUntilFirstUserAuthentication
                contentMatched = try Data(contentsOf: file) == payload
            } catch {
                rows.append(observation("Protection operation", "INCONCLUSIVE"))
            }
            if manager.fileExists(atPath: file.path) {
                do {
                    try manager.removeItem(at: file)
                    cleaned = true
                } catch {
                    cleaned = false
                }
            }
        }
        rows.append(observation("File protection attribute", attributeMatched ? "MATCH" : "NOT CONFIRMED"))
        rows.append(observation("Own protected file read", contentMatched ? "PASS" : "NOT CONFIRMED"))
        rows.append(observation("Temporary cleanup", cleaned ? "PASS" : "NOT CONFIRMED"))
        rows.append(observation("Entitlements", "LOCAL MAC INSPECTION ONLY"))

        return LabStage(
            id: "J2", title: "Security Boundaries", subtitle: "Own directories & Data Protection",
            status: allReadable && attributeMatched && contentMatched && cleaned ? .passed : .partial,
            observations: rows
        )
    }

    private func runJ3() -> LabStage {
        let uid = getuid()
        let effectiveUID = geteuid()
        var rows: [LabObservation] = [
            observation("Process UID / EUID", "\(uid) / \(effectiveUID)"),
            observation("Execution context", "SIGNED APP PROCESS")
        ]

        // Read 8 bytes of the executable's own Mach-O file header only.
        // This is format identification, NOT verification of an Apple signature.
        var machORecognized = false
        if let executable = Bundle.main.executableURL {
            do {
                let file = try FileHandle(forReadingFrom: executable)
                let bytes = try file.read(upToCount: 8) ?? Data()
                try file.close()
                let raw = Array(bytes)
                machORecognized = raw.count == 8 &&
                    Array(raw[0..<4]) == [0xcf, 0xfa, 0xed, 0xfe] &&
                    Array(raw[4..<8]) == [0x0c, 0x00, 0x00, 0x01]
            } catch {
                machORecognized = false
            }
        }
        rows.append(observation("Own executable", machORecognized ? "ARM64 MACH-O HEADER" : "NOT VERIFIED"))

        // Deterministic trusted-code execution check, not arbitrary code execution.
        let digest = SHA256.hash(data: Data("abc".utf8))
            .map { String(format: "%02x", $0) }.joined()
        let knownAnswer =
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        let selfCheckPassed = digest == knownAnswer
        rows.append(observation("Compiled code self-check", selfCheckPassed ? "PASS" : "FAIL"))
        rows.append(observation("Apple signature verification", "NOT PERFORMED"))
        rows.append(observation("Arbitrary code execution", "NOT TESTED"))
        rows.append(observation("Sandbox / kernel exploit", "NOT TESTED"))

        return LabStage(
            id: "J3", title: "Runtime Integrity", subtitle: "Own Mach-O header & deterministic self-test",
            status: machORecognized && selfCheckPassed ? .passed : .partial,
            observations: rows
        )
    }

    private func buildReport(_ results: [LabStage]) -> String {
        var lines = [
            "NYX16 DEVICE LAB — UNIFIED J1–J3 REPORT",
            "iOS: \(UIDevice.current.systemVersion)",
            "Process UID: \(getuid())",
            "Effective UID: \(geteuid())",
            "Device identifiers collected: NO",
            "Network requests: NONE",
            "Protected system paths accessed: NO",
            "Other app containers accessed: NO"
        ]
        for stage in results {
            lines.append("")
            lines.append("[\(stage.id)] \(stage.title.uppercased()): \(stage.status.rawValue)")
            for row in stage.observations {
                lines.append("\(row.title): \(row.value)")
            }
        }
        lines += [
            "",
            "J3 PASS means only that the signed app ran its own test code.",
            "SIGNATURE BYPASS: NOT TESTED",
            "SANDBOX ESCAPE: NOT TESTED",
            "KERNEL PRIVILEGE: NOT TESTED",
            "JAILBREAK: NOT DEMONSTRATED"
        ]
        return lines.joined(separator: "\n")
    }
}

// Original scalable Nyx16 emblem, rendered natively in SwiftUI (no external asset).
private struct NyxMark: View {
    var size: CGFloat = 82

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.24, style: .continuous)
                .fill(LinearGradient(
                    colors: [Color(red: 0.10, green: 0.24, blue: 0.40), LabPalette.midnight],
                    startPoint: .topLeading, endPoint: .bottomTrailing
                ))
            RoundedRectangle(cornerRadius: size * 0.24, style: .continuous)
                .strokeBorder(LabPalette.cyan.opacity(0.42), lineWidth: 1)
            Circle()
                .trim(from: 0.05, to: 0.82)
                .stroke(LabPalette.cyan.opacity(0.55),
                        style: StrokeStyle(lineWidth: 1.8, lineCap: .round))
                .frame(width: size * 0.73, height: size * 0.73)
                .rotationEffect(.degrees(-32))
            Path { path in
                let k = size / 82
                path.move(to: CGPoint(x: 25*k, y: 56*k))
                path.addLine(to: CGPoint(x: 25*k, y: 25*k))
                path.addLine(to: CGPoint(x: 54*k, y: 56*k))
                path.addLine(to: CGPoint(x: 54*k, y: 25*k))
            }
            .stroke(
                LinearGradient(colors: [LabPalette.cyan, Color.white, LabPalette.blue],
                               startPoint: .topLeading, endPoint: .bottomTrailing),
                style: StrokeStyle(lineWidth: size * 0.078, lineCap: .round, lineJoin: .round)
            )
            Text("16")
                .font(.system(size: size * 0.13, weight: .heavy, design: .rounded))
                .foregroundStyle(LabPalette.cyan)
                .offset(x: size * 0.26, y: size * 0.26)
        }
        .frame(width: size, height: size)
        .shadow(color: LabPalette.cyan.opacity(0.15), radius: 18, y: 6)
        .accessibilityLabel("Nyx16 logo")
    }
}

private struct StageCard: View {
    let stage: LabStage
    @State private var isExpanded = true

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.2)) { isExpanded.toggle() }
            } label: {
                HStack(spacing: 12) {
                    Text(stage.id)
                        .font(.system(.caption, design: .monospaced).weight(.bold))
                        .foregroundStyle(LabPalette.cyan)
                        .frame(width: 40, height: 40)
                        .background(LabPalette.cyan.opacity(0.10), in: RoundedRectangle(cornerRadius: 12))
                    VStack(alignment: .leading, spacing: 3) {
                        Text(stage.title)
                            .font(.system(.subheadline, weight: .semibold))
                            .foregroundStyle(.white)
                        Text(stage.subtitle)
                            .font(.caption2)
                            .foregroundStyle(LabPalette.muted)
                    }
                    Spacer(minLength: 4)
                    Image(systemName: stage.status.symbol)
                        .foregroundStyle(stage.status.tint)
                    Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                        .font(.caption)
                        .foregroundStyle(LabPalette.muted)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if isExpanded {
                Rectangle()
                    .fill(Color.white.opacity(0.09))
                    .frame(height: 1)
                    .padding(.vertical, 14)
                ForEach(stage.observations) { row in
                    HStack(alignment: .top, spacing: 12) {
                        Text(row.title)
                            .foregroundStyle(LabPalette.muted)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        Text(row.value)
                            .fontWeight(.medium)
                            .foregroundStyle(.white)
                            .multilineTextAlignment(.trailing)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                    .font(.system(size: 12, design: .monospaced))
                    .padding(.vertical, 5)
                }
            }
        }
        .padding(16)
        .background(LabPalette.panel.opacity(0.92), in: RoundedRectangle(cornerRadius: 20))
        .overlay {
            RoundedRectangle(cornerRadius: 20)
                .strokeBorder(Color.white.opacity(0.08), lineWidth: 1)
        }
    }
}

struct ContentView: View {
    @StateObject private var model = LabViewModel()

    var body: some View {
        ZStack {
            LabPalette.midnight.ignoresSafeArea()
            RadialGradient(colors: [LabPalette.blue.opacity(0.22), .clear],
                           center: .topTrailing, startRadius: 16, endRadius: 340)
                .ignoresSafeArea().allowsHitTesting(false)

            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    HStack(alignment: .center, spacing: 16) {
                        NyxMark(size: 72)
                        VStack(alignment: .leading, spacing: 5) {
                            Text("NYX16")
                                .font(.system(size: 29, weight: .heavy, design: .rounded))
                                .tracking(3)
                                .foregroundStyle(.white)
                            Text("DEVICE RESEARCH LAB")
                                .font(.system(size: 10, weight: .bold, design: .monospaced))
                                .tracking(2)
                                .foregroundStyle(LabPalette.cyan)
                        }
                        Spacer()
                    }
                    .padding(.top, 8)

                    VStack(alignment: .leading, spacing: 16) {
                        HStack {
                            Label("ON-DEVICE DIAGNOSTICS", systemImage: "waveform.path.ecg")
                                .font(.system(size: 11, weight: .bold, design: .monospaced))
                                .tracking(0.6)
                                .foregroundStyle(LabPalette.cyan)
                            Spacer()
                            Text("v0.3")
                                .font(.caption2.monospaced())
                                .foregroundStyle(LabPalette.muted)
                        }
                        Text("One run.\nThree research stages.")
                            .font(.system(size: 28, weight: .bold, design: .rounded))
                            .foregroundStyle(.white)
                            .fixedSize(horizontal: false, vertical: true)
                        Text("J1 Sandbox  •  J2 Security  •  J3 Runtime")
                            .font(.system(size: 12))
                            .foregroundStyle(LabPalette.muted)

                        HStack(spacing: 9) {
                            ForEach(["J1", "J2", "J3"], id: \.self) { id in
                                HStack(spacing: 5) {
                                    Image(systemName: model.stages.first(where: { $0.id == id })?.status.symbol ?? "circle")
                                        .foregroundStyle(model.stages.first(where: { $0.id == id })?.status.tint ?? LabPalette.muted)
                                    Text(id).font(.system(size: 12, weight: .semibold, design: .monospaced))
                                }
                                .padding(.horizontal, 12)
                                .padding(.vertical, 9)
                                .background(Color.white.opacity(0.065), in: Capsule())
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(20)
                    .background(
                        LinearGradient(
                            colors: [Color(red: 0.08, green: 0.19, blue: 0.29), LabPalette.panel],
                            startPoint: .topLeading, endPoint: .bottomTrailing
                        ),
                        in: RoundedRectangle(cornerRadius: 24)
                    )
                    .overlay {
                        RoundedRectangle(cornerRadius: 24)
                            .strokeBorder(LabPalette.cyan.opacity(0.15), lineWidth: 1)
                    }

                    Button {
                        model.runAllDiagnostics()
                    } label: {
                        HStack(spacing: 12) {
                            Image(systemName: "play.fill")
                            Text(model.isRunning ? "RUNNING..." : (model.hasReport ? "RUN ALL AGAIN" : "RUN FULL DIAGNOSTICS"))
                                .tracking(0.8)
                            Spacer()
                            Image(systemName: "arrow.right")
                        }
                        .font(.system(size: 14, weight: .heavy, design: .rounded))
                        .foregroundStyle(LabPalette.midnight)
                        .padding(18)
                        .background(
                            LinearGradient(colors: [LabPalette.cyan, Color(red: 0.40, green: 0.67, blue: 1)],
                                           startPoint: .leading, endPoint: .trailing),
                            in: RoundedRectangle(cornerRadius: 17)
                        )
                    }
                    .disabled(model.isRunning)
                    .buttonStyle(.plain)
                    .accessibilityIdentifier("runFullDiagnostics")

                    if model.hasReport {
                        HStack(spacing: 12) {
                            Button {
                                model.copyReport()
                            } label: {
                                Label("Copy Report", systemImage: "doc.on.doc")
                                    .frame(maxWidth: .infinity)
                            }
                            .accessibilityIdentifier("copySecurityReport")

                            ShareLink(item: model.reportText) {
                                Label("AirDrop / Share", systemImage: "square.and.arrow.up")
                                    .frame(maxWidth: .infinity)
                            }
                            .accessibilityIdentifier("shareSecurityReport")
                        }
                        .font(.system(size: 13, weight: .semibold))
                        .tint(.white)
                        .buttonStyle(.bordered)

                        if !model.clipboardNotice.isEmpty {
                            Text(model.clipboardNotice)
                                .font(.caption)
                                .foregroundStyle(LabPalette.cyan)
                                .accessibilityIdentifier("clipboardCopyStatus")
                        }

                        HStack {
                            Text("RESULTS")
                                .font(.system(size: 12, weight: .bold, design: .monospaced))
                                .tracking(1.8)
                                .foregroundStyle(LabPalette.muted)
                            Spacer()
                            Text("\(model.passedCount)/3 passed")
                                .font(.system(size: 12, weight: .semibold, design: .monospaced))
                                .foregroundStyle(LabPalette.mint)
                        }
                        ForEach(model.stages) { stage in
                            StageCard(stage: stage)
                        }
                    } else {
                        HStack(spacing: 10) {
                            Image(systemName: "info.circle")
                                .foregroundStyle(LabPalette.cyan)
                            Text("Tap once to run J1, J2 and J3 on this iPhone. Results stay local until you copy or share.")
                                .font(.caption)
                                .foregroundStyle(LabPalette.muted)
                        }
                        .padding(.horizontal, 5)
                    }

                    Text("AUTHORIZED RESEARCH  •  NO EXPLOIT EXECUTION\nNo protected paths, kernel modification or DFU payloads.")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(LabPalette.muted.opacity(0.8))
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: .infinity)
                        .padding(.top, 10)
                }
                .padding(.horizontal, 20)
                .padding(.bottom, 34)
            }
        }
        .preferredColorScheme(.dark)
    }
}

@main
struct Nyx16LabApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
