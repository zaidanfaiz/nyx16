import SwiftUI
import Foundation
import UIKit
import Darwin

/// Deliberately limited to stock iOS application APIs.
/// This app cannot inspect another app's container or modify protected system paths.
@MainActor
final class LabViewModel: ObservableObject {
    @Published var report = "No test has run. Tap Run Sandbox Test to collect local evidence."
    @Published var securityReport = "J2 has not run. Tap Run J2 Diagnostics to inspect only this app and its own files."

    func runSandboxTest() {
        let fileManager = FileManager.default
        let documentURL = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first

        var lines = [
            "NYX16 ON-DEVICE LAB · BASELINE",
            "Mode: normal signed iOS application",
            "Installed iOS: \(UIDevice.current.systemVersion)",
            "Bundle ID: \(Bundle.main.bundleIdentifier ?? "UNKNOWN")",
            "Process UID: \(getuid())",
            "Effective UID: \(geteuid())",
            "Device identifiers collected: NO",
            "Network requests: NONE",
            "Privileged access attempted: NO",
            "",
        ]

        guard let documentURL else {
            lines.append("Application Documents directory: UNAVAILABLE")
            lines.append("Sandbox test: INCONCLUSIVE")
            report = lines.joined(separator: "\n")
            return
        }

        lines.append("Application Documents directory: AVAILABLE")
        let probe = documentURL.appendingPathComponent("nyx16-local-probe.txt")
        let payload = "Nyx16 local container test. No system files were accessed."

        do {
            try Data(payload.utf8).write(to: probe, options: .atomic)
            let readBack = try Data(contentsOf: probe)
            let matched = String(data: readBack, encoding: .utf8) == payload
            // Cleanup always remains inside the application's Documents directory.
            try fileManager.removeItem(at: probe)

            lines.append("Own sandbox file write/read: \(matched ? "PASS" : "FAIL")")
            lines.append("Temporary test file cleanup: PASS")
        } catch {
            lines.append("Own sandbox file write/read: FAIL")
            lines.append("Local error: \(error.localizedDescription)")
            if fileManager.fileExists(atPath: probe.path) {
                try? fileManager.removeItem(at: probe)
            }
        }

        lines += [
            "",
            "KERNEL PRIVILEGE: NOT TESTED",
            "SANDBOX ESCAPE: NOT TESTED",
            "JAILBREAK: NOT DEMONSTRATED",
            "",
            "A successful sandbox write proves only normal app-container access."
        ]
        report = lines.joined(separator: "\n")
    }

    /// Read-only checks of our container plus one temporary Data Protection file.
    /// Does not query protected paths, other app containers, DFU or kernel interfaces.
    func runJ2Diagnostics() {
        let manager = FileManager.default
        let home = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true).resolvingSymlinksInPath().standardizedFileURL.path
        let documents = manager.urls(for: .documentDirectory, in: .userDomainMask).first
        let library = manager.urls(for: .libraryDirectory, in: .userDomainMask).first
        let caches = manager.urls(for: .cachesDirectory, in: .userDomainMask).first
        let tmp = manager.temporaryDirectory

        var lines = [
            "NYX16 J2 · SECURITY DIAGNOSTICS",
            "Installed iOS: \(UIDevice.current.systemVersion)",
            "Process UID: \(getuid())",
            "Effective UID: \(geteuid())",
            "Device identifiers collected: NO",
            "Network requests: NONE",
            "",
            "APP CONTAINER DIRECTORY INVENTORY"
        ]

        let locations: [(String, URL?)] = [
            ("Documents", documents),
            ("Library", library),
            ("Caches", caches),
            ("tmp", tmp)
        ]
        for (name, location) in locations {
            guard let location else {
                lines.append("\(name): UNAVAILABLE")
                continue
            }
            let normalized = location.resolvingSymlinksInPath().standardizedFileURL.path
            guard normalized.hasPrefix(home + "/") else {
                lines.append("\(name): NOT WITHIN OWN CONTAINER")
                continue
            }
            let exists = manager.fileExists(atPath: normalized)
            let readable = exists && manager.isReadableFile(atPath: normalized)
            lines.append("\(name): \(exists ? "EXISTS" : "MISSING"), \(readable ? "READABLE" : "NOT READABLE")")
        }

        lines += [
            "",
            "CODE SIGNING ENTITLEMENTS",
            "On-device entitlement inspection: NOT PERFORMED",
            "Verify the signed .app using tools/inspect_lab_entitlements.py on Mac.",
            "No code-signature bypass attempted.",
            "",
            "FILE DATA PROTECTION",
            "Protected data currently available: \(UIApplication.shared.isProtectedDataAvailable ? "YES" : "NO")"
        ]

        if let documents, documents.resolvingSymlinksInPath().standardizedFileURL.path.hasPrefix(home + "/") {
            let testFile = documents.appendingPathComponent("nyx16-j2-protection-test.txt")
            // Refuse to overwrite a preexisting user/application file.
            guard !manager.fileExists(atPath: testFile.path) else {
                lines.append("Data Protection test: SKIPPED (file already exists)")
                lines.append("JAILBREAK: NOT DEMONSTRATED")
                securityReport = lines.joined(separator: "\n")
                return
            }
            do {
                try Data("Nyx16 J2 harmless temporary test".utf8).write(to: testFile, options: .atomic)
                try manager.setAttributes(
                    [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                    ofItemAtPath: testFile.path
                )
                let attrs = try manager.attributesOfItem(atPath: testFile.path)
                let observed = attrs[.protectionKey] as? FileProtectionType
                lines.append("Requested protection: COMPLETE_UNTIL_FIRST_AUTHENTICATION")
                lines.append("Protection attribute: \(observed == .completeUntilFirstUserAuthentication ? "MATCH" : "NOT CONFIRMED")")
                let content = try Data(contentsOf: testFile)
                lines.append("Own protected file read: \(String(data: content, encoding: .utf8) == "Nyx16 J2 harmless temporary test" ? "PASS" : "FAIL")")
            } catch {
                lines.append("Data Protection test: INCONCLUSIVE (local API error)")
            }
            // Cleanup remains inside the application Documents directory only.
            if manager.fileExists(atPath: testFile.path) {
                do {
                    try manager.removeItem(at: testFile)
                    lines.append("Temporary protected file cleanup: PASS")
                } catch {
                    lines.append("Temporary protected file cleanup: FAIL")
                }
            }
        } else {
            lines.append("Data Protection test: INCONCLUSIVE (Documents outside expected container)")
        }

        lines += [
            "",
            "PROTECTED SYSTEM PATHS: NOT ACCESSED",
            "OTHER APP CONTAINERS: NOT ACCESSED",
            "SANDBOX ESCAPE: NOT TESTED",
            "KERNEL PRIVILEGE: NOT TESTED",
            "JAILBREAK: NOT DEMONSTRATED",
            "",
            "These are ordinary authorized app operations, not an exploit."
        ]
        securityReport = lines.joined(separator: "\n")
    }

}

struct ContentView: View {
    @StateObject private var model = LabViewModel()

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    Text("Nyx16 Device Lab")
                        .font(.largeTitle.weight(.bold))

                    Text("Jailbreak research — authorized device, stock app sandbox baseline.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)

                    Button {
                        model.runSandboxTest()
                    } label: {
                        Label("Run Sandbox Test", systemImage: "checkmark.shield")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("runSandboxTest")

                    Button {
                        model.runJ2Diagnostics()
                    } label: {
                        Label("Run J2 Diagnostics", systemImage: "lock.shield")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier("runJ2Diagnostics")

                    Text(model.securityReport)
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))

                    Text(model.report)
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))

                    Text("This application does not use private APIs, send DFU payloads, bypass code signing, or probe protected system paths.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding()
            }
            .navigationTitle("Nyx16Lab")
            .navigationBarTitleDisplayMode(.inline)
        }
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
