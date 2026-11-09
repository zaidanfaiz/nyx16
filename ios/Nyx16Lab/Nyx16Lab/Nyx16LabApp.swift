import SwiftUI
import Foundation
import UIKit
import Darwin

/// Deliberately limited to stock iOS application APIs.
/// This app cannot inspect another app's container or modify protected system paths.
@MainActor
final class LabViewModel: ObservableObject {
    @Published var report = "No test has run. Tap Run Sandbox Test to collect local evidence."

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
