import AppKit
import ArgumentParser
import Foundation

struct VPhoneCLI: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "vphone-cli",
        abstract: "Boot a virtual iPhone (PV=3)",
        discussion: """
            Creates a Virtualization.framework VM with platform version 3 (vphone)
            and boots it into DFU mode for firmware loading via irecovery.

            Requires:
              - macOS 15+ (Sequoia or later)
              - SIP/AMFI disabled
              - Signed with vphone entitlements (done automatically by wrapper script)

            Example:
              vphone-cli --rom firmware/rom.bin --disk firmware/disk.img
            """,
        subcommands: [Boot.self, Patch.self, GenManifest.self],
        defaultSubcommand: Boot.self
    )

    struct Boot: AsyncParsableCommand {
        static var configuration = CommandConfiguration(
            commandName: "boot",
            abstract: "Boot the virtual machine"
        )

        @Option(help: "Path to the AVPBooter / ROM binary")
        var rom: String

        @Option(help: "Path to the disk image")
        var disk: String

        @Option(help: "Path to NVRAM storage (created/overwritten)")
        var nvram: String = "nvram.bin"

        @Option(help: "Path to machineIdentifier file (created if missing)")
        var machineId: String

        @Option(help: "Number of CPU cores")
        var cpu: Int = 8

        @Option(help: "Memory size in MB")
        var memory: Int = 8192

        @Option(help: "Path to SEP storage file (created if missing)")
        var sepStorage: String

        @Option(help: "Path to SEP ROM binary")
        var sepRom: String

        @Flag(help: "Boot into DFU mode")
        var dfu: Bool = false

        @Option(help: "Display width in pixels (default: 1290)")
        var screenWidth: Int = 1290

        @Option(help: "Display height in pixels (default: 2796)")
        var screenHeight: Int = 2796

        @Option(help: "Display pixels per inch (default: 460)")
        var screenPpi: Int = 460

        @Option(help: "Window scale divisor (default: 3.0)")
        var screenScale: Double = 3.0

        @Flag(help: "Run without GUI (headless)")
        var noGraphics: Bool = false

        @MainActor
        func run() async throws {
            let app = NSApplication.shared
            let delegate = VPhoneAppDelegate(config: self)
            app.delegate = delegate
            app.run()
        }
    }

    struct Patch: AsyncParsableCommand {
        static var configuration = CommandConfiguration(
            commandName: "patch",
            abstract: "Patch firmware components (boot chain / kernel)"
        )

        @Argument(help: "Component to patch (avpbooter, iboot, txm, kernel, cfw)")
        var component: String

        @Argument(help: "Input firmware file path")
        var input: String

        @Option(help: "Output patched file path (defaults to overwriting input)")
        var output: String?

        func run() async throws {
            print("=== vphone-patcher ===")
            print("Component: \(component)")
            print("Input    : \(input)")
            if let out = output {
                print("Output   : \(out)")
            }
            print("")

            try VPhonePatcher.patch(component: component, inputPath: input, outputPath: output)
        }
    }

    struct GenManifest: AsyncParsableCommand {
        static var configuration = CommandConfiguration(
            commandName: "gen-manifest",
            abstract: "Generate hybrid BuildManifest.plist and Restore.plist"
        )

        @Argument(help: "Path to iPhone restore directory")
        var iphoneDir: String

        @Argument(help: "Path to cloudOS restore directory")
        var cloudosDir: String

        func run() async throws {
            print("=== vphone-manifest ===")
            print("iPhone Dir  : \(iphoneDir)")
            print("cloudOS Dir : \(cloudosDir)")
            print("")

            try VPhoneManifest.generate(iphoneDir: iphoneDir, cloudosDir: cloudosDir)
        }
    }
}
