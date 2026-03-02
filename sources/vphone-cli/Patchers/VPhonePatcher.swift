import Foundation
import Image4

/// Entry point for firmware patching — delegates to component-specific patchers.
enum VPhonePatcher {
    static func patch(component: String, inputPath: String, outputPath: String?) throws {
        let inputURL = URL(fileURLWithPath: inputPath)
        let outputURL = URL(fileURLWithPath: outputPath ?? inputPath)
        let fileData = try Data(contentsOf: inputURL)
        var workingData: Data = fileData
        var isIM4P = false
        var originalFourCC: String? = nil
        var originalDescription: String? = nil
        var originalProperties: [ManifestProperty] = []

        if let im4p = try? IM4P(data: fileData) {
            isIM4P = true
            originalFourCC = im4p.fourcc
            originalDescription = im4p.description
            if let payload = im4p.payload {
                try payload.decompress()
                workingData = payload.data
            }
            originalProperties = im4p.properties
            print("  [+] Detected IM4P container (\(originalFourCC ?? "unknown"))")
        }

        let patcher: Patcher
        switch component.lowercased() {
        case "avpbooter": patcher = AVPBooterPatcher(data: workingData)
        case "txm": patcher = TXMPatcher(data: workingData)
        case "ibss", "ibec", "llb": patcher = IBootPatcher(data: workingData, mode: component)
        case "kernel": patcher = try KernelPatcher(data: workingData)
        default:
            throw NSError(
                domain: "VPhonePatcher", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Unsupported component: \(component)"])
        }

        let count = try patcher.apply()
        if count > 0 {
            var finalOutputData = patcher.data
            if isIM4P {
                print("  [*] Repackaging as IM4P...")
                let newIm4p = IM4P()
                newIm4p.fourcc = originalFourCC
                let newPayload = IM4PData(data: finalOutputData)
                // TXM and kernel: repackage with lzfse compression and preserve PAYP
                // properties, matching Python's preserve_payp=True path.
                // Description is intentionally nil — pyimg4's `im4p create` CLI
                // drops it, producing IA5String(""). Matching this exactly ensures
                // byte-identical IM4P output, which avoids any hash mismatch with
                // downstream tools (idevicerestore personalization, ramdisk_build).
                // iBoot components (ibss/ibec/llb): store uncompressed without PAYP.
                let needsLzfseAndPayp = ["txm", "kernel"].contains(component.lowercased())
                if needsLzfseAndPayp {
                    newIm4p.description = nil
                    newIm4p.properties = originalProperties
                    try newPayload.compress(to: .lzfse)
                } else {
                    newIm4p.description = originalDescription
                }
                newIm4p.payload = newPayload
                finalOutputData = try newIm4p.output()
            }
            try finalOutputData.write(to: outputURL)
            print("  [+] Successfully applied \(count) patches to \(outputURL.lastPathComponent)")
        } else {
            print("  [-] No patches applied.")
        }
    }
}
