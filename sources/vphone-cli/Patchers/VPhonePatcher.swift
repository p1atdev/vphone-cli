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

        if let im4p = try? IM4P(data: fileData) {
            isIM4P = true
            originalFourCC = im4p.fourcc
            originalDescription = im4p.description
            if let payload = im4p.payload {
                try payload.decompress()
                workingData = payload.data
            }
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
                newIm4p.description = originalDescription
                let newPayload = IM4PData(data: finalOutputData)
                newPayload.compression = Image4.Compression.none
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
