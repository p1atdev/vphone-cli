import Foundation

// MARK: - Patch Logging Helpers

/// Provides Python-compatible BEFORE/AFTER context logging for firmware patches.
enum PatchLog {
    /// Number of context instructions to show before and after the patched region.
    private static let contextLines = 3

    /// Print BEFORE/AFTER context for a patch at a given file offset.
    ///
    /// - Parameters:
    ///   - data: The binary data (post-patch state).
    ///   - at: File offset of first patched instruction.
    ///   - count: Number of consecutively patched instructions.
    ///   - label: Human-readable label for the patch.
    ///   - old: Original instruction values (before patch).
    ///   - new: New instruction values (after patch).
    static func context(
        data: Data, at offset: Int, count: Int, label: String,
        old: [UInt32], new: [UInt32]
    ) {
        let regionStart = max(offset - contextLines * 4, 0)
        let regionEnd = min(offset + (count + contextLines) * 4, data.count)
        let patchEnd = offset + count * 4

        print("  [+] \(label) at 0x\(String(offset, radix: 16))")
        print("      BEFORE:")
        printRegion(
            data: data, from: regionStart, to: regionEnd,
            patchStart: offset, patchEnd: patchEnd,
            overrides: makeOverrides(at: offset, values: old),
            marker: nil)
        print("      AFTER:")
        printRegion(
            data: data, from: regionStart, to: regionEnd,
            patchStart: offset, patchEnd: patchEnd,
            overrides: nil,
            marker: "PATCHED")
    }

    /// Print BEFORE/AFTER context when entirely new instructions are injected (e.g., stub replacement).
    static func contextNew(
        data: Data, at offset: Int, count: Int, label: String,
        old: [UInt32], new: [UInt32]
    ) {
        let regionStart = max(offset - contextLines * 4, 0)
        let regionEnd = min(offset + (count + contextLines) * 4, data.count)
        let patchEnd = offset + count * 4

        print("  [+] \(label) at 0x\(String(offset, radix: 16))")
        print("      BEFORE:")
        printRegion(
            data: data, from: regionStart, to: regionEnd,
            patchStart: offset, patchEnd: patchEnd,
            overrides: makeOverrides(at: offset, values: old),
            marker: nil)
        print("      AFTER:")
        printRegion(
            data: data, from: regionStart, to: regionEnd,
            patchStart: offset, patchEnd: patchEnd,
            overrides: nil,
            marker: "NEW")
    }

    // MARK: - Private

    private static func makeOverrides(at offset: Int, values: [UInt32]) -> [Int: UInt32] {
        var dict: [Int: UInt32] = [:]
        for (i, v) in values.enumerated() {
            dict[offset + i * 4] = v
        }
        return dict
    }

    private static func printRegion(
        data: Data, from regionStart: Int, to regionEnd: Int,
        patchStart: Int, patchEnd: Int,
        overrides: [Int: UInt32]?,
        marker: String?
    ) {
        data.withUnsafeBytes { buffer in
            for off in stride(from: regionStart, to: regionEnd, by: 4) {
                guard off + 4 <= buffer.count else { break }
                let insn: UInt32
                if let overrides = overrides, let v = overrides[off] {
                    insn = v
                } else {
                    insn = buffer.load(fromByteOffset: off, as: UInt32.self)
                }
                let hex = ARM64.hexBytes(insn)
                let asm = ARM64.disassemble(insn, at: off)
                let isPatch = off >= patchStart && off < patchEnd
                if isPatch, let marker = marker {
                    let padded = asm.padding(toLength: 40, withPad: " ", startingAt: 0)
                    print(
                        String(
                            format: "        0x%06x: %@  %@ ◄━━ %@", off, hex, padded as NSString,
                            marker as NSString))
                } else {
                    print(String(format: "        0x%06x: %@  %@", off, hex, asm as NSString))
                }
            }
        }
    }

    // MARK: - Verification Summary

    /// Print a verification summary table.
    /// Each entry is `(patchName, offset, count)`.
    static func summary(component: String, patches: [(name: String, offset: Int, count: Int)]) {
        guard !patches.isEmpty else { return }
        let total = patches.reduce(0) { $0 + $1.count }
        print("\n  ━━━ VERIFICATION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        let hdr = "Patch".padding(toLength: 44, withPad: " ", startingAt: 0)
        print("  \(hdr)  Offset  Count")
        print("  ────────────────────────────────────────────────────────")
        for p in patches.sorted(by: { $0.offset < $1.offset }) {
            let name = p.name.padding(toLength: 44, withPad: " ", startingAt: 0)
            print("  \(name)  0x\(String(format: "%04x", p.offset))  \(p.count)")
        }
        print("  ────────────────────────────────────────────────────────")
        print("  \(component): \(patches.count) patches, \(total) instructions modified")
        print("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
    }
}
