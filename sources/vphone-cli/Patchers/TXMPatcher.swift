import Foundation

class TXMPatcher: Patcher {
    var data: Data
    private let verbose: Bool

    init(data: Data, verbose: Bool = true) {
        self.data = data
        self.verbose = verbose
    }

    func apply() throws -> Int {
        var patchCount = 0
        data.withUnsafeMutableBytes { buffer in
            // Step 1: find marker instruction  mov w19, #0x2446
            var markerIdx: Int? = nil
            for i in stride(from: 0, to: buffer.count - 4, by: 4) {
                let insn = buffer.load(fromByteOffset: i, as: UInt32.self)
                if insn == 0x5284_88D3 {
                    markerIdx = i
                    break
                }
            }
            guard let mIdx = markerIdx else {
                if verbose { print("  [-] TXM: marker mov w19,#0x2446 not found") }
                return
            }

            // Step 2: scan backward from marker to find PACIBSP or PACIASP (function prologue)
            var funcStart: Int? = nil
            let scanBack = max(mIdx - 0x1000, 0)
            for i in stride(from: mIdx & ~3, through: scanBack, by: -4) {
                let insn = buffer.load(fromByteOffset: i, as: UInt32.self)
                if insn == ARM64.pacibsp || insn == ARM64.paciasp {
                    funcStart = i
                    break
                }
            }
            guard let start = funcStart else {
                if verbose {
                    print("  [-] TXM: function start (PACIBSP/PACIASP) not found near marker")
                }
                return
            }

            // Step 3: forward scan for 4-instruction pattern:
            //   mov w2, #0x14   (SHA-1 size, exactly as Python checks)
            //   BL <hash_cmp>  (trustcache binary search comparator)
            //   CBZ w0, <match>
            //   TBNZ/TBZ Rt, #31  (sign bit -> search direction)
            // mov w2, #0x14 = movz w2, #20, lsl 0 = 0x52800282
            let end = min(start + 0x2000, buffer.count - 16)
            for i in stride(from: start, to: end, by: 4) {
                let i0 = buffer.load(fromByteOffset: i, as: UInt32.self)
                let i1 = buffer.load(fromByteOffset: i + 4, as: UInt32.self)
                let i2 = buffer.load(fromByteOffset: i + 8, as: UInt32.self)
                let i3 = buffer.load(fromByteOffset: i + 12, as: UInt32.self)
                // i0: exactly mov w2, #0x14 (SHA-1 digest size)
                let isMov = i0 == 0x5280_0282
                // i1: BL
                let isBL = ARM64.isBL(i1)
                // i2: CBZ/CBNZ w0
                let isCBZ = (i2 & 0xFF00_001F) == 0x3400_0000 || (i2 & 0xFF00_001F) == 0x3500_0000
                // i3: TBNZ/TBZ Rt, #31 (any Rt, bit#=31)
                let isTBNZ = (i3 & 0xFFF8_0000) == 0x37F8_0000 || (i3 & 0xFFF8_0000) == 0x36F8_0000
                if isMov && isBL && isCBZ && isTBNZ {
                    let patchOff = i + 4
                    let oldInsn = i1
                    buffer.storeBytes(
                        of: ARM64.mov_x0_0.littleEndian, toByteOffset: patchOff, as: UInt32.self)
                    if verbose {
                        PatchLog.context(
                            data: Data(buffer), at: patchOff, count: 1,
                            label: "TXM: trustcache bypass",
                            old: [oldInsn], new: [ARM64.mov_x0_0])
                    }
                    patchCount += 1
                    break
                }
            }

            if patchCount == 0, verbose {
                print(
                    "  [-] TXM: 4-insn pattern not found in function at 0x\(String(start, radix: 16))"
                )
            }
        }
        return patchCount
    }
}
