import Foundation

class AVPBooterPatcher: Patcher {
    var data: Data
    private let verbose: Bool

    init(data: Data, verbose: Bool = true) {
        self.data = data
        self.verbose = verbose
    }

    func apply() throws -> Int {
        var patchCount = 0
        data.withUnsafeMutableBytes { buffer in
            var hitIdx: Int? = nil
            for i in stride(from: 0, to: buffer.count - 4, by: 4) {
                let insn = buffer.load(fromByteOffset: i, as: UInt32.self)
                // movk w8, #0x4447, lsl #16 is 0x72a888e8 (LE: e8 88 a8 72)
                if insn == 0x72A8_88E8 || insn == 0x72A8_88E1 {
                    hitIdx = i
                    break
                }
            }

            guard let startIdx = hitIdx else { return }

            var retIdx: Int? = nil
            for i in stride(from: startIdx, to: min(startIdx + 2048, buffer.count - 4), by: 4) {
                let insn = buffer.load(fromByteOffset: i, as: UInt32.self)
                if ARM64.isRet(insn) {
                    retIdx = i
                    break
                }
            }

            guard let endIdx = retIdx else { return }

            for i in stride(from: endIdx - 4, to: max(endIdx - 128, 0), by: -4) {
                let insn = buffer.load(fromByteOffset: i, as: UInt32.self)
                if ARM64.isMovX0(insn) || (insn & 0xFFC0_001F) == 0x1A80_0000 {
                    let oldInsn = insn
                    buffer.storeBytes(
                        of: ARM64.mov_x0_0.littleEndian, toByteOffset: i, as: UInt32.self)
                    if verbose {
                        PatchLog.context(
                            data: Data(buffer), at: i, count: 1, label: "AVPBooter: DGST bypass",
                            old: [oldInsn], new: [ARM64.mov_x0_0])
                    }
                    patchCount += 1
                    break
                }
            }
        }
        return patchCount
    }
}
