import Foundation
import Image4

// MARK: - ARM64 Helpers

enum ARM64 {
    static let nop: UInt32 = 0xD503_201F
    static let ret: UInt32 = 0xD65F_03C0
    static let retaa: UInt32 = 0xD65F_0BFF
    static let retab: UInt32 = 0xD65F_0FFF
    static let paciasp: UInt32 = 0xD503_233F
    static let pacibsp: UInt32 = 0xD503_237F
    static let mov_x0_0: UInt32 = 0xD280_0000
    static let mov_x0_1: UInt32 = 0xD280_0020
    static let mov_w0_0: UInt32 = 0x5280_0000
    static let mov_w0_1: UInt32 = 0x5280_0020
    static let cmp_w0_w0: UInt32 = 0x6B00_001F
    static let cmp_x0_x0: UInt32 = 0xEB00_001F

    static func isRet(_ insn: UInt32) -> Bool {
        return insn == ret || insn == retaa || insn == retab
    }

    /// True for ret/retaa/retab/paciasp/pacibsp — marks function boundaries
    static func isFuncBoundary(_ insn: UInt32) -> Bool {
        return isRet(insn) || insn == paciasp || insn == pacibsp
    }

    static func isMovX0(_ insn: UInt32) -> Bool {
        let baseImm = insn & 0x7F80_0000
        if (insn & 0x1F) == 0 && (baseImm == 0x5280_0000 || baseImm == 0x1280_0000) { return true }
        if (insn & 0xFFE0_FFFF) == 0xAA00_03E0 { return true }
        if (insn & 0xFFE0_FFFF) == 0x2A00_03E0 { return true }
        return false
    }

    static func isBL(_ insn: UInt32) -> Bool { (insn & 0xFC00_0000) == 0x9400_0000 }

    /// Decode BL target as file offset (PC-relative, no VA translation needed for flat binaries)
    static func decodeBLTarget(insn: UInt32, foff: Int) -> Int {
        var imm26 = Int64(insn & 0x3FF_FFFF)
        if (imm26 & (1 << 25)) != 0 { imm26 -= (1 << 26) }
        return foff + Int(imm26 * 4)
    }

    static func encodeB(from src: Int, to dst: Int) -> UInt32 {
        let offset = (dst - src) / 4
        return 0x1400_0000 | (UInt32(truncatingIfNeeded: offset) & 0x3FF_FFFF)
    }

    static func isADRP(_ insn: UInt32) -> Bool { (insn & 0x9F00_0000) == 0x9000_0000 }

    static func decodeADRP(insn: UInt32, foff: Int, baseVA: UInt64) -> UInt64 {
        let pc = baseVA + UInt64(foff)
        let immlo = (insn >> 29) & 0x3
        let immhi = (insn >> 5) & 0x7FFFF
        var imm = Int64((immhi << 2) | immlo)
        if (imm & (1 << 20)) != 0 { imm -= (1 << 21) }
        return UInt64(bitPattern: (Int64(bitPattern: pc) & ~0xFFF) + (imm << 12))
    }

    static func encodeADRP(rd: UInt32, from foff: Int, to targetVA: UInt64, baseVA: UInt64)
        -> UInt32
    {
        let pc = Int64(bitPattern: baseVA) + Int64(foff)
        let imm = (Int64(bitPattern: targetVA & ~0xFFF) - (pc & ~0xFFF)) >> 12
        let immlo = UInt32(truncatingIfNeeded: imm & 0x3)
        let immhi = UInt32(truncatingIfNeeded: (imm >> 2) & 0x7FFFF)
        return 0x9000_0000 | (immlo << 29) | (immhi << 5) | (rd & 0x1F)
    }

    static func isADDImm(_ insn: UInt32) -> Bool { (insn & 0xFF00_0000) == 0x9100_0000 }

    static func decodeADDImm(_ insn: UInt32) -> Int {
        let imm12 = (insn >> 10) & 0xFFF
        let shift = (insn >> 22) & 0x3
        return Int(imm12) << (shift == 1 ? 12 : 0)
    }

    static func encodeADDImm(rd: UInt32, rn: UInt32, imm: Int) -> UInt32 {
        return 0x9100_0000 | ((UInt32(imm & 0xFFF)) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)
    }

    /// Decode an arm64e chained fixup pointer to a raw file offset.
    /// auth rebase (bit63=1): foff = val & 0xFFFFFFFF
    /// non-auth rebase (bit63=0): reconstruct VA from high8+low43, then subtract baseVA
    static func decodeChainedPtr(_ val: UInt64, baseVA: UInt64) -> Int {
        if val == 0 { return -1 }
        if (val & (1 << 63)) != 0 {
            return Int(val & 0xFFFF_FFFF)
        } else {
            let low43 = val & 0x7FF_FFFF_FFFF
            let high8 = (val >> 43) & 0xFF
            let fullVA = (high8 << 56) | low43
            if fullVA > baseVA { return Int(fullVA - baseVA) }
            return -1
        }
    }
}

// MARK: - Mach-O Parsing Helpers

struct MachO {
    struct Segment {
        let name: String
        let vmaddr: UInt64
        let vmsize: UInt64
        let fileoff: UInt64
        let filesize: UInt64
        let initprot: UInt32
    }
    struct Section {
        let segname: String
        let sectname: String
        let vmaddr: UInt64
        let size: UInt64
        let offset: UInt32
    }

    let data: Data
    var sections: [String: Section] = [:]
    var segments: [Segment] = []
    var baseVA: UInt64 = 0

    init(data: Data) throws {
        self.data = data
        try parse()
    }

    private mutating func parse() throws {
        guard data.count >= 32 else { return }
        data.withUnsafeBytes { buffer in
            let magic = buffer.load(fromByteOffset: 0, as: UInt32.self)
            guard magic == 0xFEED_FACF else { return }
            let ncmds = buffer.load(fromByteOffset: 16, as: UInt32.self)
            var offset = 32
            for _ in 0..<ncmds {
                guard offset + 8 <= buffer.count else { break }
                let cmd = buffer.load(fromByteOffset: offset, as: UInt32.self)
                let cmdsize = buffer.load(fromByteOffset: offset + 4, as: UInt32.self)
                guard offset + Int(cmdsize) <= buffer.count else { break }
                if cmd == 0x19 {  // LC_SEGMENT_64
                    let segnameBytes = buffer.baseAddress!.advanced(by: offset + 8)
                        .assumingMemoryBound(to: UInt8.self)
                    let segnameData = Data(bytes: segnameBytes, count: 16)
                    let segname =
                        String(data: segnameData.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
                    let vmaddr = buffer.load(fromByteOffset: offset + 24, as: UInt64.self)
                    let vmsize = buffer.load(fromByteOffset: offset + 32, as: UInt64.self)
                    let fileoff = buffer.load(fromByteOffset: offset + 40, as: UInt64.self)
                    let filesize = buffer.load(fromByteOffset: offset + 48, as: UInt64.self)
                    let initprot = buffer.load(fromByteOffset: offset + 60, as: UInt32.self)
                    segments.append(
                        Segment(
                            name: segname, vmaddr: vmaddr, vmsize: vmsize,
                            fileoff: fileoff, filesize: filesize, initprot: initprot))
                    if segname == "__TEXT" { baseVA = vmaddr }
                    let nsects = buffer.load(fromByteOffset: offset + 64, as: UInt32.self)
                    var sectOffset = offset + 72
                    for _ in 0..<nsects {
                        guard sectOffset + 80 <= buffer.count else { break }
                        let snameBytes = buffer.baseAddress!.advanced(by: sectOffset)
                            .assumingMemoryBound(to: UInt8.self)
                        let snameData = Data(bytes: snameBytes, count: 16)
                        let sname =
                            String(data: snameData.prefix(while: { $0 != 0 }), encoding: .utf8)
                            ?? ""
                        let saddr = buffer.load(fromByteOffset: sectOffset + 32, as: UInt64.self)
                        let ssize = buffer.load(fromByteOffset: sectOffset + 40, as: UInt64.self)
                        let soff = buffer.load(fromByteOffset: sectOffset + 48, as: UInt32.self)
                        sections["\(segname),\(sname)"] = Section(
                            segname: segname, sectname: sname, vmaddr: saddr, size: ssize,
                            offset: soff)
                        sectOffset += 80
                    }
                }
                offset += Int(cmdsize)
            }
        }
    }

    func vaToFoff(_ va: UInt64) -> Int {
        for seg in segments {
            if va >= seg.vmaddr && va < seg.vmaddr + seg.vmsize {
                return Int(seg.fileoff + (va - seg.vmaddr))
            }
        }
        return -1
    }

    func foffToVa(_ foff: Int) -> UInt64 {
        for seg in segments {
            if UInt64(foff) >= seg.fileoff && UInt64(foff) < seg.fileoff + seg.filesize {
                return seg.vmaddr + (UInt64(foff) - seg.fileoff)
            }
        }
        return 0
    }

    /// File offset ranges of executable segments (code)
    var codeSegments: [(start: Int, end: Int)] {
        let names: Set<String> = ["__TEXT_EXEC", "__PRELINK_TEXT", "__TEXT_BOOT_EXEC", "__TEXT"]
        return segments.compactMap { seg in
            guard names.contains(seg.name) && seg.filesize > 0 else { return nil }
            return (Int(seg.fileoff), Int(seg.fileoff + seg.filesize))
        }.sorted { $0.start < $1.start }
    }

    /// File offset ranges of data segments (__DATA, __DATA_CONST)
    var dataSegments: [(start: Int, end: Int)] {
        return segments.compactMap { seg in
            guard (seg.name == "__DATA" || seg.name == "__DATA_CONST") && seg.filesize > 0 else {
                return nil
            }
            return (Int(seg.fileoff), Int(seg.fileoff + seg.filesize))
        }
    }
}

protocol Patcher {
    var data: Data { get set }
    func apply() throws -> Int
}

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
                    buffer.storeBytes(
                        of: ARM64.mov_x0_0.littleEndian, toByteOffset: i, as: UInt32.self)
                    if verbose { print("  [+] AVPBooter: Patched at 0x\(String(i, radix: 16))") }
                    patchCount += 1
                    break
                }
            }
        }
        return patchCount
    }
}

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
                // For bit#=31: b5=0, b4:0=11111, so bits[23:19]=11111 in the encoding.
                // tbnz any: bits[31:19] = 0b0_0110111_11111 = 0x37F8_0000
                // tbz  any: bits[31:19] = 0b0_0110110_11111 = 0x36F8_0000
                let isTBNZ = (i3 & 0xFFF8_0000) == 0x37F8_0000 || (i3 & 0xFFF8_0000) == 0x36F8_0000
                if isMov && isBL && isCBZ && isTBNZ {
                    let patchOff = i + 4
                    buffer.storeBytes(
                        of: ARM64.mov_x0_0.littleEndian, toByteOffset: patchOff, as: UInt32.self)
                    if verbose {
                        print("  [+] TXM: trustcache bypass at 0x\(String(patchOff, radix: 16))")
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

class IBootPatcher: Patcher {
    var data: Data
    private let mode: String
    private let verbose: Bool

    // Python canonical boot-args format string
    private static let bootArgs = "serial=3 -v debug=0x2014e %s"

    init(data: Data, mode: String = "ibss", verbose: Bool = true) {
        self.data = data
        self.mode = mode.lowercased()
        self.verbose = verbose
    }

    func apply() throws -> Int {
        var patchCount = 0
        patchCount += patchSerialLabels()
        patchCount += patchImage4Callback()
        if mode == "ibec" || mode == "llb" { patchCount += patchBootArgs() }
        if mode == "llb" {
            patchCount += patchRootfsBypass()
            patchCount += patchPanicBypass()
        }
        return patchCount
    }

    // MARK: - Serial Labels

    private func patchSerialLabels() -> Int {
        let label = "Loaded \(mode.uppercased())".data(using: .utf8) ?? Data()
        var count = 0
        var searchIdx = 0
        var runs: [Int] = []
        while searchIdx < data.count - 20 {
            if data[searchIdx] == UInt8(ascii: "=") {
                var runCount = 0
                while searchIdx + runCount < data.count
                    && data[searchIdx + runCount] == UInt8(ascii: "=")
                { runCount += 1 }
                if runCount >= 20 {
                    runs.append(searchIdx)
                    searchIdx += runCount
                    continue
                }
            }
            searchIdx += 1
        }
        for runStart in runs.prefix(2) {
            let writeOff = runStart + 1
            if writeOff + label.count <= data.count {
                data.replaceSubrange(writeOff..<(writeOff + label.count), with: label)
                if verbose {
                    print("  [+] iBoot (\(mode)): serial label at 0x\(String(writeOff, radix: 16))")
                }
                count += 1
            }
        }
        return count
    }

    // MARK: - Image4 Callback Bypass
    // Pattern: B.NE + MOV X0, X22 (preceded by CMP within 8 instructions)
    // Tiebreaker: prefer candidate that has MOVN W22 within preceding 64 instructions
    //   (sets W22 = -1 as an error sentinel), matching Python's preference logic.
    // Patch: B.NE → NOP, MOV X0, X22 → MOV X0, #0

    private func patchImage4Callback() -> Int {
        // movn w22, #X (any imm, any shift): MOVN 32-bit = sf=0,opc=00,100101
        //   → bits[31:24]=0x12, bits[4:0]=0x16
        let movnW22Mask: UInt32 = 0xFF00_001F
        let movnW22Val: UInt32 = 0x1200_0016

        var candidates: [(off: Int, hasMovN: Bool)] = []
        for i in stride(from: 0, to: data.count - 8, by: 4) {
            let i0 = data.withUnsafeBytes { $0.load(fromByteOffset: i, as: UInt32.self) }
            let i1 = data.withUnsafeBytes { $0.load(fromByteOffset: i + 4, as: UInt32.self) }
            // B.NE (any offset), then MOV X0, X22 (ORR X0, XZR, X22)
            guard (i0 & 0xFF00_001F) == 0x5400_0001 && i1 == 0xAA16_03E0 else { continue }
            // Confirm CMP within preceding 8 instructions.
            // CMP is SUBS with Rd=XZR (bits[4:0]=31). Cover all variants:
            //   0xEB = SUBS 64-bit register, 0xF1 = SUBS 64-bit immediate
            //   0x6B = SUBS 32-bit register, 0x71 = SUBS 32-bit immediate
            var foundCmp = false
            for j in stride(from: max(i - 32, 0), to: i, by: 4) {
                let insn = data.withUnsafeBytes { $0.load(fromByteOffset: j, as: UInt32.self) }
                let top = insn >> 24
                if (insn & 0x1F) == 0x1F
                    && (top == 0xEB || top == 0x6B || top == 0xF1 || top == 0x71)
                {
                    foundCmp = true
                    break
                }
            }
            guard foundCmp else { continue }
            // Check for MOVN W22 within 64 preceding instructions
            var hasMovN = false
            for j in stride(from: max(i - 256, 0), to: i, by: 4) {
                let insn = data.withUnsafeBytes { $0.load(fromByteOffset: j, as: UInt32.self) }
                if (insn & movnW22Mask) == movnW22Val {
                    hasMovN = true
                    break
                }
            }
            candidates.append((i, hasMovN))
        }
        guard !candidates.isEmpty else {
            if verbose { print("  [-] iBoot (\(mode)): image4 callback pattern not found") }
            return 0
        }
        // Prefer candidate with MOVN W22 nearby; fall back to last candidate
        let chosen = candidates.first(where: { $0.hasMovN }) ?? candidates.last!
        let i = chosen.off
        let nopData = withUnsafeBytes(of: ARM64.nop.littleEndian) { Data($0) }
        let movData = withUnsafeBytes(of: ARM64.mov_x0_0.littleEndian) { Data($0) }
        data.replaceSubrange(i..<(i + 4), with: nopData)
        data.replaceSubrange((i + 4)..<(i + 8), with: movData)
        if verbose {
            print("  [+] iBoot (\(mode)): image4 callback at 0x\(String(i, radix: 16))")
        }
        return 2
    }

    // MARK: - Boot Args
    // Redirect ADRP+ADD x2 that references the format "%s" string to our new string slot.

    private func patchBootArgs() -> Int {
        let newArgs = Self.bootArgs.data(using: .utf8)!
        guard let fmtOff = findBootArgsFmt() else {
            if verbose { print("  [-] iBoot (\(mode)): boot-args format string not found") }
            return 0
        }
        guard let (adrpOff, addOff) = findBootArgsADRP(fmtOff: fmtOff) else {
            if verbose { print("  [-] iBoot (\(mode)): boot-args ADRP+ADD x2 not found") }
            return 0
        }
        guard let slotIdx = findStringSlot(length: newArgs.count + 1) else {
            if verbose { print("  [-] iBoot (\(mode)): no null slot for boot-args") }
            return 0
        }
        data.replaceSubrange(slotIdx..<(slotIdx + newArgs.count), with: newArgs)
        let newADRP = ARM64.encodeADRP(rd: 2, from: adrpOff, to: UInt64(slotIdx), baseVA: 0)
        let newADD = ARM64.encodeADDImm(rd: 2, rn: 2, imm: Int(UInt64(slotIdx) & 0xFFF))
        let adrpData = withUnsafeBytes(of: newADRP.littleEndian) { Data($0) }
        let addData = withUnsafeBytes(of: newADD.littleEndian) { Data($0) }
        data.replaceSubrange(adrpOff..<(adrpOff + 4), with: adrpData)
        data.replaceSubrange(addOff..<(addOff + 4), with: addData)
        if verbose {
            print("  [+] iBoot (\(mode)): boot-args → slot 0x\(String(slotIdx, radix: 16))")
        }
        return 3
    }

    /// Find standalone `%s` (preceded and followed by NUL) within 0x40 bytes of `rd=md0`.
    private func findBootArgsFmt() -> Int? {
        let anchor: Int
        if let r = data.range(of: "rd=md0".data(using: .utf8)!) {
            anchor = r.lowerBound
        } else if let r = data.range(of: "BootArgs".data(using: .utf8)!) {
            anchor = r.lowerBound
        } else {
            return nil
        }
        let fmtBytes = "%s".data(using: .utf8)!
        var off = anchor
        let limit = min(anchor + 0x40, data.count)
        while off < limit {
            guard let r = data.range(of: fmtBytes, in: off..<limit) else { break }
            let at = r.lowerBound
            if at > 0 && data[at - 1] == 0 && at + 2 < data.count && data[at + 2] == 0 {
                return at
            }
            off = at + 1
        }
        return nil
    }

    /// Find ADRP x2; ADD x2, x2, #imm pointing at fmtOff (in raw file = VA for iBoot).
    private func findBootArgsADRP(fmtOff: Int) -> (adrpOff: Int, addOff: Int)? {
        let fmtVa = UInt64(fmtOff)
        for i in stride(from: 0, to: data.count - 8, by: 4) {
            let i0 = data.withUnsafeBytes { $0.load(fromByteOffset: i, as: UInt32.self) }
            let i1 = data.withUnsafeBytes { $0.load(fromByteOffset: i + 4, as: UInt32.self) }
            guard ARM64.isADRP(i0) && ARM64.isADDImm(i1) else { continue }
            // Both must use x2
            guard (i0 & 0x1F) == 2 && (i1 & 0x1F) == 2 && ((i1 >> 5) & 0x1F) == 2 else { continue }
            let page = ARM64.decodeADRP(insn: i0, foff: i, baseVA: 0)
            let imm12 = UInt64((i1 >> 10) & 0xFFF)
            if page + imm12 == fmtVa { return (i, i + 4) }
        }
        return nil
    }

    private func findStringSlot(length: Int) -> Int? {
        var searchIdx = 0x14000
        while searchIdx < data.count - length {
            if data[searchIdx] == 0 {
                let runStart = searchIdx
                while searchIdx < data.count && data[searchIdx] == 0 { searchIdx += 1 }
                if searchIdx - runStart >= length + 16 { return (runStart + 8 + 15) & ~15 }
            } else {
                searchIdx += 1
            }
        }
        return nil
    }

    // MARK: - Rootfs Bypass (LLB only, 5 sub-patches)

    private func patchRootfsBypass() -> Int {
        var count = 0
        count += patchCBZBeforeError(errorCode: 0x3B7, desc: "rootfs skip sig check (0x3B7)")
        count += patchBHSAfterCMP0x400()
        count += patchCBZBeforeError(errorCode: 0x3C2, desc: "rootfs skip sig verify (0x3C2)")
        count += patchNullCheck0x78()
        count += patchCBZBeforeError(errorCode: 0x110, desc: "rootfs skip size verify (0x110)")
        return count
    }

    /// Find unique `MOVZ W8, #errorCode`, convert preceding CBZ/CBNZ to unconditional B.
    private func patchCBZBeforeError(errorCode: UInt32, desc: String) -> Int {
        // MOVZ W8, #N = 0x52800008 | (N << 5)
        let movPattern = UInt32(0x5280_0008) | (errorCode << 5)
        var found: [Int] = []
        for i in stride(from: 0, to: data.count - 4, by: 4) {
            let insn = data.withUnsafeBytes { $0.load(fromByteOffset: i, as: UInt32.self) }
            if insn == movPattern { found.append(i) }
        }
        guard found.count == 1 else {
            if verbose { print("  [-] iBoot: \(desc): expected 1 match, found \(found.count)") }
            return 0
        }
        let errOff = found[0]
        let cbzOff = errOff - 4
        guard cbzOff >= 0 else { return 0 }
        let insn = data.withUnsafeBytes { $0.load(fromByteOffset: cbzOff, as: UInt32.self) }
        // CBZ or CBNZ, 32-bit or 64-bit: top 7 bits = 0x34/0x35 (ignoring sf bit)
        let isCBZ = (insn & 0x7F00_0000) == 0x3400_0000
        let isCBNZ = (insn & 0x7F00_0000) == 0x3500_0000
        guard isCBZ || isCBNZ else {
            if verbose {
                print("  [-] iBoot: \(desc): expected CBZ/CBNZ at 0x\(String(cbzOff, radix: 16))")
            }
            return 0
        }
        // Decode 19-bit signed immediate (bits[23:5]), scale ×4
        let raw19 = Int32(bitPattern: (insn >> 5) & 0x7FFFF)
        let imm19 = (raw19 << 13) >> 13  // sign-extend 19→32 bits
        let target = cbzOff + Int(imm19) * 4
        let b = ARM64.encodeB(from: cbzOff, to: target)
        let bData = withUnsafeBytes(of: b.littleEndian) { Data($0) }
        data.replaceSubrange(cbzOff..<(cbzOff + 4), with: bData)
        if verbose { print("  [+] iBoot: \(desc) at 0x\(String(cbzOff, radix: 16))") }
        return 1
    }

    /// Find unique `CMP X8, #0x400`, NOP the following B.HS.
    private func patchBHSAfterCMP0x400() -> Int {
        // CMP X8, #0x400 = SUBS XZR, X8, #0x400
        // encoding: 0xF1000000 | (0x400 << 10) | (8 << 5) | 31 = 0xF110011F
        let cmpPattern = UInt32(0xF110_011F)
        var found: [Int] = []
        for i in stride(from: 0, to: data.count - 8, by: 4) {
            let insn = data.withUnsafeBytes { $0.load(fromByteOffset: i, as: UInt32.self) }
            if insn == cmpPattern { found.append(i) }
        }
        guard found.count == 1 else {
            if verbose {
                print("  [-] iBoot: rootfs b.hs: expected 1 CMP X8,#0x400, found \(found.count)")
            }
            return 0
        }
        let bhsOff = found[0] + 4
        let bhs = data.withUnsafeBytes { $0.load(fromByteOffset: bhsOff, as: UInt32.self) }
        // B.HS = B.CS: condition code 2, opcode 0x5400_0002
        guard (bhs & 0xFF00_001F) == 0x5400_0002 else {
            if verbose { print("  [-] iBoot: expected B.HS at 0x\(String(bhsOff, radix: 16))") }
            return 0
        }
        let nopData = withUnsafeBytes(of: ARM64.nop.littleEndian) { Data($0) }
        data.replaceSubrange(bhsOff..<(bhsOff + 4), with: nopData)
        if verbose { print("  [+] iBoot: rootfs NOP B.HS at 0x\(String(bhsOff, radix: 16))") }
        return 1
    }

    /// Walk back from unique `MOVZ W8, #0x110`, find LDR Xt,[Xn,#0x78]+CBZ Xt, NOP the CBZ.
    private func patchNullCheck0x78() -> Int {
        let movPattern = UInt32(0x5280_0008) | UInt32(0x110 << 5)  // MOVZ W8, #0x110
        var found: [Int] = []
        for i in stride(from: 0, to: data.count - 4, by: 4) {
            let insn = data.withUnsafeBytes { $0.load(fromByteOffset: i, as: UInt32.self) }
            if insn == movPattern { found.append(i) }
        }
        guard found.count == 1 else {
            if verbose {
                print(
                    "  [-] iBoot: null check #0x78: expected 1 MOVZ W8,#0x110, found \(found.count)"
                )
            }
            return 0
        }
        let errOff = found[0]
        for scan in stride(from: errOff - 8, through: max(errOff - 0x300, 0), by: -4) {
            let i1 = data.withUnsafeBytes { $0.load(fromByteOffset: scan, as: UInt32.self) }
            let i2 = data.withUnsafeBytes { $0.load(fromByteOffset: scan + 4, as: UInt32.self) }
            // LDR Xt, [Xn, #0x78]: 64-bit unsigned offset, imm12=0x78/8=15
            //   upper 10 bits of 32-bit encoding = 0x3E5 for 64-bit LDR, imm12 in bits[21:10]
            let isLDR = ((i1 >> 22) & 0x3FF) == 0x3E5 && ((i1 >> 10) & 0xFFF) == 15
            guard isLDR else { continue }
            let rt = i1 & 0x1F
            // CBZ Xt (64-bit): 0xB4000000 | (imm19 << 5) | Rt
            let isCBZ = (i2 & 0xFF00_0000) == 0xB400_0000 && (i2 & 0x1F) == rt
            if isCBZ {
                let nopData = withUnsafeBytes(of: ARM64.nop.littleEndian) { Data($0) }
                data.replaceSubrange((scan + 4)..<(scan + 8), with: nopData)
                if verbose {
                    print(
                        "  [+] iBoot: rootfs NOP CBZ null check at 0x\(String(scan + 4, radix: 16))"
                    )
                }
                return 1
            }
        }
        if verbose { print("  [-] iBoot: null check #0x78: LDR+CBZ pattern not found") }
        return 0
    }

    // MARK: - Panic Bypass (LLB only)
    // Pattern: MOVZ W8,#0x328; MOVK W8,#0x40,LSL#16; ...; BL; CBNZ W0
    // Patch: NOP the CBNZ W0

    private func patchPanicBypass() -> Int {
        // MOVZ W8, #0x328: 0x52800008 | (0x328 << 5)
        let mov328 = UInt32(0x5280_0008) | UInt32(0x328 << 5)
        // MOVK W8, #0x40, LSL#16: 0x72800000 | (1 << 21) | (0x40 << 5) | 8
        let movk40 = UInt32(0x72A0_0808)
        for i in stride(from: 0, to: data.count - 24, by: 4) {
            let i0 = data.withUnsafeBytes { $0.load(fromByteOffset: i, as: UInt32.self) }
            guard i0 == mov328 else { continue }
            let i1 = data.withUnsafeBytes { $0.load(fromByteOffset: i + 4, as: UInt32.self) }
            guard i1 == movk40 else { continue }
            // Walk forward up to 8 instructions to find BL; CBNZ W0
            for step in stride(from: i + 8, to: min(i + 44, data.count - 4), by: 4) {
                let si = data.withUnsafeBytes { $0.load(fromByteOffset: step, as: UInt32.self) }
                guard ARM64.isBL(si) else { continue }
                let ni = data.withUnsafeBytes { $0.load(fromByteOffset: step + 4, as: UInt32.self) }
                // CBNZ W0 (32-bit): 0x3500_0000, Rt=0 → (ni & 0xFF00_001F) == 0x3500_0000
                if (ni & 0xFF00_001F) == 0x3500_0000 {
                    let nopData = withUnsafeBytes(of: ARM64.nop.littleEndian) { Data($0) }
                    data.replaceSubrange((step + 4)..<(step + 8), with: nopData)
                    if verbose {
                        print(
                            "  [+] iBoot: panic bypass NOP CBNZ at 0x\(String(step + 4, radix: 16))"
                        )
                    }
                    return 1
                }
                break
            }
        }
        if verbose { print("  [-] iBoot: panic bypass pattern not found") }
        return 0
    }
}

class KernelPatcher: Patcher {
    var data: Data
    private let verbose: Bool
    private var macho: MachO
    private var blCallers: [Int: [Int]] = [:]  // target_foff -> [caller_foff, ...]
    private var panicOff: Int = -1

    init(data: Data, verbose: Bool = true) throws {
        self.data = data
        self.verbose = verbose
        self.macho = try MachO(data: data)
        buildBLIndex()
        findPanic()
    }

    func apply() throws -> Int {
        var n = 0
        n += patchAPFSRootSnapshot()
        n += patchAPFSSealBroken()
        n += patchBSDInitRootVP()
        n += patchLaunchConstraints()
        n += patchDebugger()
        n += patchPostValidationNOP()
        n += patchPostValidationCMP()
        n += patchCheckDyldPolicy()
        n += patchAPFSGraft()
        n += patchAPFSVFSMountCMP()
        n += patchAPFSMountUpgradeChecks()
        n += patchHandleFsiocGraft()
        n += patchSandboxHooks()
        return n
    }

    // MARK: - Index builders

    private func buildBLIndex() {
        for seg in macho.codeSegments {
            for off in stride(from: seg.start, to: seg.end - 4, by: 4) {
                guard off + 4 <= data.count else { break }
                let insn = data.withUnsafeBytes { $0.load(fromByteOffset: off, as: UInt32.self) }
                guard ARM64.isBL(insn) else { continue }
                let target = ARM64.decodeBLTarget(insn: insn, foff: off)
                blCallers[target, default: []].append(off)
            }
        }
        if verbose { print("  [*] KernelPatcher: BL index built (\(blCallers.count) targets)") }
    }

    private func findPanic() {
        // _panic is the most-called function whose callers reference "@%s:%d" abort strings
        let top = blCallers.sorted { $0.value.count > $1.value.count }.prefix(20)
        for (targetOff, callers) in top {
            guard callers.count >= 500 else { break }
            var confirmed = 0
            for callerOff in callers.prefix(30) {
                for back in stride(from: callerOff - 4, through: max(callerOff - 32, 0), by: -4) {
                    let insn = data.withUnsafeBytes {
                        $0.load(fromByteOffset: back, as: UInt32.self)
                    }
                    guard ARM64.isADDImm(insn) && (insn & 0x1F) == 0 else { continue }
                    guard back >= 4 else { break }
                    let prev = data.withUnsafeBytes {
                        $0.load(fromByteOffset: back - 4, as: UInt32.self)
                    }
                    guard ARM64.isADRP(prev) && (prev & 0x1F) == 0 else { break }
                    let page = ARM64.decodeADRP(insn: prev, foff: back - 4, baseVA: macho.baseVA)
                    let imm12 = Int((insn >> 10) & 0xFFF)
                    let strFoff = macho.vaToFoff(page + UInt64(imm12))
                    if strFoff >= 0 && strFoff + 60 < data.count {
                        let range = strFoff..<(strFoff + 60)
                        let hasAbort =
                            data.range(of: Data("@%s:%d".utf8), in: range) != nil
                            || data.range(of: Data("%s:%d".utf8), in: range) != nil
                        if hasAbort {
                            confirmed += 1
                            break
                        }
                    }
                    break
                }
            }
            if confirmed >= 3 {
                panicOff = targetOff
                if verbose {
                    print(
                        "  [*] KernelPatcher: _panic at foff 0x\(String(panicOff, radix: 16)) (\(callers.count) callers)"
                    )
                }
                return
            }
        }
        // Fallback: just use the top caller
        panicOff = top.first?.key ?? -1
        if verbose && panicOff >= 0 {
            print("  [*] KernelPatcher: _panic (fallback) at foff 0x\(String(panicOff, radix: 16))")
        }
    }

    // MARK: - Helpers

    /// Find C string start for string `s` in binary (walks back to preceding NUL).
    private func findString(_ s: String) -> Int {
        guard let d = s.data(using: .utf8),
            let r = data.range(of: d)
        else { return -1 }
        var off = r.lowerBound
        while off > 0 && data[off - 1] != 0 { off -= 1 }
        return off
    }

    /// Find exactly `\0s\0` — returns offset of first byte of `s`.
    private func findExactString(_ s: String) -> Int {
        guard let d = s.data(using: .utf8) else { return -1 }
        let pattern = Data([0]) + d + Data([0])
        guard let r = data.range(of: pattern) else { return -1 }
        return r.lowerBound + 1
    }

    /// All (adrpOff, addOff) pairs referencing string at strFoff (via ADRP+ADD).
    private func findStringRefs(strFoff: Int, rangeStart: Int? = nil, rangeEnd: Int? = nil) -> [(
        Int, Int
    )] {
        let strVa = macho.foffToVa(strFoff)
        let targetPage = strVa & ~0xFFF
        let pageOff = UInt64(strVa & 0xFFF)
        let rStart = rangeStart ?? 0
        let rEnd = rangeEnd ?? data.count

        var results: [(Int, Int)] = []
        for off in stride(from: rStart, to: min(rEnd, data.count - 8), by: 4) {
            let i0 = data.withUnsafeBytes { $0.load(fromByteOffset: off, as: UInt32.self) }
            guard ARM64.isADRP(i0) else { continue }
            let page = ARM64.decodeADRP(insn: i0, foff: off, baseVA: macho.baseVA)
            guard page == targetPage else { continue }
            let rd = i0 & 0x1F
            let i1 = data.withUnsafeBytes { $0.load(fromByteOffset: off + 4, as: UInt32.self) }
            guard ARM64.isADDImm(i1) else { continue }
            guard ((i1 >> 5) & 0x1F) == rd && UInt64((i1 >> 10) & 0xFFF) == pageOff else {
                continue
            }
            results.append((off, off + 4))
        }
        return results
    }

    /// Walk backward from `off` to find function prologue (PACIBSP, PACIASP, or STP X29,X30,[SP,...]).
    private func findFunctionStart(_ off: Int, maxBack: Int = 0x4000) -> Int {
        let limit = max(off - maxBack, 0)
        var o = (off - 4) & ~3
        while o >= limit {
            let insn = data.withUnsafeBytes { $0.load(fromByteOffset: o, as: UInt32.self) }
            if insn == ARM64.pacibsp || insn == ARM64.paciasp { return o }
            // STP X29, X30, [SP, #imm]: (insn & 0xFFC07FFF) == 0xA9007BFD
            if (insn & 0xFFC0_7FFF) == 0xA900_7BFD {
                // Check further back for PACIBSP/PACIASP (ARM64e prologue)
                for k in stride(from: o - 4, through: max(o - 0x24, 0), by: -4) {
                    let ki = data.withUnsafeBytes { $0.load(fromByteOffset: k, as: UInt32.self) }
                    if ki == ARM64.pacibsp || ki == ARM64.paciasp { return k }
                }
                return o
            }
            o -= 4
        }
        return -1
    }

    /// Decode any conditional branch at `off` to get target file offset. Returns nil if not a branch.
    private func decodeCondBranchTarget(_ insn: UInt32, at off: Int) -> Int? {
        // B.cond: bits[31:24]=0x54, bit[4]=0
        if (insn & 0xFF00_0010) == 0x5400_0000 {
            let imm19 = (Int32(bitPattern: (insn >> 5) & 0x7FFFF) << 13) >> 13
            return off + Int(imm19) * 4
        }
        // CBZ / CBNZ (32 or 64-bit): bits[30:25]=0b10_1000 or 0b10_1001
        if (insn & 0x7E00_0000) == 0x3400_0000 {
            let imm19 = (Int32(bitPattern: (insn >> 5) & 0x7FFFF) << 13) >> 13
            return off + Int(imm19) * 4
        }
        // TBZ / TBNZ: bits[30:25]=0b11_0110 or 0b11_0111
        if (insn & 0x7E00_0000) == 0x3600_0000 {
            let imm14 = (Int32(bitPattern: (insn >> 5) & 0x3FFF) << 18) >> 18
            return off + Int(imm14) * 4
        }
        return nil
    }

    private func emit(_ label: String, at off: Int, _ bytes: [UInt32]) -> Int {
        var count = 0
        for (i, v) in bytes.enumerated() {
            let o = off + i * 4
            let d = withUnsafeBytes(of: v.littleEndian) { Data($0) }
            data.replaceSubrange(o..<(o + 4), with: d)
            count += 1
        }
        if verbose { print("  [+] Kernel: \(label) at 0x\(String(off, radix: 16))") }
        return count
    }

    private func patchU32(at off: Int, _ val: UInt32) {
        let d = withUnsafeBytes(of: val.littleEndian) { Data($0) }
        data.replaceSubrange(off..<(off + 4), with: d)
    }

    // MARK: - Patch 1: APFS root snapshot check

    private func patchAPFSRootSnapshot() -> Int {
        let strOff = findString("Rooting from snapshot with xid")
        if strOff < 0 {
            if verbose { print("  [-] Kernel [1]: 'Rooting from snapshot with xid' not found") }
            return 0
        }
        let refs = findStringRefs(strFoff: strOff)
        for (_, addOff) in refs {
            for scan in stride(from: addOff, to: min(addOff + 0x200, data.count - 4), by: 4) {
                let insn = data.withUnsafeBytes { $0.load(fromByteOffset: scan, as: UInt32.self) }
                // TBNZ or TBZ (bits[30:25] == 0x1B or 0x1A, i.e. 0x37 or 0x36 at bits[31:24])
                let op = (insn >> 24) & 0xFE
                guard op == 0x36 || op == 0x37 else { continue }
                // bit number in bits[23:19] (b40), plus bit31 (b5). For bit#5: b5=0, b40=5
                let b5 = (insn >> 31) & 1
                let b40 = (insn >> 19) & 0x1F
                let bitNum = Int((b5 << 5) | b40)
                guard bitNum == 5 else { continue }
                return emit(
                    "Patch[1] APFS root snapshot (NOP tbz/tbnz w8,#5)", at: scan, [ARM64.nop])
            }
        }
        if verbose { print("  [-] Kernel [1]: tbz/tbnz bit#5 not found near xref") }
        return 0
    }

    // MARK: - Patch 2: APFS seal broken

    private func patchAPFSSealBroken() -> Int {
        let strOff = findString("root volume seal is broken")
        if strOff < 0 {
            if verbose { print("  [-] Kernel [2]: 'root volume seal is broken' not found") }
            return 0
        }
        for (adrpOff, addOff) in findStringRefs(strFoff: strOff) {
            // Find BL _panic after the ADRP+ADD
            var blPanicOff = -1
            for scan in stride(from: addOff, to: min(addOff + 0x40, data.count - 4), by: 4) {
                let insn = data.withUnsafeBytes { $0.load(fromByteOffset: scan, as: UInt32.self) }
                if ARM64.isBL(insn) && ARM64.decodeBLTarget(insn: insn, foff: scan) == panicOff {
                    blPanicOff = scan
                    break
                }
            }
            if blPanicOff < 0 { continue }
            // Scan backwards for conditional branch whose target is in range [adrpOff-0x40, blPanicOff+4]
            let errLo = adrpOff - 0x40
            let errHi = blPanicOff + 4
            for back in stride(from: adrpOff - 4, through: max(adrpOff - 0x200, 0), by: -4) {
                let insn = data.withUnsafeBytes { $0.load(fromByteOffset: back, as: UInt32.self) }
                if let target = decodeCondBranchTarget(insn, at: back),
                    errLo <= target && target <= errHi
                {
                    return emit(
                        "Patch[2] APFS seal broken (NOP cond branch)", at: back, [ARM64.nop])
                }
            }
        }
        if verbose { print("  [-] Kernel [2]: APFS seal broken cond branch not found") }
        return 0
    }

    // MARK: - Patch 3: BSD init rootvp auth

    private func patchBSDInitRootVP() -> Int {
        let strOff = findString("rootvp not authenticated after mounting")
        if strOff < 0 {
            if verbose { print("  [-] Kernel [3]: rootvp string not found") }
            return 0
        }
        for (adrpOff, addOff) in findStringRefs(strFoff: strOff) {
            var blPanicOff = -1
            for scan in stride(from: addOff, to: min(addOff + 0x40, data.count - 4), by: 4) {
                let insn = data.withUnsafeBytes { $0.load(fromByteOffset: scan, as: UInt32.self) }
                if ARM64.isBL(insn) && ARM64.decodeBLTarget(insn: insn, foff: scan) == panicOff {
                    blPanicOff = scan
                    break
                }
            }
            if blPanicOff < 0 { continue }
            let errLo = blPanicOff - 0x40
            let errHi = blPanicOff + 4
            for back in stride(from: adrpOff - 4, through: max(adrpOff - 0x400, 0), by: -4) {
                let insn = data.withUnsafeBytes { $0.load(fromByteOffset: back, as: UInt32.self) }
                if let target = decodeCondBranchTarget(insn, at: back),
                    errLo <= target && target <= errHi
                {
                    return emit(
                        "Patch[3] bsd_init rootvp auth (NOP cond branch)", at: back, [ARM64.nop])
                }
            }
        }
        if verbose { print("  [-] Kernel [3]: rootvp cond branch not found") }
        return 0
    }

    // MARK: - Patches 4-5: proc_check_launch_constraints → mov w0,#0; ret

    private func patchLaunchConstraints() -> Int {
        let strOff = findString("AMFI: Validation Category info")
        if strOff < 0 {
            if verbose { print("  [-] Kernel [4-5]: 'AMFI: Validation Category info' not found") }
            return 0
        }
        for (adrpOff, _) in findStringRefs(strFoff: strOff) {
            let funcStart = findFunctionStart(adrpOff)
            if funcStart < 0 { continue }
            return emit(
                "Patch[4-5] proc_check_launch_constraints stub", at: funcStart,
                [ARM64.mov_w0_0, ARM64.ret])
        }
        if verbose { print("  [-] Kernel [4-5]: function start not found") }
        return 0
    }

    // MARK: - Patches 6-7: PE_i_can_has_debugger → mov x0,#1; ret

    private func patchDebugger() -> Int {
        // Strategy: ADRP X8 preceded by function boundary (ret/pacibsp),
        // followed by LDR Wx,[X8,#imm] within 6 instructions,
        // AND has 50-250 BL callers.
        var bestOff = -1
        var bestCallers = 0
        for seg in macho.codeSegments {
            for off in stride(from: seg.start, to: seg.end - 24, by: 4) {
                let i0 = data.withUnsafeBytes { $0.load(fromByteOffset: off, as: UInt32.self) }
                guard ARM64.isADRP(i0) && (i0 & 0x1F) == 8 else { continue }  // ADRP X8
                // Must be preceded by function boundary
                guard off >= 4 else { continue }
                let prev = data.withUnsafeBytes {
                    $0.load(fromByteOffset: off - 4, as: UInt32.self)
                }
                guard ARM64.isFuncBoundary(prev) else { continue }
                // Must have LDR Wr, [X8, #imm] within first 6 instructions
                var hasWLoad = false
                for k in 1...6 {
                    let kOff = off + k * 4
                    guard kOff + 4 <= data.count else { break }
                    let ki = data.withUnsafeBytes { $0.load(fromByteOffset: kOff, as: UInt32.self) }
                    // LDR Wr, [X8, #imm]: 32-bit unsigned offset load from X8
                    // 64-bit LDR (unsigned offset): bits[31:22] = 0b11_11100_1_01 = NOT this
                    // 32-bit LDR (unsigned offset): bits[31:22] = 0b10_11100_1_01 = 0x2E5? No.
                    // 32-bit unsigned: 0xB940_0000, Rn=8: 0xB940_0008 masked with any Rt
                    // Actually: LDR Wt, [Xn, #imm12*4]: 0xB9400000 | (imm << 10) | (Rn << 5) | Rt
                    // Check LDR Wr, [X8]: bits[31:22]=0b10111001_01 and Rn=8
                    let isLDRW_X8 = ((ki >> 22) & 0x3FF) == 0x2E5 && ((ki >> 5) & 0x1F) == 8
                    if isLDRW_X8 {
                        hasWLoad = true
                        break
                    }
                }
                guard hasWLoad else { continue }
                let nCallers = blCallers[off, default: []].count
                if nCallers >= 50 && nCallers <= 250 && nCallers > bestCallers {
                    bestCallers = nCallers
                    bestOff = off
                }
            }
        }
        if bestOff >= 0 {
            return emit(
                "Patch[6-7] PE_i_can_has_debugger stub (\(bestCallers) callers)", at: bestOff,
                [ARM64.mov_x0_1, ARM64.ret])
        }
        if verbose { print("  [-] Kernel [6-7]: PE_i_can_has_debugger not found") }
        return 0
    }

    // MARK: - Patch 8: TXM post-validation NOP (tbnz)

    private func patchPostValidationNOP() -> Int {
        let strOff = findString("TXM [Error]: CodeSignature")
        if strOff < 0 {
            if verbose { print("  [-] Kernel [8]: 'TXM [Error]: CodeSignature' not found") }
            return 0
        }
        for (_, addOff) in findStringRefs(strFoff: strOff) {
            for scan in stride(from: addOff, to: min(addOff + 0x40, data.count - 4), by: 4) {
                let insn = data.withUnsafeBytes { $0.load(fromByteOffset: scan, as: UInt32.self) }
                // TBNZ: bits[31:24]=0x37
                if (insn & 0xFF00_0000) == 0x3700_0000 {
                    return emit("Patch[8] TXM post-validation NOP tbnz", at: scan, [ARM64.nop])
                }
            }
        }
        if verbose { print("  [-] Kernel [8]: TBNZ not found after TXM error string") }
        return 0
    }

    // MARK: - Patch 9: postValidation CMP → cmp w0,w0

    private func patchPostValidationCMP() -> Int {
        let strOff = findString("AMFI: code signature validation failed")
        if strOff < 0 {
            if verbose { print("  [-] Kernel [9]: AMFI code-sig string not found") }
            return 0
        }
        let refs = findStringRefs(strFoff: strOff)
        guard !refs.isEmpty else {
            if verbose { print("  [-] Kernel [9]: no code refs") }
            return 0
        }
        let callerStart = findFunctionStart(refs[0].0)
        if callerStart < 0 {
            if verbose { print("  [-] Kernel [9]: caller function start not found") }
            return 0
        }
        // Collect BL targets from caller (stop only at PACIBSP, not at ret)
        var blTargets = Set<Int>()
        for scan in stride(from: callerStart, to: min(callerStart + 0x2000, data.count - 4), by: 4)
        {
            if scan > callerStart + 8 {
                let insn = data.withUnsafeBytes { $0.load(fromByteOffset: scan, as: UInt32.self) }
                if insn == ARM64.pacibsp || insn == ARM64.paciasp { break }
            }
            let insn = data.withUnsafeBytes { $0.load(fromByteOffset: scan, as: UInt32.self) }
            if ARM64.isBL(insn) {
                blTargets.insert(ARM64.decodeBLTarget(insn: insn, foff: scan))
            }
        }
        // In each BL target (within all code segments), look for: CMP W0, #imm; B.NE
        for target in blTargets.sorted() {
            let inCode = macho.codeSegments.contains { target >= $0.start && target < $0.end }
            guard inCode else { continue }
            for off in stride(from: target, to: min(target + 0x200, data.count - 8), by: 4) {
                if off > target + 8 {
                    let insn = data.withUnsafeBytes {
                        $0.load(fromByteOffset: off, as: UInt32.self)
                    }
                    if insn == ARM64.pacibsp || insn == ARM64.paciasp { break }
                }
                let i0 = data.withUnsafeBytes { $0.load(fromByteOffset: off, as: UInt32.self) }
                let i1 = data.withUnsafeBytes { $0.load(fromByteOffset: off + 4, as: UInt32.self) }
                // CMP W0, #imm: SUBS WZR, W0, #imm — bits[31:22]=0b0111000100, Rn=0, Rd=31
                // = (insn & 0xFFC003FF) == 0x7100001F
                let isCMPW0imm = (i0 & 0xFFC0_03FF) == 0x7100_001F
                // B.NE: (insn & 0xFF00001F) == 0x54000001
                let isBNE = (i1 & 0xFF00_001F) == 0x5400_0001
                guard isCMPW0imm && isBNE else { continue }
                // Verify preceded by BL within 2 instructions
                var hasBL = false
                for gap in [4, 8] {
                    if off - gap >= 0 {
                        let bi = data.withUnsafeBytes {
                            $0.load(fromByteOffset: off - gap, as: UInt32.self)
                        }
                        if ARM64.isBL(bi) {
                            hasBL = true
                            break
                        }
                    }
                }
                guard hasBL else { continue }
                return emit("Patch[9] postValidation cmp w0,w0", at: off, [ARM64.cmp_w0_w0])
            }
        }
        if verbose { print("  [-] Kernel [9]: CMP W0,#imm + B.NE not found") }
        return 0
    }

    // MARK: - Patches 10-11: check_dyld_policy_internal → mov w0,#1 (two BLs)

    private func patchCheckDyldPolicy() -> Int {
        let strOff = findString("com.apple.developer.swift-playgrounds-app.development-build")
        if strOff < 0 {
            if verbose { print("  [-] Kernel [10-11]: swift-playgrounds string not found") }
            return 0
        }
        for (adrpOff, _) in findStringRefs(strFoff: strOff) {
            // Walk backward for BL + conditional-branch-on-W0 pairs
            var blsWithCond: [(off: Int, target: Int)] = []
            for back in stride(from: adrpOff - 4, through: max(adrpOff - 80, 0), by: -4) {
                let insn = data.withUnsafeBytes { $0.load(fromByteOffset: back, as: UInt32.self) }
                guard ARM64.isBL(insn) else { continue }
                let blTarget = ARM64.decodeBLTarget(insn: insn, foff: back)
                let next = data.withUnsafeBytes {
                    $0.load(fromByteOffset: back + 4, as: UInt32.self)
                }
                // Condition on W0: CBZ/CBNZ W0 or B.cc after BL
                let isCBZW0 =
                    (next & 0xFF00_001F) == 0x3400_0000 || (next & 0xFF00_001F) == 0x3500_0000
                // tbz/tbnz W0, #bit, label: op=0x36/0x37, Rt=W0 (bits[4:0]=0)
                let isTBZW0 =
                    (next & 0xFF00_001F) == 0x3600_0000 || (next & 0xFF00_001F) == 0x3700_0000
                let isBcond = (next & 0xFF00_0010) == 0x5400_0000
                if isCBZW0 || isTBZW0 || isBcond {
                    blsWithCond.append((back, blTarget))
                }
            }
            guard blsWithCond.count >= 2 else { continue }
            let bl2 = blsWithCond[0]  // closer to ADRP
            let bl1 = blsWithCond[1]  // farther
            // The two BLs must target DIFFERENT functions
            guard bl1.target != bl2.target else { continue }
            var count = 0
            count += emit("Patch[10] dyld_policy BL1 → mov w0,#1", at: bl1.off, [ARM64.mov_w0_1])
            count += emit("Patch[11] dyld_policy BL2 → mov w0,#1", at: bl2.off, [ARM64.mov_w0_1])
            return count
        }
        if verbose { print("  [-] Kernel [10-11]: dyld_policy BL pair not found") }
        return 0
    }

    // MARK: - Patch 12: apfs_graft → mov w0,#0 (BL validate_root_hash)

    private func patchAPFSGraft() -> Int {
        let strOff = findExactString("apfs_graft")
        if strOff < 0 {
            if verbose { print("  [-] Kernel [12]: 'apfs_graft' string not found") }
            return 0
        }
        let refs = findStringRefs(strFoff: strOff)
        guard !refs.isEmpty else {
            if verbose { print("  [-] Kernel [12]: no code refs to apfs_graft") }
            return 0
        }
        let graftStart = findFunctionStart(refs[0].0)
        if graftStart < 0 {
            if verbose { print("  [-] Kernel [12]: _apfs_graft function start not found") }
            return 0
        }
        // Find validate_on_disk_root_hash via its string ref
        let vrhFuncOff = findValidateRootHashFunc()
        if vrhFuncOff < 0 {
            if verbose { print("  [-] Kernel [12]: validate_on_disk_root_hash not found") }
            return 0
        }
        // Scan _apfs_graft for BL to validate_on_disk_root_hash
        for scan in stride(from: graftStart, to: min(graftStart + 0x2000, data.count - 4), by: 4) {
            if scan > graftStart + 8 {
                let insn = data.withUnsafeBytes { $0.load(fromByteOffset: scan, as: UInt32.self) }
                if insn == ARM64.pacibsp || insn == ARM64.paciasp { break }
            }
            let insn = data.withUnsafeBytes { $0.load(fromByteOffset: scan, as: UInt32.self) }
            if ARM64.isBL(insn) && ARM64.decodeBLTarget(insn: insn, foff: scan) == vrhFuncOff {
                return emit("Patch[12] apfs_graft: mov w0,#0 (BL vrh)", at: scan, [ARM64.mov_w0_0])
            }
        }
        if verbose {
            print("  [-] Kernel [12]: BL to validate_on_disk_root_hash not found in _apfs_graft")
        }
        return 0
    }

    private func findValidateRootHashFunc() -> Int {
        let strOff = findString("authenticate_root_hash")
        if strOff < 0 { return -1 }
        let refs = findStringRefs(strFoff: strOff)
        if refs.isEmpty { return -1 }
        return findFunctionStart(refs[0].0)
    }

    // MARK: - Patch 13: apfs_vfsop_mount CMP X0,Xm → cmp x0,x0

    private func patchAPFSVFSMountCMP() -> Int {
        let strOff = findExactString("apfs_mount_upgrade_checks")
        if strOff < 0 {
            if verbose { print("  [-] Kernel [13]: 'apfs_mount_upgrade_checks' string not found") }
            return 0
        }
        let refs = findStringRefs(strFoff: strOff)
        guard !refs.isEmpty else {
            if verbose { print("  [-] Kernel [13]: no code refs") }
            return 0
        }
        let funcStart = findFunctionStart(refs[0].0)
        if funcStart < 0 {
            if verbose { print("  [-] Kernel [13]: _apfs_mount_upgrade_checks start not found") }
            return 0
        }
        // Find callers of _apfs_mount_upgrade_checks via BL index
        var callers = blCallers[funcStart, default: []]
        if callers.isEmpty {
            callers = blCallers[funcStart + 4, default: []]
        }
        // Fallback: linear scan for BL to funcStart
        if callers.isEmpty {
            for seg in macho.codeSegments {
                for off in stride(from: seg.start, to: seg.end - 4, by: 4) {
                    let insn = data.withUnsafeBytes {
                        $0.load(fromByteOffset: off, as: UInt32.self)
                    }
                    if ARM64.isBL(insn) && ARM64.decodeBLTarget(insn: insn, foff: off) == funcStart
                    {
                        callers.append(off)
                    }
                }
            }
        }
        if callers.isEmpty {
            if verbose { print("  [-] Kernel [13]: no callers of _apfs_mount_upgrade_checks") }
            return 0
        }
        for callerOff in callers {
            let callerFuncStart = findFunctionStart(callerOff)
            let scanStart = callerFuncStart >= 0 ? callerFuncStart : max(callerOff - 0x800, 0)
            let scanEnd = min(callerOff + 0x100, data.count - 4)
            for scan in stride(from: scanStart, to: scanEnd, by: 4) {
                let insn = data.withUnsafeBytes { $0.load(fromByteOffset: scan, as: UInt32.self) }
                // CMP X0, Xm (64-bit register CMP): SUBS XZR, X0, Xm
                // = 0xEB000000 | (Rm << 16) | (0 << 5) | 31, but check via:
                // (insn & 0xFF20_03FF) == 0xEB00_001F  (Rn=0, Rd=31=XZR, shift=LSL, 64-bit)
                guard (insn & 0xFF20_03FF) == 0xEB00_001F else { continue }
                // Skip if it's already CMP X0, X0
                let rm = (insn >> 16) & 0x1F
                guard rm != 0 else { continue }
                return emit("Patch[13] apfs_vfsop_mount cmp x0,x0", at: scan, [ARM64.cmp_x0_x0])
            }
        }
        if verbose {
            print("  [-] Kernel [13]: CMP X0,Xm not found near mount_upgrade_checks callers")
        }
        return 0
    }

    // MARK: - Patch 14: apfs_mount_upgrade_checks TBNZ W0,#0xe → mov w0,#0

    private func patchAPFSMountUpgradeChecks() -> Int {
        let strOff = findExactString("apfs_mount_upgrade_checks")
        if strOff < 0 {
            if verbose { print("  [-] Kernel [14]: 'apfs_mount_upgrade_checks' string not found") }
            return 0
        }
        let refs = findStringRefs(strFoff: strOff)
        guard !refs.isEmpty else { return 0 }
        let funcStart = findFunctionStart(refs[0].0)
        if funcStart < 0 {
            if verbose { print("  [-] Kernel [14]: function start not found") }
            return 0
        }
        for scan in stride(from: funcStart, to: min(funcStart + 0x200, data.count - 8), by: 4) {
            if scan > funcStart + 8 {
                let insn = data.withUnsafeBytes { $0.load(fromByteOffset: scan, as: UInt32.self) }
                if insn == ARM64.pacibsp || insn == ARM64.paciasp { break }
            }
            let insn = data.withUnsafeBytes { $0.load(fromByteOffset: scan, as: UInt32.self) }
            guard ARM64.isBL(insn) else { continue }
            // Check BL target is a small leaf (ends with ret within 0x20 bytes)
            let blTarget = ARM64.decodeBLTarget(insn: insn, foff: scan)
            var isLeaf = false
            for k in stride(from: 0, to: 0x20, by: 4) {
                if blTarget + k >= data.count { break }
                let ki = data.withUnsafeBytes {
                    $0.load(fromByteOffset: blTarget + k, as: UInt32.self)
                }
                if ARM64.isRet(ki) {
                    isLeaf = true
                    break
                }
            }
            guard isLeaf else { continue }
            let next = data.withUnsafeBytes { $0.load(fromByteOffset: scan + 4, as: UInt32.self) }
            // TBNZ W0, #0xe — b40=0xe=14, b5=0 → bits[23:19]=14, bits[31:24]=0x37, Rt=0
            // (next >> 19) & 0x1FFF == (0x37 << 5) | 14 = 0x6E0 | 14 = 0x6EE
            // But also check Rt=0: (next & 0x1F) == 0
            let isTBNZ_W0_e =
                ((next >> 24) & 0xFF) == 0x37 && ((next >> 19) & 0x1F) == 14 && (next & 0x1F) == 0
            if isTBNZ_W0_e {
                return emit(
                    "Patch[14] apfs_mount_upgrade_checks: mov w0,#0 (tbnz)", at: scan + 4,
                    [ARM64.mov_w0_0])
            }
        }
        if verbose { print("  [-] Kernel [14]: BL+TBNZ W0,#0xe pattern not found") }
        return 0
    }

    // MARK: - Patch 15: handle_fsioc_graft → mov w0,#0 (BL validate_payload_and_manifest)

    private func patchHandleFsiocGraft() -> Int {
        let strOff = findExactString("handle_fsioc_graft")
        if strOff < 0 {
            if verbose { print("  [-] Kernel [15]: 'handle_fsioc_graft' string not found") }
            return 0
        }
        let refs = findStringRefs(strFoff: strOff)
        guard !refs.isEmpty else {
            if verbose { print("  [-] Kernel [15]: no code refs") }
            return 0
        }
        let fsiocStart = findFunctionStart(refs[0].0)
        if fsiocStart < 0 {
            if verbose { print("  [-] Kernel [15]: function start not found") }
            return 0
        }
        let valFuncOff = findValidatePayloadManifestFunc()
        if valFuncOff < 0 {
            if verbose { print("  [-] Kernel [15]: validate_payload_and_manifest not found") }
            return 0
        }
        for scan in stride(from: fsiocStart, to: min(fsiocStart + 0x400, data.count - 4), by: 4) {
            if scan > fsiocStart + 8 {
                let insn = data.withUnsafeBytes { $0.load(fromByteOffset: scan, as: UInt32.self) }
                if insn == ARM64.pacibsp || insn == ARM64.paciasp { break }
            }
            let insn = data.withUnsafeBytes { $0.load(fromByteOffset: scan, as: UInt32.self) }
            if ARM64.isBL(insn) && ARM64.decodeBLTarget(insn: insn, foff: scan) == valFuncOff {
                return emit(
                    "Patch[15] handle_fsioc_graft: mov w0,#0 (BL val)", at: scan, [ARM64.mov_w0_0])
            }
        }
        if verbose { print("  [-] Kernel [15]: BL to validate_payload_and_manifest not found") }
        return 0
    }

    private func findValidatePayloadManifestFunc() -> Int {
        let strOff = findString("validate_payload_and_manifest")
        if strOff < 0 { return -1 }
        let refs = findStringRefs(strFoff: strOff)
        if refs.isEmpty { return -1 }
        return findFunctionStart(refs[0].0)
    }

    // MARK: - Patches 16-25: Sandbox MACF hooks stub

    private func patchSandboxHooks() -> Int {
        // Find exact \0Sandbox\0 and "Seatbelt sandbox policy"
        let sandboxRaw = data.range(of: Data([0]) + "Sandbox".data(using: .utf8)! + Data([0]))
        guard let sandboxRange = sandboxRaw else {
            if verbose { print("  [-] Kernel [16-25]: \\0Sandbox\\0 not found") }
            return 0
        }
        let sandboxFoff = sandboxRange.lowerBound + 1  // offset of 'S' in Sandbox

        let seatbeltFoff = findString("Seatbelt sandbox policy")
        if seatbeltFoff < 0 {
            if verbose { print("  [-] Kernel [16-25]: 'Seatbelt sandbox policy' not found") }
            return 0
        }
        if verbose {
            print(
                "  [*] Kernel: Sandbox foff 0x\(String(sandboxFoff, radix: 16)), Seatbelt foff 0x\(String(seatbeltFoff, radix: 16))"
            )
        }

        // Find mac_policy_conf in data segments.
        // In the kernel on-disk binary, the mac_policy_conf fields are stored as
        // dyld chained fixup "non-auth rebase" pointers (bit63=0):
        //   mpc_name    at +0:  lower 43 bits (target field) == sandboxFoff
        //   mpc_fullname at +8: lower 43 bits (target field) == seatbeltFoff
        //   mpc_ops     at +32: non-auth rebase target == ops_table file offset
        // ops_table function entries use auth rebase (bit63=1): lower 32 bits == func file offset
        let mask43 = UInt64(0x7FF_FFFF_FFFF)
        var opsTableOff = -1
        let dataSegs = macho.dataSegments
        outer: for (dStart, dEnd) in dataSegs {
            for i in stride(from: dStart, to: dEnd - 40, by: 8) {
                guard i + 40 <= data.count else { break }
                let val0 = data.withUnsafeBytes { $0.load(fromByteOffset: i, as: UInt64.self) }
                let val1 = data.withUnsafeBytes { $0.load(fromByteOffset: i + 8, as: UInt64.self) }
                // Both must be non-auth rebase (bit63=0) with target == file offset
                guard (val0 & (1 << 63)) == 0 && (val1 & (1 << 63)) == 0 else { continue }
                guard (val0 & mask43) == UInt64(sandboxFoff) else { continue }
                guard (val1 & mask43) == UInt64(seatbeltFoff) else { continue }
                // ops pointer at +32
                let opsVal = data.withUnsafeBytes {
                    $0.load(fromByteOffset: i + 32, as: UInt64.self)
                }
                // ops pointer may be non-auth rebase: extract lower 43 bits as file offset
                let rawOps = Int(opsVal & mask43)
                guard rawOps > 0 && rawOps < data.count else { continue }
                opsTableOff = rawOps
                if verbose {
                    print(
                        "  [*] Kernel: mac_policy_conf foff 0x\(String(i, radix: 16)), ops_table→0x\(String(opsTableOff, radix: 16))"
                    )
                }
                break outer
            }
        }

        if opsTableOff < 0 {
            if verbose { print("  [-] Kernel [16-25]: mac_policy_conf not found") }
            return 0
        }

        // Read function pointers from ops table (auth rebase, bit63=1: lower 32 bits = file offset)
        let hookIndices = [36, 87, 88, 91, 120]
        var count = 0
        for idx in hookIndices {
            let entryOff = opsTableOff + idx * 8
            guard entryOff + 8 <= data.count else { continue }
            let funcVal = data.withUnsafeBytes {
                $0.load(fromByteOffset: entryOff, as: UInt64.self)
            }
            // Try auth rebase (bit63=1) first
            let funcOff: Int
            if (funcVal & (1 << 63)) != 0 {
                funcOff = Int(funcVal & 0xFFFF_FFFF)
            } else {
                // Non-auth rebase: use lower 43 bits
                let raw = Int(funcVal & mask43)
                funcOff = raw > 0 ? raw : -1
            }
            guard funcOff > 0 && funcOff + 8 <= data.count else {
                if verbose {
                    print("  [-] Kernel: sandbox ops[\(idx)] invalid (funcOff=\(funcOff))")
                }
                continue
            }
            count += emit(
                "Patch sandbox hook ops[\(idx)] (mov x0,#0; ret)", at: funcOff,
                [ARM64.mov_x0_0, ARM64.ret])
        }
        return count
    }
}

/// Main entry for patching firmware
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
