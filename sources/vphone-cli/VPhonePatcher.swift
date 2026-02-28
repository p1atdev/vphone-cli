import Foundation
import Image4

/// ARM64 instruction constants and helpers
enum ARM64 {
    static let nop: UInt32 = 0xD503_201F
    static let ret: UInt32 = 0xD65F_03C0
    static let mov_x0_0: UInt32 = 0xD280_0000
    static let mov_x0_1: UInt32 = 0xD280_0020
    static let mov_w0_0: UInt32 = 0x5280_0000
    static let mov_w0_1: UInt32 = 0x5280_0020

    /// Checks if the instruction is a return instruction (ret, retaa, retab)
    static func isRet(_ insn: UInt32) -> Bool {
        let base = insn & 0xFFFF_FC1F
        return (base == 0xD65F_0000 && (insn & 0x3E0) == 0x3C0)
            || (insn == 0xD65F_0BFF || insn == 0xD65F_0FFF)
    }

    /// Checks if the instruction is a mov x0, ... or mov w0, ...
    static func isMovX0(_ insn: UInt32) -> Bool {
        let baseImm = insn & 0x7F80_0000
        if (insn & 0x1F) == 0 && (baseImm == 0x5280_0000 || baseImm == 0x1280_0000) {
            return true
        }
        // mov x0, xN is orr x0, xzr, xN (0xaa??03e0)
        if (insn & 0xFFE0_FFFF) == 0xAA00_03E0 {
            return true
        }
        // mov w0, wN is orr w0, wzr, wN (0x2a??03e0)
        if (insn & 0xFFE0_FFFF) == 0x2A00_03E0 {
            return true
        }
        return false
    }

    /// Checks if the instruction is a BL
    static func isBL(_ insn: UInt32) -> Bool {
        return (insn & 0xFC00_0000) == 0x9400_0000
    }

    /// Decodes a BL target offset from the instruction and its address
    static func decodeBLTarget(insn: UInt32, address: UInt64) -> UInt64 {
        var imm26 = Int64(insn & 0x3FFFFFF)
        if (imm26 & (1 << 25)) != 0 {
            imm26 -= (1 << 26)
        }
        return UInt64(bitPattern: Int64(bitPattern: address) + (imm26 * 4))
    }

    /// Encodes a BL target offset into an instruction at a given address
    static func encodeBL(target: UInt64, address: UInt64) -> UInt32 {
        let offset = (Int64(bitPattern: target) - Int64(bitPattern: address)) / 4
        return 0x9400_0000 | (UInt32(truncatingIfNeeded: offset) & 0x3FFFFFF)
    }

    /// Checks if the instruction is an ADRP
    static func isADRP(_ insn: UInt32) -> Bool {
        return (insn & 0x9F00_0000) == 0x9000_0000
    }

    /// Decodes an ADRP target page from the instruction and its address
    static func decodeADRP(insn: UInt32, address: UInt64) -> UInt64 {
        let immlo = (insn >> 29) & 0x3
        let immhi = (insn >> 5) & 0x7FFFF
        var imm = Int64((immhi << 2) | immlo)
        if (imm & (1 << 20)) != 0 {
            imm -= (1 << 21)
        }
        return UInt64(bitPattern: (Int64(bitPattern: address) & ~0xFFF) + (imm << 12))
    }

    /// Encodes an ADRP instruction targeting a page from a given address
    static func encodeADRP(target: UInt64, address: UInt64, rd: UInt32) -> UInt32 {
        let imm = (Int64(bitPattern: target & ~0xFFF) - Int64(bitPattern: address & ~0xFFF))
        let imm_val = imm >> 12
        let immlo = UInt32(truncatingIfNeeded: imm_val & 0x3)
        let immhi = UInt32(truncatingIfNeeded: (imm_val >> 2) & 0x7FFFF)
        return 0x9000_0000 | (immlo << 29) | (immhi << 5) | (rd & 0x1F)
    }

    /// Checks if the instruction is an ADD (immediate)
    static func isADDImm(_ insn: UInt32) -> Bool {
        return (insn & 0xFF00_0000) == 0x9100_0000
    }

    /// Decodes an ADD (immediate) value
    static func decodeADDImm(_ insn: UInt32) -> Int {
        let imm12 = (insn >> 10) & 0xFFF
        let shift = (insn >> 22) & 0x3
        return Int(imm12) << (shift == 1 ? 12 : 0)
    }

    /// Encodes an ADD (immediate) instruction
    static func encodeADDImm(rd: UInt32, rn: UInt32, imm: Int) -> UInt32 {
        let imm12 = UInt32(imm & 0xFFF)
        return 0x9100_0000 | (imm12 << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)
    }
}

/// Mach-O Parsing Helpers
struct MachO {
    struct Section {
        let segname: String
        let sectname: String
        let vmaddr: UInt64
        let size: UInt64
        let offset: UInt32
    }

    let data: Data
    var sections: [String: Section] = [:]
    var segments:
        [(name: String, vmaddr: UInt64, vmsize: UInt64, fileoff: UInt64, filesize: UInt64)] = []
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

                    segments.append((segname, vmaddr, vmsize, fileoff, filesize))
                    if segname == "__TEXT" {
                        baseVA = vmaddr
                    }

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
            var markerIdx: Int? = nil
            for i in stride(from: 0, to: buffer.count - 4, by: 4) {
                let insn = buffer.load(fromByteOffset: i, as: UInt32.self)
                if insn == 0x5284_88D3 {  // mov w19, #0x2446
                    markerIdx = i
                    break
                }
            }

            guard let mIdx = markerIdx else { return }

            var funcStart: Int? = nil
            for i in stride(from: mIdx & ~3, to: max(mIdx - 1024, 0), by: -4) {
                let insn = buffer.load(fromByteOffset: i, as: UInt32.self)
                if insn == 0xD503_233F {  // pacibsp
                    funcStart = i
                    break
                }
            }

            guard let start = funcStart else { return }
            for i in stride(from: start, to: min(start + 2048, buffer.count - 12), by: 4) {
                let i0 = buffer.load(fromByteOffset: i, as: UInt32.self)
                let i1 = buffer.load(fromByteOffset: i + 4, as: UInt32.self)
                let i2 = buffer.load(fromByteOffset: i + 8, as: UInt32.self)
                if i0 == 0x5280_0282 && ARM64.isBL(i1) && (i2 & 0xFF00_001F) == 0x3400_0000 {
                    buffer.storeBytes(
                        of: ARM64.mov_x0_0.littleEndian, toByteOffset: i + 4, as: UInt32.self)
                    if verbose {
                        print(
                            "  [+] TXM: Patched trustcache bypass at 0x\(String(i + 4, radix: 16))")
                    }
                    patchCount += 1
                    break
                }
            }
        }
        return patchCount
    }
}

class IBootPatcher: Patcher {
    var data: Data
    private let mode: String
    private let verbose: Bool

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
        return patchCount
    }

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
                count += 1
            }
        }
        return count
    }

    private func patchImage4Callback() -> Int {
        for i in stride(from: 0, to: data.count - 8, by: 4) {
            let i0 = data.withUnsafeBytes { $0.load(fromByteOffset: i, as: UInt32.self) }
            let i1 = data.withUnsafeBytes { $0.load(fromByteOffset: i + 4, as: UInt32.self) }
            if (i0 & 0xFF00_000F) == 0x5400_0001 && i1 == 0xAA16_03E0 {
                var foundCmp = false
                for j in stride(from: i - 32, to: i, by: 4) {
                    if j < 0 { continue }
                    let insn = data.withUnsafeBytes { $0.load(fromByteOffset: j, as: UInt32.self) }
                    if (insn & 0xFF20_0000) == 0xEB00_0000 {
                        foundCmp = true
                        break
                    }
                }
                if foundCmp {
                    let nopData = withUnsafeBytes(of: ARM64.nop.littleEndian) { Data($0) }
                    let movData = withUnsafeBytes(of: ARM64.mov_x0_0.littleEndian) { Data($0) }
                    self.data.replaceSubrange(i..<(i + 4), with: nopData)
                    self.data.replaceSubrange((i + 4)..<(i + 8), with: movData)
                    if verbose {
                        print("  [+] iBoot: Patched image4 callback at 0x\(String(i, radix: 16))")
                    }
                    return 2
                }
            }
        }
        return 0
    }

    private func patchBootArgs() -> Int {
        let newArgs = "serial=3 rd=md0 debug=0x2014e -v wdt=-1 %s".data(using: .utf8)!
        guard
            let anchorRange = data.range(of: "rd=md0".data(using: .utf8)!)
                ?? data.range(of: "BootArgs".data(using: .utf8)!)
        else { return 0 }
        let searchStart = anchorRange.lowerBound
        let searchRange = searchStart..<(min(searchStart + 0x100, data.count))
        guard let fmtRange = data.range(of: "%s\0".data(using: .utf8)!, in: searchRange) else {
            return 0
        }
        let fmtOffset = UInt64(fmtRange.lowerBound)
        for i in stride(from: 0, to: data.count - 8, by: 4) {
            let i0 = data.withUnsafeBytes { $0.load(fromByteOffset: i, as: UInt32.self) }
            let i1 = data.withUnsafeBytes { $0.load(fromByteOffset: i + 4, as: UInt32.self) }
            if ARM64.isADRP(i0) && ARM64.isADDImm(i1) {
                let rd0 = i0 & 0x1F
                let rd1 = i1 & 0x1F
                let rn1 = (i1 >> 5) & 0x1F
                if rd0 == 2 && rd1 == 2 && rn1 == 2 {
                    let target =
                        ARM64.decodeADRP(insn: i0, address: UInt64(i))
                        + UInt64(ARM64.decodeADDImm(i1))
                    if target == fmtOffset {
                        if let slotIdx = findStringSlot(length: newArgs.count) {
                            let slotVa = UInt64(slotIdx)
                            data.replaceSubrange(slotIdx..<(slotIdx + newArgs.count), with: newArgs)
                            let newADRP = ARM64.encodeADRP(
                                target: slotVa, address: UInt64(i), rd: 2)
                            let newADD = ARM64.encodeADDImm(rd: 2, rn: 2, imm: Int(slotVa & 0xFFF))
                            let adrpData = withUnsafeBytes(of: newADRP.littleEndian) { Data($0) }
                            let addData = withUnsafeBytes(of: newADD.littleEndian) { Data($0) }
                            data.replaceSubrange(i..<(i + 4), with: adrpData)
                            data.replaceSubrange((i + 4)..<(i + 8), with: addData)
                            if verbose {
                                print(
                                    "  [+] iBoot: Redirected boot-args to 0x\(String(slotIdx, radix: 16))"
                                )
                            }
                            return 2
                        }
                    }
                }
            }
        }
        return 0
    }

    private func findStringSlot(length: Int) -> Int? {
        var searchIdx = 0x14000
        while searchIdx < data.count - length {
            if data[searchIdx] == 0 {
                var zeroCount = 0
                while searchIdx + zeroCount < data.count && data[searchIdx + zeroCount] == 0 {
                    zeroCount += 1
                }
                if zeroCount >= length + 16 { return (searchIdx + 8 + 15) & ~15 }
                searchIdx += zeroCount
            } else {
                searchIdx += 1
            }
        }
        return nil
    }
}

class KernelPatcher: Patcher {
    var data: Data
    private let verbose: Bool
    private var macho: MachO?

    init(data: Data, verbose: Bool = true) {
        self.data = data
        self.verbose = verbose
        self.macho = try? MachO(data: data)
    }

    func apply() throws -> Int {
        var patchCount = 0
        patchCount += patchAPFSRootSnapshot()
        patchCount += patchAPFSSealBroken()
        patchCount += patchBSDInitRootVP()
        patchCount += patchLaunchConstraints()
        patchCount += patchDebugger()
        patchCount += patchPostValidationNOP()
        patchCount += patchPostValidationCMP()
        patchCount += patchCheckDyldPolicy()
        patchCount += patchAPFSVFSMountCMP()
        patchCount += patchSandboxHooks()
        return patchCount
    }

    private func findString(_ s: String) -> Int {
        guard let range = data.range(of: s.data(using: .utf8)!) else { return -1 }
        var off = range.lowerBound
        while off > 0 && data[off - 1] != 0 {
            off -= 1
        }
        return off
    }

    private func patchAPFSRootSnapshot() -> Int {
        let strOff = findString("Rooting from snapshot with xid")
        if strOff < 0 { return 0 }
        let strVa = macho?.foffToVa(strOff) ?? 0

        var count = 0
        data.withUnsafeMutableBytes { buffer in
            for i in stride(from: 0, to: buffer.count - 8, by: 4) {
                let i0 = buffer.load(fromByteOffset: i, as: UInt32.self)
                let i1 = buffer.load(fromByteOffset: i + 4, as: UInt32.self)
                if ARM64.isADRP(i0) && ARM64.isADDImm(i1) {
                    let va = macho?.foffToVa(i) ?? 0
                    let target =
                        ARM64.decodeADRP(insn: i0, address: va) + UInt64(ARM64.decodeADDImm(i1))
                    if target == strVa {
                        for j in stride(from: i + 8, to: min(i + 0x200, buffer.count - 4), by: 4) {
                            let insn = buffer.load(fromByteOffset: j, as: UInt32.self)
                            if (insn & 0xFF00_0000) == 0x3700_0000 && (insn & 0x1F) == 0x08
                                && ((insn >> 19) & 0x1F) == 5
                            {
                                buffer.storeBytes(
                                    of: ARM64.nop.littleEndian, toByteOffset: j, as: UInt32.self)
                                if verbose {
                                    print(
                                        "  [+] Kernel: Patched APFS root snapshot check at 0x\(String(j, radix: 16))"
                                    )
                                }
                                count += 1
                                break
                            }
                        }
                    }
                }
            }
        }
        return count
    }

    private func patchAPFSSealBroken() -> Int {
        let strOff = findString("root volume seal is broken")
        if strOff < 0 { return 0 }
        let strVa = macho?.foffToVa(strOff) ?? 0

        var count = 0
        data.withUnsafeMutableBytes { buffer in
            for i in stride(from: 0, to: buffer.count - 8, by: 4) {
                let i0 = buffer.load(fromByteOffset: i, as: UInt32.self)
                let i1 = buffer.load(fromByteOffset: i + 4, as: UInt32.self)
                if ARM64.isADRP(i0) && ARM64.isADDImm(i1) {
                    let va = macho?.foffToVa(i) ?? 0
                    let target =
                        ARM64.decodeADRP(insn: i0, address: va) + UInt64(ARM64.decodeADDImm(i1))
                    if target == strVa {
                        for j in stride(from: i - 4, to: max(i - 0x100, 0), by: -4) {
                            let insn = buffer.load(fromByteOffset: j, as: UInt32.self)
                            if (insn & 0xFE00_0000) == 0x3600_0000
                                || (insn & 0xFF00_0000) == 0x5400_0000
                            {
                                buffer.storeBytes(
                                    of: ARM64.nop.littleEndian, toByteOffset: j, as: UInt32.self)
                                if verbose {
                                    print(
                                        "  [+] Kernel: Patched APFS seal broken check at 0x\(String(j, radix: 16))"
                                    )
                                }
                                count += 1
                                break
                            }
                        }
                    }
                }
            }
        }
        return count
    }

    private func patchBSDInitRootVP() -> Int {
        let strOff = findString("rootvp not authenticated after mounting")
        if strOff < 0 { return 0 }
        let strVa = macho?.foffToVa(strOff) ?? 0

        var count = 0
        data.withUnsafeMutableBytes { buffer in
            for i in stride(from: 0, to: buffer.count - 8, by: 4) {
                let i0 = buffer.load(fromByteOffset: i, as: UInt32.self)
                let i1 = buffer.load(fromByteOffset: i + 4, as: UInt32.self)
                if ARM64.isADRP(i0) && ARM64.isADDImm(i1) {
                    let va = macho?.foffToVa(i) ?? 0
                    let target =
                        ARM64.decodeADRP(insn: i0, address: va) + UInt64(ARM64.decodeADDImm(i1))
                    if target == strVa {
                        for j in stride(from: i - 4, to: max(i - 0x100, 0), by: -4) {
                            let insn = buffer.load(fromByteOffset: j, as: UInt32.self)
                            if (insn & 0xFF00_0000) == 0x3500_0000 {
                                buffer.storeBytes(
                                    of: ARM64.nop.littleEndian, toByteOffset: j, as: UInt32.self)
                                if verbose {
                                    print(
                                        "  [+] Kernel: Patched bsd_init rootvp auth check at 0x\(String(j, radix: 16))"
                                    )
                                }
                                count += 1
                                break
                            }
                        }
                    }
                }
            }
        }
        return count
    }

    private func patchLaunchConstraints() -> Int {
        let strOff = findString("AMFI: Validation Category info")
        if strOff < 0 { return 0 }
        let strVa = macho?.foffToVa(strOff) ?? 0

        var count = 0
        data.withUnsafeMutableBytes { buffer in
            for i in stride(from: 0, to: buffer.count - 8, by: 4) {
                let i0 = buffer.load(fromByteOffset: i, as: UInt32.self)
                let i1 = buffer.load(fromByteOffset: i + 4, as: UInt32.self)
                if ARM64.isADRP(i0) && ARM64.isADDImm(i1) {
                    let va = macho?.foffToVa(i) ?? 0
                    let target =
                        ARM64.decodeADRP(insn: i0, address: va) + UInt64(ARM64.decodeADDImm(i1))
                    if target == strVa {
                        for j in stride(from: i, to: max(i - 0x1000, 0), by: -4) {
                            let insn = buffer.load(fromByteOffset: j, as: UInt32.self)
                            if insn == 0xD503_233F || (insn & 0xFFC0_7FFF) == 0xA900_7BFD {
                                buffer.storeBytes(
                                    of: ARM64.mov_w0_0.littleEndian, toByteOffset: j,
                                    as: UInt32.self)
                                buffer.storeBytes(
                                    of: ARM64.ret.littleEndian, toByteOffset: j + 4, as: UInt32.self
                                )
                                if verbose {
                                    print(
                                        "  [+] Kernel: Stubbed proc_check_launch_constraints at 0x\(String(j, radix: 16))"
                                    )
                                }
                                count += 2
                                return
                            }
                        }
                    }
                }
            }
        }
        return count
    }

    private func patchDebugger() -> Int {
        var count = 0
        data.withUnsafeMutableBytes { buffer in
            for i in stride(from: 0, to: buffer.count - 16, by: 4) {
                let i0 = buffer.load(fromByteOffset: i, as: UInt32.self)
                let i1 = buffer.load(fromByteOffset: i + 4, as: UInt32.self)
                if (i0 & 0x9F00_001F) == 0x9000_0008 && (i1 & 0xFFC0_03FF) == 0xB940_0109 {
                    if i >= 4 {
                        let prev = buffer.load(fromByteOffset: i - 4, as: UInt32.self)
                        if ARM64.isRet(prev) || prev == 0xD503_233F {
                            buffer.storeBytes(
                                of: ARM64.mov_x0_1.littleEndian, toByteOffset: i, as: UInt32.self)
                            buffer.storeBytes(
                                of: ARM64.ret.littleEndian, toByteOffset: i + 4, as: UInt32.self)
                            if verbose {
                                print(
                                    "  [+] Kernel: Stubbed PE_i_can_has_debugger at 0x\(String(i, radix: 16))"
                                )
                            }
                            count += 2
                            break
                        }
                    }
                }
            }
        }
        return count
    }

    private func patchPostValidationNOP() -> Int {
        let strOff = findString("TXM [Error]: CodeSignature")
        if strOff < 0 { return 0 }
        let strVa = macho?.foffToVa(strOff) ?? 0

        var count = 0
        data.withUnsafeMutableBytes { buffer in
            for i in stride(from: 0, to: buffer.count - 8, by: 4) {
                let i0 = buffer.load(fromByteOffset: i, as: UInt32.self)
                let i1 = buffer.load(fromByteOffset: i + 4, as: UInt32.self)
                if ARM64.isADRP(i0) && ARM64.isADDImm(i1) {
                    let va = macho?.foffToVa(i) ?? 0
                    let target =
                        ARM64.decodeADRP(insn: i0, address: va) + UInt64(ARM64.decodeADDImm(i1))
                    if target == strVa {
                        for j in stride(from: i + 8, to: min(i + 0x40, buffer.count - 4), by: 4) {
                            let insn = buffer.load(fromByteOffset: j, as: UInt32.self)
                            if (insn & 0xFE00_0000) == 0x3600_0000 {
                                buffer.storeBytes(
                                    of: ARM64.nop.littleEndian, toByteOffset: j, as: UInt32.self)
                                if verbose {
                                    print(
                                        "  [+] Kernel: Patched TXM post-validation NOP at 0x\(String(j, radix: 16))"
                                    )
                                }
                                count += 1
                                break
                            }
                        }
                    }
                }
            }
        }
        return count
    }

    private func patchPostValidationCMP() -> Int {
        let strOff = findString("AMFI: code signature validation failed")
        if strOff < 0 { return 0 }
        let strVa = macho?.foffToVa(strOff) ?? 0

        var count = 0
        data.withUnsafeMutableBytes { buffer in
            for i in stride(from: 0, to: buffer.count - 8, by: 4) {
                let i0 = buffer.load(fromByteOffset: i, as: UInt32.self)
                let i1 = buffer.load(fromByteOffset: i + 4, as: UInt32.self)
                if ARM64.isADRP(i0) && ARM64.isADDImm(i1) {
                    let va = macho?.foffToVa(i) ?? 0
                    let target =
                        ARM64.decodeADRP(insn: i0, address: va) + UInt64(ARM64.decodeADDImm(i1))
                    if target == strVa {
                        for j in stride(
                            from: i & ~0xFFF, to: min((i & ~0xFFF) + 0x2000, buffer.count - 4),
                            by: 4)
                        {
                            let insn = buffer.load(fromByteOffset: j, as: UInt32.self)
                            if insn == 0x7100_081F {
                                buffer.storeBytes(
                                    of: UInt32(0x6B00_001F).littleEndian, toByteOffset: j,
                                    as: UInt32.self)
                                if verbose {
                                    print(
                                        "  [+] Kernel: Patched postValidation cmp at 0x\(String(j, radix: 16))"
                                    )
                                }
                                count += 1
                            }
                        }
                        break
                    }
                }
            }
        }
        return count
    }

    private func patchCheckDyldPolicy() -> Int {
        let strOff = findString("com.apple.developer.swift-playgrounds-app.development-build")
        if strOff < 0 { return 0 }
        let strVa = macho?.foffToVa(strOff) ?? 0

        var count = 0
        data.withUnsafeMutableBytes { buffer in
            for i in stride(from: 0, to: buffer.count - 8, by: 4) {
                let i0 = buffer.load(fromByteOffset: i, as: UInt32.self)
                let i1 = buffer.load(fromByteOffset: i + 4, as: UInt32.self)
                if ARM64.isADRP(i0) && ARM64.isADDImm(i1) {
                    let va = macho?.foffToVa(i) ?? 0
                    let target =
                        ARM64.decodeADRP(insn: i0, address: va) + UInt64(ARM64.decodeADDImm(i1))
                    if target == strVa {
                        var blsFound = 0
                        for j in stride(from: i - 4, to: max(i - 0x80, 0), by: -4) {
                            let insn = buffer.load(fromByteOffset: j, as: UInt32.self)
                            if ARM64.isBL(insn) {
                                buffer.storeBytes(
                                    of: ARM64.mov_w0_1.littleEndian, toByteOffset: j,
                                    as: UInt32.self)
                                if verbose {
                                    print(
                                        "  [+] Kernel: Patched dyld policy BL at 0x\(String(j, radix: 16))"
                                    )
                                }
                                blsFound += 1
                                if blsFound >= 2 { break }
                            }
                        }
                        count += blsFound
                        break
                    }
                }
            }
        }
        return count
    }

    private func patchAPFSVFSMountCMP() -> Int {
        let strOff = findString("apfs_mount_upgrade_checks\0")
        if strOff < 0 { return 0 }
        let strVa = macho?.foffToVa(strOff) ?? 0

        var count = 0
        data.withUnsafeMutableBytes { buffer in
            for i in stride(from: 0, to: buffer.count - 8, by: 4) {
                let i0 = buffer.load(fromByteOffset: i, as: UInt32.self)
                let i1 = buffer.load(fromByteOffset: i + 4, as: UInt32.self)
                if ARM64.isADRP(i0) && ARM64.isADDImm(i1) {
                    let va = macho?.foffToVa(i) ?? 0
                    let target =
                        ARM64.decodeADRP(insn: i0, address: va) + UInt64(ARM64.decodeADDImm(i1))
                    if target == strVa {
                        // Scan around for cmp x0, x8 (0xEB08001F)
                        for j in stride(
                            from: max(i - 0x1000, 0), to: min(i + 0x1000, buffer.count - 4), by: 4)
                        {
                            let insn = buffer.load(fromByteOffset: j, as: UInt32.self)
                            if insn == 0xEB08_001F {
                                buffer.storeBytes(
                                    of: UInt32(0xEB00_001F).littleEndian, toByteOffset: j,
                                    as: UInt32.self)
                                if verbose {
                                    print(
                                        "  [+] Kernel: Patched apfs_vfsop_mount cmp at 0x\(String(j, radix: 16))"
                                    )
                                }
                                count += 1
                                break
                            }
                        }
                        break
                    }
                }
            }
        }
        return count
    }

    private func patchSandboxHooks() -> Int {
        let seatbeltOff = findString("Seatbelt sandbox policy")
        let sandboxOff = findString("Sandbox")
        if seatbeltOff < 0 || sandboxOff < 0 { return 0 }

        var count = 0
        data.withUnsafeMutableBytes { buffer in
            for i in stride(from: 0, to: buffer.count - 40, by: 8) {
                let val0 = buffer.load(fromByteOffset: i, as: UInt64.self)
                let val1 = buffer.load(fromByteOffset: i + 8, as: UInt64.self)
                if (val0 & 0x7FF_FFFF_FFFF) == UInt64(sandboxOff)
                    && (val1 & 0x7FF_FFFF_FFFF) == UInt64(seatbeltOff)
                {
                    let opsVa = buffer.load(fromByteOffset: i + 32, as: UInt64.self)
                    let opsOff = Int(opsVa & 0xFFFF_FFFF)
                    if opsOff > 0 && opsOff < buffer.count {
                        let indices = [36, 87, 88, 91, 120]
                        for idx in indices {
                            let funcVa = buffer.load(
                                fromByteOffset: opsOff + idx * 8, as: UInt64.self)
                            let funcOff = Int(funcVa & 0xFFFF_FFFF)
                            if funcOff > 0 && funcOff < buffer.count {
                                buffer.storeBytes(
                                    of: ARM64.mov_x0_0.littleEndian, toByteOffset: funcOff,
                                    as: UInt32.self)
                                buffer.storeBytes(
                                    of: ARM64.ret.littleEndian, toByteOffset: funcOff + 4,
                                    as: UInt32.self)
                                if verbose {
                                    print(
                                        "  [+] Kernel: Stubbed sandbox hook at 0x\(String(funcOff, radix: 16))"
                                    )
                                }
                                count += 2
                            }
                        }
                    }
                    break
                }
            }
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
        case "kernel": patcher = KernelPatcher(data: workingData)
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
