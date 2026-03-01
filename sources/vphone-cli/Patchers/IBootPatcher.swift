import Foundation

class IBootPatcher: Patcher {
    var data: Data
    private let mode: String
    private let verbose: Bool
    private var patchRecord: [(name: String, offset: Int, count: Int)] = []

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
        if verbose {
            PatchLog.summary(component: "iBoot(\(mode))", patches: patchRecord)
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
                    print(
                        "  [+] iBoot (\(mode)): serial label at 0x\(String(writeOff, radix: 16)) → \"\(String(data: label, encoding: .utf8)!)\""
                    )
                }
                patchRecord.append((name: "serial label", offset: writeOff, count: 1))
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
        let oldBNE = data.withUnsafeBytes { $0.load(fromByteOffset: i, as: UInt32.self) }
        let oldMov = data.withUnsafeBytes { $0.load(fromByteOffset: i + 4, as: UInt32.self) }
        let nopData = withUnsafeBytes(of: ARM64.nop.littleEndian) { Data($0) }
        let movData = withUnsafeBytes(of: ARM64.mov_x0_0.littleEndian) { Data($0) }
        data.replaceSubrange(i..<(i + 4), with: nopData)
        data.replaceSubrange((i + 4)..<(i + 8), with: movData)
        if verbose {
            PatchLog.context(
                data: data, at: i, count: 2,
                label: "iBoot (\(mode)): image4 callback bypass",
                old: [oldBNE, oldMov], new: [ARM64.nop, ARM64.mov_x0_0])
        }
        patchRecord.append((name: "image4 callback (NOP b.ne + mov x0,#0)", offset: i, count: 2))
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
        let oldADRP = data.withUnsafeBytes { $0.load(fromByteOffset: adrpOff, as: UInt32.self) }
        let oldADD = data.withUnsafeBytes { $0.load(fromByteOffset: addOff, as: UInt32.self) }
        data.replaceSubrange(slotIdx..<(slotIdx + newArgs.count), with: newArgs)
        let newADRP = ARM64.encodeADRP(rd: 2, from: adrpOff, to: UInt64(slotIdx), baseVA: 0)
        let newADD = ARM64.encodeADDImm(rd: 2, rn: 2, imm: Int(UInt64(slotIdx) & 0xFFF))
        let adrpData = withUnsafeBytes(of: newADRP.littleEndian) { Data($0) }
        let addData = withUnsafeBytes(of: newADD.littleEndian) { Data($0) }
        data.replaceSubrange(adrpOff..<(adrpOff + 4), with: adrpData)
        data.replaceSubrange(addOff..<(addOff + 4), with: addData)
        if verbose {
            PatchLog.context(
                data: data, at: adrpOff, count: 2,
                label: "iBoot (\(mode)): boot-args → slot 0x\(String(slotIdx, radix: 16))",
                old: [oldADRP, oldADD], new: [newADRP, newADD])
            print("      boot-args: \"\(Self.bootArgs)\"")
        }
        patchRecord.append((name: "boot-args string", offset: slotIdx, count: 1))
        patchRecord.append((name: "boot-args ADRP+ADD redirect", offset: adrpOff, count: 2))
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
        if verbose {
            PatchLog.context(
                data: data, at: cbzOff, count: 1,
                label: "iBoot (\(mode)): \(desc)",
                old: [insn], new: [b])
        }
        patchRecord.append((name: desc, offset: cbzOff, count: 1))
        return 1
    }

    /// Find unique `CMP X8, #0x400`, NOP the following B.HS.
    private func patchBHSAfterCMP0x400() -> Int {
        // CMP X8, #0x400 = SUBS XZR, X8, #0x400
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
        if verbose {
            PatchLog.context(
                data: data, at: bhsOff, count: 1,
                label: "iBoot (\(mode)): rootfs NOP B.HS",
                old: [bhs], new: [ARM64.nop])
        }
        patchRecord.append((name: "rootfs NOP B.HS after CMP #0x400", offset: bhsOff, count: 1))
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
            let isLDR = ((i1 >> 22) & 0x3FF) == 0x3E5 && ((i1 >> 10) & 0xFFF) == 15
            guard isLDR else { continue }
            let rt = i1 & 0x1F
            // CBZ Xt (64-bit): 0xB4000000 | (imm19 << 5) | Rt
            let isCBZ = (i2 & 0xFF00_0000) == 0xB400_0000 && (i2 & 0x1F) == rt
            if isCBZ {
                let nopData = withUnsafeBytes(of: ARM64.nop.littleEndian) { Data($0) }
                data.replaceSubrange((scan + 4)..<(scan + 8), with: nopData)
                if verbose {
                    PatchLog.context(
                        data: data, at: scan + 4, count: 1,
                        label: "iBoot (\(mode)): rootfs NOP CBZ null check #0x78",
                        old: [i2], new: [ARM64.nop])
                }
                patchRecord.append(
                    (name: "rootfs NOP CBZ null check #0x78", offset: scan + 4, count: 1))
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
                        PatchLog.context(
                            data: data, at: step + 4, count: 1,
                            label: "iBoot (\(mode)): panic bypass NOP CBNZ",
                            old: [ni], new: [ARM64.nop])
                    }
                    patchRecord.append((name: "panic bypass NOP CBNZ", offset: step + 4, count: 1))
                    return 1
                }
                break
            }
        }
        if verbose { print("  [-] iBoot: panic bypass pattern not found") }
        return 0
    }
}
