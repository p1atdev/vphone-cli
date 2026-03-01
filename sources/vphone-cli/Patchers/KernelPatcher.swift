import Foundation

class KernelPatcher: Patcher {
    var data: Data
    private let verbose: Bool
    private var macho: MachO
    private var blCallers: [Int: [Int]] = [:]  // target_foff -> [caller_foff, ...]
    private var panicOff: Int = -1
    private var patchRecord: [(name: String, offset: Int, count: Int)] = []

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
        if verbose {
            PatchLog.summary(component: "KernelCache", patches: patchRecord)
        }
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
        if verbose {
            print("  [*] KernelPatcher: BL index built (\(blCallers.count) unique targets)")
            let totalBLs = blCallers.values.reduce(0) { $0 + $1.count }
            print("  [*] KernelPatcher: \(totalBLs) total BL instructions indexed")
        }
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
                    let va = macho.foffToVa(panicOff)
                    print(
                        "  [*] KernelPatcher: _panic at foff 0x\(String(panicOff, radix: 16)) (va 0x\(String(va, radix: 16)), \(callers.count) callers)"
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

    /// Decode any conditional branch at `off` to get target file offset.
    private func decodeCondBranchTarget(_ insn: UInt32, at off: Int) -> Int? {
        // B.cond
        if (insn & 0xFF00_0010) == 0x5400_0000 {
            let imm19 = (Int32(bitPattern: (insn >> 5) & 0x7FFFF) << 13) >> 13
            return off + Int(imm19) * 4
        }
        // CBZ / CBNZ
        if (insn & 0x7E00_0000) == 0x3400_0000 {
            let imm19 = (Int32(bitPattern: (insn >> 5) & 0x7FFFF) << 13) >> 13
            return off + Int(imm19) * 4
        }
        // TBZ / TBNZ
        if (insn & 0x7E00_0000) == 0x3600_0000 {
            let imm14 = (Int32(bitPattern: (insn >> 5) & 0x3FFF) << 18) >> 18
            return off + Int(imm14) * 4
        }
        return nil
    }

    private func emit(_ label: String, at off: Int, _ bytes: [UInt32]) -> Int {
        // Capture old instructions before patching
        var oldInsns: [UInt32] = []
        for i in 0..<bytes.count {
            let o = off + i * 4
            if o + 4 <= data.count {
                oldInsns.append(
                    data.withUnsafeBytes { $0.load(fromByteOffset: o, as: UInt32.self) })
            }
        }
        var count = 0
        for (i, v) in bytes.enumerated() {
            let o = off + i * 4
            let d = withUnsafeBytes(of: v.littleEndian) { Data($0) }
            data.replaceSubrange(o..<(o + 4), with: d)
            count += 1
        }
        if verbose {
            PatchLog.context(
                data: data, at: off, count: bytes.count,
                label: "Kernel: \(label)",
                old: oldInsns, new: bytes)
        }
        patchRecord.append((name: label, offset: off, count: count))
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
                let op = (insn >> 24) & 0xFE
                guard op == 0x36 || op == 0x37 else { continue }
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
            var blPanicOff = -1
            for scan in stride(from: addOff, to: min(addOff + 0x40, data.count - 4), by: 4) {
                let insn = data.withUnsafeBytes { $0.load(fromByteOffset: scan, as: UInt32.self) }
                if ARM64.isBL(insn) && ARM64.decodeBLTarget(insn: insn, foff: scan) == panicOff {
                    blPanicOff = scan
                    break
                }
            }
            if blPanicOff < 0 { continue }
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
        var bestOff = -1
        var bestCallers = 0
        for seg in macho.codeSegments {
            for off in stride(from: seg.start, to: seg.end - 24, by: 4) {
                let i0 = data.withUnsafeBytes { $0.load(fromByteOffset: off, as: UInt32.self) }
                guard ARM64.isADRP(i0) && (i0 & 0x1F) == 8 else { continue }
                guard off >= 4 else { continue }
                let prev = data.withUnsafeBytes {
                    $0.load(fromByteOffset: off - 4, as: UInt32.self)
                }
                guard ARM64.isFuncBoundary(prev) else { continue }
                var hasWLoad = false
                for k in 1...6 {
                    let kOff = off + k * 4
                    guard kOff + 4 <= data.count else { break }
                    let ki = data.withUnsafeBytes { $0.load(fromByteOffset: kOff, as: UInt32.self) }
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
                let isCMPW0imm = (i0 & 0xFFC0_03FF) == 0x7100_001F
                let isBNE = (i1 & 0xFF00_001F) == 0x5400_0001
                guard isCMPW0imm && isBNE else { continue }
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
            var blsWithCond: [(off: Int, target: Int)] = []
            for back in stride(from: adrpOff - 4, through: max(adrpOff - 80, 0), by: -4) {
                let insn = data.withUnsafeBytes { $0.load(fromByteOffset: back, as: UInt32.self) }
                guard ARM64.isBL(insn) else { continue }
                let blTarget = ARM64.decodeBLTarget(insn: insn, foff: back)
                let next = data.withUnsafeBytes {
                    $0.load(fromByteOffset: back + 4, as: UInt32.self)
                }
                let isCBZW0 =
                    (next & 0xFF00_001F) == 0x3400_0000 || (next & 0xFF00_001F) == 0x3500_0000
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
        let vrhFuncOff = findValidateRootHashFunc()
        if vrhFuncOff < 0 {
            if verbose { print("  [-] Kernel [12]: validate_on_disk_root_hash not found") }
            return 0
        }
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
        var callers = blCallers[funcStart, default: []]
        if callers.isEmpty {
            callers = blCallers[funcStart + 4, default: []]
        }
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
                guard (insn & 0xFF20_03FF) == 0xEB00_001F else { continue }
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
        let sandboxRaw = data.range(of: Data([0]) + "Sandbox".data(using: .utf8)! + Data([0]))
        guard let sandboxRange = sandboxRaw else {
            if verbose { print("  [-] Kernel [16-25]: \\0Sandbox\\0 not found") }
            return 0
        }
        let sandboxFoff = sandboxRange.lowerBound + 1

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

        let mask43 = UInt64(0x7FF_FFFF_FFFF)
        var opsTableOff = -1
        let dataSegs = macho.dataSegments
        outer: for (dStart, dEnd) in dataSegs {
            for i in stride(from: dStart, to: dEnd - 40, by: 8) {
                guard i + 40 <= data.count else { break }
                let val0 = data.withUnsafeBytes { $0.load(fromByteOffset: i, as: UInt64.self) }
                let val1 = data.withUnsafeBytes { $0.load(fromByteOffset: i + 8, as: UInt64.self) }
                guard (val0 & (1 << 63)) == 0 && (val1 & (1 << 63)) == 0 else { continue }
                guard (val0 & mask43) == UInt64(sandboxFoff) else { continue }
                guard (val1 & mask43) == UInt64(seatbeltFoff) else { continue }
                let opsVal = data.withUnsafeBytes {
                    $0.load(fromByteOffset: i + 32, as: UInt64.self)
                }
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

        let hookIndices = [36, 87, 88, 91, 120]
        var count = 0
        for idx in hookIndices {
            let entryOff = opsTableOff + idx * 8
            guard entryOff + 8 <= data.count else { continue }
            let funcVal = data.withUnsafeBytes {
                $0.load(fromByteOffset: entryOff, as: UInt64.self)
            }
            let funcOff: Int
            if (funcVal & (1 << 63)) != 0 {
                funcOff = Int(funcVal & 0xFFFF_FFFF)
            } else {
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
