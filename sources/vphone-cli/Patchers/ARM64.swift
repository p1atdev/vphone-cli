import Foundation

// MARK: - ARM64 Instruction Constants & Helpers

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

    // MARK: - Lightweight Disassembler

    /// Register name for a 5-bit register field.
    private static func regName(_ reg: UInt32, w: Bool = false) -> String {
        if reg == 31 { return w ? "wzr" : "xzr" }
        return "\(w ? "w" : "x")\(reg)"
    }

    /// Disassemble a single ARM64 instruction to a human-readable string.
    /// Covers all instruction types used in patching; falls back to hex for unknown encodings.
    static func disassemble(_ insn: UInt32, at pc: Int = 0) -> String {
        // NOP
        if insn == nop { return "nop" }
        // RET variants
        if insn == ret { return "ret" }
        if insn == retaa { return "retaa" }
        if insn == retab { return "retab" }
        // PAC hints
        if insn == paciasp { return "paciasp" }
        if insn == pacibsp { return "pacibsp" }
        // BTI
        if insn == 0xD503_245F { return "bti c" }

        // MOVZ / MOVN / MOVK (W and X)
        // MOVZ: sf=X, opc=10, 100101
        if (insn & 0x7F80_0000) == 0x5280_0000 {
            let sf = (insn >> 31) & 1
            let hw = (insn >> 21) & 0x3
            let imm16 = (insn >> 5) & 0xFFFF
            let rd = insn & 0x1F
            let shift = hw * 16
            let rn = regName(rd, w: sf == 0)
            if shift == 0 {
                return "mov \(rn), #0x\(String(imm16, radix: 16))"
            }
            return "movz \(rn), #0x\(String(imm16, radix: 16)), lsl #\(shift)"
        }

        // MOVN: sf=X, opc=00, 100101
        if (insn & 0x7F80_0000) == 0x1280_0000 {
            let sf = (insn >> 31) & 1
            let hw = (insn >> 21) & 0x3
            let imm16 = (insn >> 5) & 0xFFFF
            let rd = insn & 0x1F
            let shift = hw * 16
            let rn = regName(rd, w: sf == 0)
            return "movn \(rn), #0x\(String(imm16, radix: 16))\(shift > 0 ? ", lsl #\(shift)" : "")"
        }

        // MOVK: sf=X, opc=11, 100101
        if (insn & 0x7F80_0000) == 0x7280_0000 {
            let sf = (insn >> 31) & 1
            let hw = (insn >> 21) & 0x3
            let imm16 = (insn >> 5) & 0xFFFF
            let rd = insn & 0x1F
            let shift = hw * 16
            let rn = regName(rd, w: sf == 0)
            return "movk \(rn), #0x\(String(imm16, radix: 16))\(shift > 0 ? ", lsl #\(shift)" : "")"
        }

        // MOV (register) = ORR Rd, XZR, Rm
        if (insn & 0x7FE0_FFE0) == 0x2A00_03E0 {
            let sf = (insn >> 31) & 1
            let rd = insn & 0x1F
            let rm = (insn >> 16) & 0x1F
            return "mov \(regName(rd, w: sf == 0)), \(regName(rm, w: sf == 0))"
        }

        // BL
        if (insn & 0xFC00_0000) == 0x9400_0000 {
            let target = decodeBLTarget(insn: insn, foff: pc)
            return "bl #0x\(String(target, radix: 16))"
        }

        // B (unconditional)
        if (insn & 0xFC00_0000) == 0x1400_0000 {
            var imm26 = Int32(insn & 0x3FF_FFFF)
            if (imm26 & (1 << 25)) != 0 { imm26 -= (1 << 26) }
            let target = pc + Int(imm26) * 4
            return "b #0x\(String(target, radix: 16))"
        }

        // B.cond
        if (insn & 0xFF00_0010) == 0x5400_0000 {
            let cond = insn & 0xF
            let condNames = [
                "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le",
                "al", "nv",
            ]
            let imm19 = (Int32(bitPattern: (insn >> 5) & 0x7FFFF) << 13) >> 13
            let target = pc + Int(imm19) * 4
            return "b.\(condNames[Int(cond)]) #0x\(String(target, radix: 16))"
        }

        // CBZ / CBNZ
        if (insn & 0x7E00_0000) == 0x3400_0000 {
            let sf = (insn >> 31) & 1
            let op = (insn >> 24) & 1  // 0=cbz, 1=cbnz
            let rt = insn & 0x1F
            let imm19 = (Int32(bitPattern: (insn >> 5) & 0x7FFFF) << 13) >> 13
            let target = pc + Int(imm19) * 4
            return
                "\(op == 0 ? "cbz" : "cbnz") \(regName(rt, w: sf == 0)), #0x\(String(target, radix: 16))"
        }

        // TBZ / TBNZ
        if (insn & 0x7E00_0000) == 0x3600_0000 {
            let op = (insn >> 24) & 1  // 0=tbz, 1=tbnz
            let b5 = (insn >> 31) & 1
            let b40 = (insn >> 19) & 0x1F
            let bitNum = (b5 << 5) | b40
            let rt = insn & 0x1F
            let imm14 = (Int32(bitPattern: (insn >> 5) & 0x3FFF) << 18) >> 18
            let target = pc + Int(imm14) * 4
            let w = bitNum < 32
            return
                "\(op == 0 ? "tbz" : "tbnz") \(regName(rt, w: w)), #\(bitNum), #0x\(String(target, radix: 16))"
        }

        // ADRP
        if isADRP(insn) {
            let rd = insn & 0x1F
            // Show raw without baseVA for brevity
            let page = decodeADRP(insn: insn, foff: pc, baseVA: 0)
            return "adrp \(regName(rd)), #0x\(String(page, radix: 16))"
        }

        // ADD (immediate, 64-bit)
        if isADDImm(insn) {
            let rd = insn & 0x1F
            let rn = (insn >> 5) & 0x1F
            let imm = decodeADDImm(insn)
            return "add \(regName(rd)), \(regName(rn)), #0x\(String(imm, radix: 16))"
        }

        // SUB (immediate, 64-bit) = 0xD1000000
        if (insn & 0xFF00_0000) == 0xD100_0000 {
            let rd = insn & 0x1F
            let rn = (insn >> 5) & 0x1F
            let imm12 = (insn >> 10) & 0xFFF
            return "sub \(regName(rd)), \(regName(rn)), #0x\(String(imm12, radix: 16))"
        }

        // CMP (register, 64-bit) = SUBS XZR, Xn, Xm
        if (insn & 0xFF20_03FF) == 0xEB00_001F {
            let rn = (insn >> 5) & 0x1F
            let rm = (insn >> 16) & 0x1F
            return "cmp \(regName(rn)), \(regName(rm))"
        }

        // CMP (register, 32-bit) = SUBS WZR, Wn, Wm
        if (insn & 0xFF20_03FF) == 0x6B00_001F {
            let rn = (insn >> 5) & 0x1F
            let rm = (insn >> 16) & 0x1F
            return "cmp \(regName(rn, w: true)), \(regName(rm, w: true))"
        }

        // CMP (immediate, 64-bit) = SUBS XZR, Xn, #imm
        if (insn & 0xFFC0_001F) == 0xF100_001F {
            let rn = (insn >> 5) & 0x1F
            let imm12 = (insn >> 10) & 0xFFF
            return "cmp \(regName(rn)), #0x\(String(imm12, radix: 16))"
        }

        // CMP (immediate, 32-bit) = SUBS WZR, Wn, #imm
        if (insn & 0xFFC0_03FF) == 0x7100_001F {
            let rn = (insn >> 5) & 0x1F
            let imm12 = (insn >> 10) & 0xFFF
            return "cmp \(regName(rn, w: true)), #\(imm12)"
        }

        // STP (pre-index / signed offset) for X registers
        if (insn & 0x7FC0_0000) == 0xA900_0000 || (insn & 0x7FC0_0000) == 0xA980_0000 {
            let rt = insn & 0x1F
            let rn = (insn >> 5) & 0x1F
            let rt2 = (insn >> 10) & 0x1F
            let imm7 = Int32(bitPattern: (insn >> 15) & 0x7F)
            let signedImm = ((imm7 << 25) >> 25) * 8
            let sf = (insn >> 31) & 1
            let preIdx = ((insn >> 23) & 1) == 1
            let rnName = rn == 31 ? "sp" : regName(rn, w: sf == 0)
            if preIdx {
                return
                    "stp \(regName(rt, w: sf == 0)), \(regName(rt2, w: sf == 0)), [\(rnName), #\(signedImm)]!"
            }
            return
                "stp \(regName(rt, w: sf == 0)), \(regName(rt2, w: sf == 0)), [\(rnName), #\(signedImm)]"
        }

        // LDP (post-index / signed offset) for X registers
        if (insn & 0x7FC0_0000) == 0xA940_0000 || (insn & 0x7FC0_0000) == 0xA8C0_0000 {
            let rt = insn & 0x1F
            let rn = (insn >> 5) & 0x1F
            let rt2 = (insn >> 10) & 0x1F
            let imm7 = Int32(bitPattern: (insn >> 15) & 0x7F)
            let signedImm = ((imm7 << 25) >> 25) * 8
            let sf = (insn >> 31) & 1
            let postIdx = ((insn >> 23) & 1) == 1
            let rnName = rn == 31 ? "sp" : regName(rn, w: sf == 0)
            if postIdx {
                return
                    "ldp \(regName(rt, w: sf == 0)), \(regName(rt2, w: sf == 0)), [\(rnName)], #\(signedImm)"
            }
            return
                "ldp \(regName(rt, w: sf == 0)), \(regName(rt2, w: sf == 0)), [\(rnName), #\(signedImm)]"
        }

        // LDR (unsigned offset, 64-bit) = 0xF9400000
        if (insn & 0xFFC0_0000) == 0xF940_0000 {
            let rt = insn & 0x1F
            let rn = (insn >> 5) & 0x1F
            let imm12 = ((insn >> 10) & 0xFFF) * 8
            let rnName = rn == 31 ? "sp" : regName(rn)
            return "ldr \(regName(rt)), [\(rnName), #0x\(String(imm12, radix: 16))]"
        }

        // LDR (unsigned offset, 32-bit) = 0xB9400000
        if (insn & 0xFFC0_0000) == 0xB940_0000 {
            let rt = insn & 0x1F
            let rn = (insn >> 5) & 0x1F
            let imm12 = ((insn >> 10) & 0xFFF) * 4
            let rnName = rn == 31 ? "sp" : regName(rn)
            return "ldr \(regName(rt, w: true)), [\(rnName), #0x\(String(imm12, radix: 16))]"
        }

        // LDRB (unsigned offset) = 0x39400000
        if (insn & 0xFFC0_0000) == 0x3940_0000 {
            let rt = insn & 0x1F
            let rn = (insn >> 5) & 0x1F
            let imm12 = (insn >> 10) & 0xFFF
            let rnName = rn == 31 ? "sp" : regName(rn)
            return "ldrb \(regName(rt, w: true)), [\(rnName), #0x\(String(imm12, radix: 16))]"
        }

        // BRK
        if (insn & 0xFFE0_0000) == 0xD420_0000 {
            let imm16 = (insn >> 5) & 0xFFFF
            return "brk #0x\(String(imm16, radix: 16))"
        }

        // BLRAA / BLRAB (PAC branch)
        if insn == 0xD63F_0BFF { return "blraaz" }
        if (insn & 0xFFFF_FC00) == 0xD73F_0800 {
            let rn = (insn >> 5) & 0x1F
            let rm = insn & 0x1F
            return "blraa \(regName(rn)), \(regName(rm))"
        }

        // Fallback: hex
        return String(format: ".inst 0x%08x", insn)
    }

    /// Format a hex dump of raw bytes (4 bytes, little-endian display matching objdump style).
    static func hexBytes(_ insn: UInt32) -> String {
        let b0 = UInt8(insn & 0xFF)
        let b1 = UInt8((insn >> 8) & 0xFF)
        let b2 = UInt8((insn >> 16) & 0xFF)
        let b3 = UInt8((insn >> 24) & 0xFF)
        return String(format: "%02x %02x %02x %02x", b0, b1, b2, b3)
    }
}
