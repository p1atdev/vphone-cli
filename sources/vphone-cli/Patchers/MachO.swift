import Foundation

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

// MARK: - Patcher Protocol

protocol Patcher {
    var data: Data { get set }
    func apply() throws -> Int
}
