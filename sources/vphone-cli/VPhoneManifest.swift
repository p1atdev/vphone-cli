import Foundation

enum VPhoneManifest {
    typealias PlistDict = [String: Any]

    static func generate(iphoneDir: String, cloudosDir: String) throws {
        let iphoneURL = URL(fileURLWithPath: iphoneDir)
        let cloudosURL = URL(fileURLWithPath: cloudosDir)

        // 1. Load source plists
        let cloudosBM = try loadPlist(url: cloudosURL.appendingPathComponent("BuildManifest.plist"))
        let iphoneBM = try loadPlist(url: iphoneURL.appendingPathComponent("BuildManifest.plist"))
        let cloudosRP = try loadPlist(url: cloudosURL.appendingPathComponent("Restore.plist"))
        let iphoneRP = try loadPlist(url: iphoneURL.appendingPathComponent("Restore.plist"))

        guard let C = cloudosBM["BuildIdentities"] as? [PlistDict],
            let I = iphoneBM["BuildIdentities"] as? [PlistDict]
        else {
            throw NSError(
                domain: "VPhoneManifest", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Invalid BuildManifest format"])
        }

        // 2. Discover source identities
        // PROD / RES = vresearch101ap release / research (boot chain)
        // VP / VPR = vphone600ap release / research (runtime)
        let (prodIdx, resIdx) = try findCloudOS(identities: C, deviceClass: "vresearch101ap")
        let (vpIdx, vprIdx) = try findCloudOS(identities: C, deviceClass: "vphone600ap")
        let iEraseIdx = try findIPhoneErase(identities: I)

        print("  cloudOS vresearch101ap: release=#\(prodIdx), research=#\(resIdx)")
        print("  cloudOS vphone600ap:    release=#\(vpIdx), research=#\(vprIdx)")
        print("  iPhone  erase: #\(iEraseIdx)")

        // 3. Build the single DFU erase identity
        var bi = C[prodIdx]
        bi["Manifest"] = [String: Any]()
        bi["Ap,ProductType"] = "ComputeModule14,2"
        bi["Ap,Target"] = "VRESEARCH101AP"
        bi["Ap,TargetType"] = "vresearch101"
        bi["ApBoardID"] = "0x90"
        bi["ApChipID"] = "0xFE01"
        bi["ApSecurityDomain"] = "0x01"

        bi.removeValue(forKey: "NeRDEpoch")
        bi.removeValue(forKey: "RestoreAttestationMode")

        if var info = bi["Info"] as? PlistDict {
            info.removeValue(forKey: "NeRDEpoch")
            info.removeValue(forKey: "RestoreAttestationMode")
            info["FDRSupport"] = false
            info["Variant"] = "Darwin Cloud Customer Erase Install (IPSW)"
            info["VariantContents"] = [
                "BasebandFirmware": "Release",
                "DCP": "DarwinProduction",
                "DFU": "DarwinProduction",
                "Firmware": "DarwinProduction",
                "InitiumBaseband": "Production",
                "InstalledKernelCache": "Production",
                "InstalledSPTM": "Production",
                "OS": "Production",
                "RestoreKernelCache": "Production",
                "RestoreRamDisk": "Production",
                "RestoreSEP": "DarwinProduction",
                "RestoreSPTM": "Production",
                "SEP": "DarwinProduction",
                "VinylFirmware": "Release",
            ]
            bi["Info"] = info
        }

        guard var m = bi["Manifest"] as? [String: Any] else { return }

        // Helper to copy entry
        func entry(_ identities: [PlistDict], _ idx: Int, _ key: String) -> Any? {
            guard let manifest = identities[idx]["Manifest"] as? PlistDict else { return nil }
            return manifest[key]
        }

        // -- Boot chain (vresearch101 — matches DFU hardware) --
        m["LLB"] = entry(C, prodIdx, "LLB")
        m["iBSS"] = entry(C, prodIdx, "iBSS")
        m["iBEC"] = entry(C, prodIdx, "iBEC")
        m["iBoot"] = entry(C, resIdx, "iBoot")  // research iBoot

        // -- Security monitors (shared across board configs) --
        m["Ap,RestoreSecurePageTableMonitor"] = entry(
            C, prodIdx, "Ap,RestoreSecurePageTableMonitor")
        m["Ap,RestoreTrustedExecutionMonitor"] = entry(
            C, prodIdx, "Ap,RestoreTrustedExecutionMonitor")
        m["Ap,SecurePageTableMonitor"] = entry(C, prodIdx, "Ap,SecurePageTableMonitor")
        m["Ap,TrustedExecutionMonitor"] = entry(C, resIdx, "Ap,TrustedExecutionMonitor")

        // -- Device tree (vphone600ap — sets MKB dt=1 for keybag-less boot)
        m["DeviceTree"] = entry(C, vpIdx, "DeviceTree")
        m["RestoreDeviceTree"] = entry(C, vpIdx, "RestoreDeviceTree")

        // -- SEP (vphone600 — matches device tree) --
        m["SEP"] = entry(C, vpIdx, "SEP")
        m["RestoreSEP"] = entry(C, vpIdx, "RestoreSEP")

        // -- Kernel (vphone600, patched by fw_patch.py) --
        m["KernelCache"] = entry(C, vprIdx, "KernelCache")  // research
        m["RestoreKernelCache"] = entry(C, vpIdx, "RestoreKernelCache")  // release

        // -- Recovery mode (vphone600ap carries this entry) --
        m["RecoveryMode"] = entry(C, vpIdx, "RecoveryMode")

        // -- CloudOS erase ramdisk --
        m["RestoreRamDisk"] = entry(C, prodIdx, "RestoreRamDisk")
        m["RestoreTrustCache"] = entry(C, prodIdx, "RestoreTrustCache")

        // -- iPhone OS image --
        m["Ap,SystemVolumeCanonicalMetadata"] = entry(
            I, iEraseIdx, "Ap,SystemVolumeCanonicalMetadata")
        m["OS"] = entry(I, iEraseIdx, "OS")
        m["StaticTrustCache"] = entry(I, iEraseIdx, "StaticTrustCache")
        m["SystemVolume"] = entry(I, iEraseIdx, "SystemVolume")

        bi["Manifest"] = m

        // 4. Assemble BuildManifest
        let buildManifest: PlistDict = [
            "BuildIdentities": [bi],
            "ManifestVersion": cloudosBM["ManifestVersion"] ?? "",
            "ProductBuildVersion": cloudosBM["ProductBuildVersion"] ?? "",
            "ProductVersion": cloudosBM["ProductVersion"] ?? "",
            "SupportedProductTypes": ["iPhone99,11"],
        ]

        // 5. Assemble Restore.plist
        var restore: PlistDict = [
            "ProductBuildVersion": cloudosRP["ProductBuildVersion"] ?? "",
            "ProductVersion": cloudosRP["ProductVersion"] ?? "",
        ]

        if let iphoneMap = iphoneRP["DeviceMap"] as? [PlistDict],
            let cloudosMap = cloudosRP["DeviceMap"] as? [PlistDict]
        {
            var deviceMap = [iphoneMap[0]]
            deviceMap.append(
                contentsOf: cloudosMap.filter { d in
                    let board = d["BoardConfig"] as? String ?? ""
                    return board == "vphone600ap" || board == "vresearch101ap"
                })
            restore["DeviceMap"] = deviceMap
        }

        if let iphoneTypeIDs = iphoneRP["SupportedProductTypeIDs"] as? [String: [Any]],
           let cloudosTypeIDs = cloudosRP["SupportedProductTypeIDs"] as? [String: [Any]] {
            var typeIDs = [String: [Any]]()
            for cat in ["DFU", "Recovery"] {
                let iphoneList = iphoneTypeIDs[cat] ?? []
                let cloudosList = cloudosTypeIDs[cat] ?? []
                typeIDs[cat] = iphoneList + cloudosList
            }
            restore["SupportedProductTypeIDs"] = typeIDs
        }


        let iphoneTypes = iphoneRP["SupportedProductTypes"] as? [String] ?? []
        let cloudosTypes = cloudosRP["SupportedProductTypes"] as? [String] ?? []
        restore["SupportedProductTypes"] = iphoneTypes + cloudosTypes
        restore["SystemRestoreImageFileSystems"] = iphoneRP["SystemRestoreImageFileSystems"] ?? []

        // 6. Write output
        try savePlist(
            dict: buildManifest, url: iphoneURL.appendingPathComponent("BuildManifest.plist"))
        try savePlist(dict: restore, url: iphoneURL.appendingPathComponent("Restore.plist"))

        print("  wrote BuildManifest.plist")
        print("  wrote Restore.plist")
    }

    // MARK: - Helpers

    private static func loadPlist(url: URL) throws -> PlistDict {
        let data = try Data(contentsOf: url)
        guard
            let plist = try PropertyListSerialization.propertyList(
                from: data, options: [], format: nil) as? PlistDict
        else {
            throw NSError(
                domain: "VPhoneManifest", code: 2,
                userInfo: [NSLocalizedDescriptionKey: "Failed to parse plist at \(url.path)"])
        }
        return plist
    }

    private static func savePlist(dict: PlistDict, url: URL) throws {
        let data = try PropertyListSerialization.data(
            fromPropertyList: dict, format: .xml, options: 0)
        try data.write(to: url)
    }

    private static func isResearch(bi: PlistDict) -> Bool {
        let manifest = bi["Manifest"] as? PlistDict ?? [:]
        for comp in ["LLB", "iBSS", "iBEC"] {
            if let entry = manifest[comp] as? PlistDict,
                let info = entry["Info"] as? PlistDict,
                let path = info["Path"] as? String
            {
                let filename = (path as NSString).lastPathComponent
                let parts = filename.components(separatedBy: ".")
                if parts.count == 4 && parts[2].contains("RESEARCH") {
                    return true
                }
            }
        }
        let info = bi["Info"] as? PlistDict ?? [:]
        let variant = info["Variant"] as? String ?? ""
        return variant.lowercased().contains("research")
    }

    private static func findCloudOS(identities: [PlistDict], deviceClass: String) throws -> (
        release: Int, research: Int
    ) {
        var release: Int?
        var research: Int?

        for (i, bi) in identities.enumerated() {
            let info = bi["Info"] as? PlistDict ?? [:]
            let dc = info["DeviceClass"] as? String ?? ""
            if dc != deviceClass { continue }

            if isResearch(bi: bi) {
                if research == nil { research = i }
            } else {
                if release == nil { release = i }
            }
        }

        guard let rel = release, let res = research else {
            throw NSError(
                domain: "VPhoneManifest", code: 3,
                userInfo: [
                    NSLocalizedDescriptionKey: "No identities found for DeviceClass=\(deviceClass)"
                ])
        }
        return (rel, res)
    }

    private static func findIPhoneErase(identities: [PlistDict]) throws -> Int {
        for (i, bi) in identities.enumerated() {
            let info = bi["Info"] as? PlistDict ?? [:]
            let variant = (info["Variant"] as? String ?? "").lowercased()
            if !variant.contains("research") && !variant.contains("upgrade")
                && !variant.contains("recovery")
            {
                return i
            }
        }
        throw NSError(
            domain: "VPhoneManifest", code: 4,
            userInfo: [NSLocalizedDescriptionKey: "No erase identity found in iPhone manifest"])
    }
}
