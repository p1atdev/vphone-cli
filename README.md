# vphone-cli

Apple's Private Cloud Compute provides virtual machines for security research, including VM configurations capable of booting an iOS/iPhone environment.

The VM system uses a dedicated PCC image. After modifying the boot firmware and LLB/iBSS/Kernel, it can load an iOS 26 virtual machine.

![poc](./demo.png)

## Prepare Development Environment

> **Note:** Disabling SIP is not for modifying the system. `Virtualization.framework` checks our binary's entitlements before allowing the launch of a specially configured VM. We need to disable SIP to modify boot arguments and disable AMFI checks.

### Reboot into Recovery Mode

On Apple Silicon, long press the power button until "Loading boot options" appears. In recovery mode, open Terminal from the Tools menu:

```bash
csrutil disable
csrutil allow-research-guests enable
```

Restart into normal macOS.

### Reboot into System

```bash
sudo nvram boot-args="amfi_get_out_of_my_way=1 -v"
```

Restart again.

### Compile libimobiledevice Suite

> Shoutout to [nikias](https://github.com/nikias) for the original all-in-one script!

```bash
make setup_libimobiledevice
```

### Set Up Python Environment

```bash
make setup_venv
source .venv/bin/activate
```

## Prepare Resource Files

### Enable Research Environment VM Resource Control

```bash
sudo /System/Library/SecurityResearch/usr/bin/pccvre
cd /System/Library/SecurityResearch/usr/bin/
./pccvre release list
./pccvre release download --release 35622
./pccvre instance create -N pcc-research -R 35622 --variant research
```

### Obtain Resource Files

Prepare the PCC VM environment. We use this virtual machine as a template, overwriting the boot firmware (removing signature checks) to load customized LLB/iBoot for recovery.

- `~/Library/Application\ Support/com.apple.security-research.vrevm/VM-Library/pcc-research.vm`

### Download Firmware

The hybrid firmware uses two IPSWs:

- [iPhone17,3_26.1_23B85_Restore.ipsw](https://updates.cdn-apple.com/2025FallFCS/fullrestores/089-13864/668EFC0E-5911-454C-96C6-E1063CB80042/iPhone17,3_26.1_23B85_Restore.ipsw)
- [PCC cloudOS IPSW](https://updates.cdn-apple.com/private-cloud-compute/399b664dd623358c3de118ffc114e42dcd51c9309e751d43bc949b98f4e31349)

These are downloaded automatically by `make fw_prepare`.

## Build and Create VM

```bash
make build
make vm_new
```

## Prepare and Patch Firmware

```bash
make fw_prepare    # Download IPSWs, extract, merge, generate hybrid manifest
make fw_patch      # Patch 6 boot-chain components (41+ modifications)
```

The patch system covers **41+ modifications** across 6 components:

```
1. AVPBooter     — DGST validation bypass
2. iBSS          — serial labels + image4 callback bypass
3. iBEC          — serial labels + image4 callback + boot-args
4. LLB           — serial labels + image4 callback + boot-args + rootfs + panic
5. TXM           — trustcache bypass
6. kernelcache   — 25 patches (APFS, MAC hooks, debugger, launch constraints)
```

### Verify Patch Status

```bash
make boot_dfu
```

Confirm the Chip ID in System Information — look for `CPID:FE01`.

## Restore Modified Firmware to VM

### Get SHSH

```bash
make restore_get_shsh
```

> If you encounter a rejection for an unknown board model, make sure `make fw_prepare` was run first.

### Restore

```bash
make restore
```

## Boot to Ramdisk

```bash
make ramdisk_build
```

Send the ramdisk to the device (VM must be in DFU mode):

```bash
make boot_dfu      # in one terminal
make ramdisk_send  # in another terminal
```

The serial console should show the SSH ramdisk booting. Connect via:

```bash
iproxy 2222 22
ssh root@127.0.0.1 -p2222   # password: alpine
```

### Patch Boot Disk

In the SSH session, rename the APFS snapshot:

```bash
mount_apfs -o rw /dev/disk1s1 /mnt1
snaputil -n $(snaputil -l /mnt1) orig-fs /mnt1
umount /mnt1
```

### Install CFW

```bash
make cfw_install
```

This installs Cryptexes, patches system binaries (seputil, launchd_cache_loader, mobileactivationd), installs jailbreak tools, and configures LaunchDaemons.

Then SSH in and halt:

```bash
ssh root@127.0.0.1 -p2222
halt
```

## First Boot

```bash
make boot
```

After entering bash, initialize the shell environment:

```bash
export PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/bin/X11:/usr/games:/iosbinpack64/usr/local/sbin:/iosbinpack64/usr/local/bin:/iosbinpack64/usr/sbin:/iosbinpack64/usr/bin:/iosbinpack64/sbin:/iosbinpack64/bin'

/iosbinpack64/bin/mkdir -p /var/dropbear
/iosbinpack64/bin/cp /iosbinpack64/etc/profile /var/profile
/iosbinpack64/bin/cp /iosbinpack64/etc/motd /var/motd

shutdown -h now
```

To connect to the virtual machine after boot:

```bash
iproxy 5901 5901
iproxy 22222 22222
```

## Appendix

### Boot PCC VM

```bash
pccvre release download --release 35622
pccvre instance create -N pcc-research -R 35622 --variant research
```

- <https://appledb.dev/firmware/cloudOS/23B85.html>
- <https://updates.cdn-apple.com/private-cloud-compute/399b664dd623358c3de118ffc114e42dcd51c9309e751d43bc949b98f4e31349>

```bash
vrevm restore -d -f --name pcc-research \
    -K ~/Desktop/kernelcache.research.vresearch101 \
    -S ~/Desktop/Firmware/sptm.vresearch1.release.im4p \
    -M ~/Desktop/Firmware/txm.iphoneos.research.im4p \
    --variant-name "Research Darwin Cloud Customer Erase Install (IPSW)" \
    ~/Desktop/PCC-CloudOS-26.1-23B85.ipsw
```

## Acknowledgements

- [wh1te4ever/super-tart-vphone-writeup](https://github.com/wh1te4ever/super-tart-vphone-writeup)
