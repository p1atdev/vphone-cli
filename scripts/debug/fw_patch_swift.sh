#!/bin/bash

BIN="../../.build/release/vphone-cli"

cd ./VM/debug

rm -rf ./patched # clean up old patched files
cp -r ./backup ./patched

ls -l ./patched

echo "=== Patching firmware components (Swift) ==="

$BIN patch avpbooter patched/AVPBooter.vresearch1.bin
$BIN patch ibss patched/iBSS.vresearch101.RELEASE.im4p
$BIN patch ibec patched/iBEC.vresearch101.RELEASE.im4p
$BIN patch llb patched/LLB.vresearch101.RELEASE.im4p
$BIN patch txm patched/txm.iphoneos.research.im4p
$BIN patch kernel patched/kernelcache.research.vphone600

echo "=== All components patched successfully ==="
