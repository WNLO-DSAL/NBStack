#!/bin/bash


#nvme admin-passthru -d /dev/nvme0n1 --opcode=0xee cdw12=1600000 cdw13=1600000

# Warm up device
sleep 1
echo "Installing qblk"
nbstackroot=`cat /tmp/nbstack/nbstack_root`
cd ${nbstackroot}/src/qblk
./install 
echo "Warming device"
dd if=/dev/zero of=/dev/qblkdev bs=4k count=8192
sync
blkdiscard /dev/qblkdev
dd if=/dev/zero of=/dev/qblkdev bs=4k count=8192
sync
echo "End of warming"
blkdiscard /dev/qblkdev
sleep 5
dmesg -c > /dev/null
sleep 5

# Prepare test
echo "Preparing nbfs test"
./makef2fs 
cd ../nbfs
./install 
./mountnbfs 
echo "Done."
