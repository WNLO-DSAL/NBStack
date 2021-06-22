#!/bin/bash

loadqblk()
{
	nbstack_root=`cat /tmp/nbstack/nbstack_root`
	if [ -z ${nbstack_root} ]; then
		echo "Please prepare test first."
		exit
	fi

	cd ${nbstack_root}
	cd src/qblk
	./install
	echo "Warming up device. This should take about 1 minute."
	fio warmup.fio &> /dev/null
	blkdiscard /dev/qblkdev
	sleep 2
	fio warmup.fio &> /dev/null
	blkdiscard /dev/qblkdev
	sleep 2
	echo "Done"
}

loaded=`lsmod | grep qblk | awk '{print $1}'`
if [ -n $loaded"" ]; then
	:
else
	loadqblk
fi
