#!/bin/bash

nbstack_root=`cat /tmp/nbstack/nbstack_root`
if [ -z ${nbstack_root} ]; then
	echo "Please prepare test first."
	exit
fi

cd ${nbstack_root}

cd src/nbfs

sed -e 's|^#define USE_NBFS|//#define USE_NBFS|g' -i nbfs.h
sed -e 's|^#define NBFS_ULTRAFAST_MODE|//#define NBFS_ULTRAFAST_MODE|g' -i nbfs.h
sed -e 's|^#define NBFS_DURABILITY_MODE (1)|#define NBFS_DURABILITY_MODE (0)|g' -i nbfs.h
sed -e 's|^//#define NBFS_NOMERGE_HINT_FOR_DATABIO|#define NBFS_NOMERGE_HINT_FOR_DATABIO|g' -i nbfs.h
sed -e 's|^#define MONITOR_TIME|//#define MONITOR_TIME|g' -i nbfs.h

make -j16 
