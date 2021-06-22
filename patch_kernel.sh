#!/bin/bash

path="kernel_patch"
kernelSource=/usr/src/kernels/linux
files=`ls $path`

for filename in $files
do
	echo cp -r ${path}/${filename} ${kernelSource}/
	yes | cp -r ${path}/${filename} ${kernelSource}/ 2>/dev/null
done

echo "Patch kernel done!"
