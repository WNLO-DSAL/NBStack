#!/bin/bash


savedpwd=""

myexec()
{
	if [ $2"" == "verbose" ]; then
		$1
	else
		$1 &>/dev/null
	fi
}

testscheme()
{
	echo ""
	echo ">>>>>>>>>>>>>>>>[Scheme="$1"]<<<<<<<<<<<<<<<<<<<"
	myexec "./scripts/change_to_${1}.sh" ${REDIRECT}
	cd evaluations/1-MobibenchTest/shell
	echo "----------------Strong Durability Guarantees------------------"
	yes | cp Makefile.fsync Makefile
	myexec "make -j16" ${REDIRECT}
	./lctes_test.sh
	echo "----------------Relaxed Durability Guarantees------------------"
	yes | cp Makefile.fdatasync Makefile
	myexec "make -j16" ${REDIRECT}
	./lctes_test.sh
	cd $savedpwd
}

# Change to nbstack root directory
nbstack_root=`cat /tmp/nbstack/nbstack_root`
if [ -z ${nbstack_root} ]; then
	echo "Please prepare test first."
	exit
fi

cd ${nbstack_root}

savedpwd=`pwd`

REDIRECT=$1

# Load qblk if needed
./scripts/loadqblkifneeded.sh

# Run tests
for scheme in f2fs nbfs_l nbfs_d nbfs_u
do
	testscheme $scheme
done
