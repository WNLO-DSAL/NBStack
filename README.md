# NBStack

## Run NBStack

### Prerequisites

Use FEMU to emulate an Open-Channel SSD for your QEMU virtual machine. We recommend FEMU commitID [783d4fb4ce46e0e10ef83d48046566cbba1e6b6d](https://github.com/ucare-uchicago/FEMU/commit/783d4fb4ce46e0e10ef83d48046566cbba1e6b6d).

### Linux Kernel version

Our implementation is based on Linux kernel 5.1.

### Download NBStack

```
git clone https://github.com/WNLO-DSAL/NBStack
```

### Tweaks for FEMU

Do the additional tweaks described in [https://github.com/ucare-uchicago/FEMU/wiki/FEMU-Best-Practice](https://github.com/ucare-uchicago/FEMU/wiki/FEMU-Best-Practice).

### Apply NBStack's kernel patch.

If your linux kernel source resides in `/usr/src/kernels/linux`, you can use our script to apply kernel patch.

```
cd NBStack
./patch_kernel.sh
```

Check out `patch_kernel.sh` for details.

### Build kernel

Here's [a nice article from kernelnewbies](https://kernelnewbies.org/KernelBuild) for buiding instructions.

Don't forget to enable lightNVM(`NVM=y`) and disable pblk(`NVM_PBLK=n`). After compilation, restart and login to the new kernel.

### Install nvme cli

```
cd ~
git clone https://github.com/linux-nvme/nvme-cli
cd nvme-cli
make
make install
```

### Build and launch qblk

```
cd /path/to/NBStack/src/qblk
make -j16
./install
# This will create a block device /dev/qblkdev
# Check out block devices
lsblk
```

### Format file system

The physical format of NBFS and F2FS are the same.
The following script works for both F2FS and NBFS.

```
cd /path/to/NBStack/src/qblk
./makef2fs
# This will format /dev/qblkdev as F2FS
```

### Build and mount F2FS/NBFS

```
cd /path/to/NBStack/src/nbfs
vim nbfs.h
```

Modify the `nbfs.h` to choose the file system we wan't to run.

* F2FS: Comment out `#define USE_NBFS`
* NBFS-L: `#define USE_NBFS` + `#define NBFS_DURABILITY_MODE (0)`
* NBFS-D: `#define USE_NBFS` + `#define NBFS_DURABILITY_MODE (1)`
* NBFS-U: `#define USE_NBFS` + `#define NBFS_ULTRAFAST_MODE`

```
make -j16
./install
./mountnbfs
# This will create a directory /mnt/qhw and mount /dev/qblkdev to /mnt/qhw
# Check out the mount:
mount | grep qhw
```

### Mobibench test

```
cd /path/to/NBStack
# Prepare for the tests
./preparetest.sh

cd scripts/lctes

# Push button tests
./mobibench.sh
```

### SQLite test (task running time)

```
cd /path/to/NBStack

# Prepare for the tests
./preparetest.sh

cd evaluations/2-TaskRunningTime

# Follow the instructions to test.
cat README.md
```

