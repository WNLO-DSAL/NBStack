# SQLite Bench

A Benchmark Tool For SQLite3

## Prerequisites

Run `preparetest.sh` in the NBStack directory before doing anything else below.

## Compile Test Programs

```
./compile.sh
```

In case of errors, try upgrading gcc.

## Usage

Config:

`vim config`

Run QBLK and NBFS

`./WarmupAndInstall.sh`

Create databases and tables

`./prepareTest`

Run test

`./runTest`

Modify NBFS or the config file to change configurations.
Afterwards, we can simply type `./retest.sh` to automatically rebuild and run.
Use `./retest.sh n` for the nobarrier test.

For more info, please check the scripts.

## For Latency Tests

1. Enable qblk and nbfs to print time.

```
vim /path/to/NBStack/src/qblk/qblk.h
# uncomment `#define MONITOR_TIME`

vim /path/to/NBStack/src/nbfs/nbfs.h
# uncomment `#define MONITOR_TIME`
```

2. Modify WarmupAndInstall.sh to change OCSSD latency. (Uncomment the following line)

```
#nvme admin-passthru -d /dev/nvme0n1 --opcode=0xee cdw12=1600000 cdw13=1600000

```

3. Run tests:

```
./WarmupAndInstall.sh
./prepareTest
./runTest
./test3_collect.sh
```
