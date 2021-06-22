#!/bin/bash

for (( i=0;i<$2;i++ ));
do
    dd if=/dev/zero of=$1/influence$i bs=4096 count=$3 > out${i}1 2>out${i}2 &
    pids1[${i}]=$!
done

for pid1 in ${pids1[*]}; do
    wait $pid1
done

