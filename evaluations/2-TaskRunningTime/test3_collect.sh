#!/bin/bash

dmesg > dmesgout
awk '{print $3"\t"$5"\t"$7"\t"$9}' dmesgout
