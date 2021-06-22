#!/bin/bash

echo "===========[Mobibench test results]==================="
./reset 0 1 16 | grep TIME | awk '{print $1" "$7" "$8}'
