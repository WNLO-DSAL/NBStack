#!/bin/bash

__RED='\033[0;31m'
__NC='\033[0m' # No Color

echo -e "${__RED}====================="

echo "Number of jobs: "$njob
echo "Number of rows per job: "$nrows
echo "Record size: "$datasize
echo "Sync mode: "$syncmode

echo -e "=====================${__NC}"
