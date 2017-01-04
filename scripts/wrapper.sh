#!/bin/bash

ws=$(pwd)
parser=${ws}"/parser.awk"

if [ $# -ne 1 ]; then
    echo "Please give me the route table file"
    exit 1
fi

rm -f ${ws}/*.dat

if [ -e "./delegated-apnic-latest" ]; then
    awk -f cn.awk delegated-apnic-latest > cn.dat
    cn="cn.dat"
fi

awk -f "${parser}" "${1}" > filtered.dat

./traceparse -filter cn.dat -data filtered.dat
