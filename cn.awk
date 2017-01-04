#!/usr/bin/env awk

BEGIN {
    FS = "|"
}

$1 != "apnic" {
    next
}

$2 == "CN" && $3 == "asn" {
    print $4
}
