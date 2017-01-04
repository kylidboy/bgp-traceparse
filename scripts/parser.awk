#!/usr/bin/env awk

BEGIN {
    network=""
    nexthop=""
    port=0
    lastport=0
    ready_echo=0
    check_adjacent_first_port=0
    cares["24400"]=1
    cares["4812"]=1
    cares["4809"]=1
    cares["17621"]=1
}

function check_set_port(p) {
    if (p in cares) {
        port = p
        ready_echo = 1
    }
}

/^[^*[:space:]]/ {
    next
}

$1 == "*" && $2 ~ /[>^idsSh]/ && $3 ~ /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]+/ && $4 ~ /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ {
    network = $3
    nexthop = $4
    first_port = sprintf("%d", $NF)
    if (first_port == "58879") {
        next
    } else {
        first_port = sprintf("%d", $NF)
        check_set_port(first_port)
    }
}

$1 == "*" && $2 ~ /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ && $3 == "0" {
    cur = NF - 1
    while (cur > 0 && $cur != 0) {
        cur--
    }
    tar = cur + 1
    for (i = tar; i <= NF; i++) {
        first_port = sprintf("%d", $tar)
        if (first_port in cares) {
            check_set_port(first_port)
        } else {
            continue
        }
    }
    lp = sprintf("%d", $NF)
    if (lp != 0) {
        lastport = lp
    }
}

/^[[:space:]]/ {
    fp = ""
    lp = sprintf("%d", $NF)
    for(i = 1; i <= NF; i++) {
        fp = sprintf("%d", $i)
        if (fp in cares) {
            check_set_port(fp)
        } else {
            continue
        }
    }
    if (lp != 0) {
        lastport = lp
    }
}

/(\?|i)$/ {
    if (ready_echo == 1) {
        print network"::"port"::"lastport
        ready_echo = 0
    }
}

