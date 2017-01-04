package main

import (
	"bufio"
	"bytes"
	"flag"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"traceparse/trace"
	"traceparse/trace/ip"
)

type (
	Dict             map[string]struct{}
	PartedTraceSlice map[string]trace.TraceList
)

var (
	cnFilterPath   string
	traceTablePath string

	void  = struct{}{}
	cares = map[string]struct{}{"24400": void, "4812": void, "17621": void, "4809": void}
)

func init() {
	flag.StringVar(&cnFilterPath, "filter", "", "This file should contain only CN node that we are interested in")
	flag.StringVar(&traceTablePath, "data", "", "This file should contain the pre-parsed data about the trace hop node")
	flag.Parse()
}

func main() {
	tl := new(trace.TraceList)
	dstDict := LoadDstDict()
	parted := NewPartedTraceSlice()
	tl.FromFile(traceTablePath, cares)
	for _, trace := range *tl {
		if _, ok := dstDict[trace[2]]; ok {
			parted[trace[1]] = append(parted[trace[1]], trace)
		}
	}

	for d, tracelist := range parted {
		export(BinaryMerge(&tracelist), d+".merged.dat")
	}
}

func NewPartedTraceSlice() PartedTraceSlice {
	pts := make(PartedTraceSlice)
	for c := range cares {
		pts[c] = make(trace.TraceList, 0, 1024)
	}
	return pts
}

func export(tl *trace.TraceList, name string) {
	output, err := os.Create(name)
	if err != nil {
		panic(err)
	}
	bo := bufio.NewWriter(output)
	for _, trace := range *tl {
		bo.WriteString(strings.Join(trace, "::") + "\n")
	}
	bo.Flush()
	output.Close()
}

//load destinations we care about
func LoadDstDict() Dict {
	filters, err := ioutil.ReadFile(cnFilterPath)
	if err != nil {
		panic(err)
	}
	filterArr := bytes.Split(filters, []byte("\n"))
	filterDict := make(Dict)
	for _, item := range filterArr {
		parts := bytes.Split(bytes.TrimRight(item, "\r"), []byte("|"))
		if string(parts[0]) == "apnic" && string(parts[1]) == "CN" && string(parts[2]) == "asn" {
			filterDict[string(parts[3])] = void
		}
	}
	return filterDict
}

func BinaryMerge(tl *trace.TraceList) *trace.TraceList {
	var hasDoneSomeMerge = false
	var workspace *trace.Trace
	var newTraceList = make(trace.TraceList, 0, len(*tl)) //every candidate will be moved here

	for i, l := 0, len(*tl); i < l; i++ {
		tps := (*tl)[i]
		if ip.CidrFromRange(tps[0]) == 0 {
			hasDoneSomeMerge = true //skip malformed ip range
			continue
		}
		if workspace == nil {
			workspace = &tps //popup workspace
			continue
		}

		rg1 := (*workspace)[0]
		rg2 := tps[0]
		cidr1 := ip.CidrFromRange(rg1)
		cidr2 := ip.CidrFromRange(rg2)
		superNetmask := ip.Cidr2uint(cidr1 - 1)
		ip1 := ip.IPFromRange((*workspace)[0])
		ip2 := ip.IPFromRange(tps[0])

		//ip1 is always <= ip2
		if ip1 == ip2 {
			if (*workspace)[2] == tps[2] {
				if cidr1 > cidr2 {
					workspace = &tps
				} else if cidr1 == cidr2 {
					// fmt.Printf("%v", (*tl)[i])
				}
				hasDoneSomeMerge = true
			} else {
				newTraceList = append(newTraceList, trace.Trace(*workspace))
				workspace = &tps
			}
			continue
		}

		if cidr1 != cidr2 {
			newTraceList = append(newTraceList, trace.Trace(*workspace))
			workspace = &tps
			continue
		}

		if ip.IsIPRangeAdjacent(rg1, rg2) &&
			ip.Ip2uint(ip1)&superNetmask == ip.Ip2uint(ip2)&superNetmask {
			newTraceList = append(newTraceList, trace.Trace{ip1 + "/" + strconv.FormatUint(uint64(cidr1-1), 10), tps[1], tps[2]}) //merge
			workspace = nil
			hasDoneSomeMerge = true
		} else {
			newTraceList = append(newTraceList, trace.Trace(*workspace))
			if i == l {
				newTraceList = append(newTraceList, (*tl)[i]) // the last one
			} else {
				workspace = &tps
			}
		}
	}

	if hasDoneSomeMerge {
		return BinaryMerge(&newTraceList)
	}

	return &newTraceList
}
