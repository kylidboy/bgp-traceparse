package ip

import (
	"math"
	"strconv"
	"strings"
)

func IsIPRangeAdjacent(rg1, rg2 string) bool {
	cidr := CidrFromRange(rg1)
	ip1 := IPFromRange(rg1)
	ip2 := IPFromRange(rg2)
	return Ip2uint(ip1)+uint32(math.Pow(2, float64(32-cidr))) == Ip2uint(ip2)
}

//Ip2uint transform IPv4 string to uint32/binary
func Ip2uint(s string) uint32 {
	var ip32 uint32
	masterSegs := strings.Split(s, ".")
	for len(masterSegs) < 4 {
		masterSegs = append(masterSegs, "0")
	}
	for _, seg := range masterSegs {
		t, _ := strconv.ParseUint(seg, 10, 8)
		ip32 = ip32<<8 + uint32(t)
	}
	return ip32
}

//Cidr2uint transform a cidr to netmask
func Cidr2uint(c uint32) uint32 {
	return uint32(math.Pow(2, float64(c))-1) << (32 - c)
}

//IPFromRange get the dot-separate ip address
func IPFromRange(ip string) string {
	return strings.Split(ip, "/")[0]
}

//CidrFromRage get the cidr from ip range
func CidrFromRange(ip string) uint32 {
	p := strings.Split(ip, "/")
	r := "0"
	if len(p) == 2 {
		r = p[1]
	}
	res, _ := strconv.ParseUint(r, 10, 32)
	return uint32(res)
}
