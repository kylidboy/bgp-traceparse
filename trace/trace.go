package trace

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"traceparse/trace/ip"
)

type (
	Trace     []string
	TraceList []Trace

	TraceParser struct {
		IP          string
		Src         string
		Dst         string
		IsDrop      bool
		IsSkip58879 bool
		Cares       map[string]struct{}
	}
)

var (
	reSeptr        = regexp.MustCompile("\\s+")
	rePort         = regexp.MustCompile("[0-9]+(i|\\?)?$")
	reIP           = regexp.MustCompile("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}")
	reParseIllegal = regexp.MustCompile("0\\.0\\.0\\.0")
)

func (tl TraceList) Len() int {
	return len(tl)
}

func (tl TraceList) Swap(i, j int) {
	tl[i], tl[j] = tl[j], tl[i]
}

func (tl TraceList) Less(i, j int) bool {
	inm := ip.CidrFromRange(tl[i][0])
	jnm := ip.CidrFromRange(tl[j][0])
	iu := ip.Ip2uint(ip.IPFromRange(tl[i][0]))
	ju := ip.Ip2uint(ip.IPFromRange(tl[j][0]))
	return iu < ju || (iu == ju && inm < jnm)
}

func (tl *TraceList) FromFile(path string, cares map[string]struct{}) error {
	par := TraceParser{}
	if cares != nil {
		par.Cares = cares
	}
	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fh.Close()
	rd := bufio.NewReader(fh)
	for {
		l, err := rd.ReadString('\n')
		if l == "" && err != nil {
			break
		}
		if tl.FromLine(l, &par) {
			*tl = append(*tl, Trace{par.IP, par.Src, par.Dst})
		}
	}
	return nil
}

func (tl *TraceList) FromLine(l string, p *TraceParser) bool {
	if reParseIllegal.MatchString(l) {
		return false
	}
	sl := strings.Trim(l, "\r\n \t")
	fields := reSeptr.Split(sl, -1)
	_ = p.ParseFreshStart(fields) || p.ParseHopStart(fields) || p.ParseHopPoint(fields)
	if !p.CheckEndpoint(fields) || p.IsDrop {
		return false
	}
	return true
}

func (p *TraceParser) ResetState() {
	p.IsDrop = false
	p.IsSkip58879 = false
}

func (p *TraceParser) ResetPath() {
	p.Src = ""
	p.Dst = ""
}

func (p *TraceParser) ParseFreshStart(t []string) bool {
	if !p.isFreshStart(t) {
		return false
	}
	p.ResetState()
	p.ResetPath()
	p.IP = ""

	if reIP.MatchString(t[1]) {
		p.IP = t[1]
	} else if reIP.MatchString(t[2]) {
		p.IP = t[2]
	} else {
		fmt.Println("some start point un-handlable:", strings.Join(t, ","))
	}
	sCursor := len(t) - 1
	peek := sCursor - 1
	for sCursor > 0 {
		if !rePort.MatchString(t[peek]) || t[peek] == "0" {
			break
		}
		sCursor--
		peek--
	}
	startPort := p.GetNeatPort(t[sCursor])
	if _, ok := p.Cares[startPort]; ok {
		p.Src, p.Dst = startPort, startPort
	} else if startPort == "58879" {
		if len(t)-1 == sCursor {
			p.IsSkip58879 = true
		} else {
			p.Src, p.Dst = t[sCursor+1], t[sCursor+1]
		}
	} else {
		p.IsDrop = true
	}

	return true
}

//ParseHopStart parse hop points with an IPv4
func (p *TraceParser) ParseHopStart(t []string) bool {
	if !p.isHopStart(t) {
		return false
	}
	p.ResetState()
	i := len(t) - 1
	for ; i >= 0; i-- {
		if t[i] == "0" || !rePort.MatchString(t[i]) {
			break
		}
	}
	i++
	maybeSrc := p.GetNeatPort(t[i])
	if _, ok := p.Cares[maybeSrc]; ok {
		p.Src, p.Dst = maybeSrc, p.GetNeatPort(t[len(t)-1])
	} else {
		p.IsDrop = true
	}

	return true
}

//mere hop points
func (p *TraceParser) ParseHopPoint(t []string) bool {
	if !p.isHopPoint(t) || p.IsDrop {
		return false
	}
	fst := p.GetNeatPort(t[0])
	lst := p.GetNeatPort(t[len(t)-1])
	_, isCare := p.Cares[fst]
	if p.IsSkip58879 {
		if isCare {
			p.Src, p.Dst = fst, lst
		} else {
			p.IsDrop = true
		}
		p.IsSkip58879 = false
	}
	p.Dst = lst

	return true
}

//CheckEndpoint whether current line contains an end mark
func (p *TraceParser) CheckEndpoint(t []string) bool {
	endOfRow := t[len(t)-1]
	if strings.HasSuffix(endOfRow, "i") || strings.HasSuffix(endOfRow, "?") {
		_dst := strings.TrimRight(endOfRow, "i?")
		if _dst != "" {
			p.Dst = _dst
		}
		if p.IsSkip58879 {
			p.IsDrop = true
		}
		return true
	}
	return false
}

func (p *TraceParser) GetNeatPort(port string) string {
	return strings.TrimRight(port, "?i\r\n")
}

func (p *TraceParser) isFreshStart(t []string) bool {
	return len(t) > 4 && t[0] == "*" &&
		((reIP.MatchString(t[2]) && reIP.MatchString(t[3])) ||
			(reIP.MatchString(t[1]) && reIP.MatchString(t[2])))
}

func (p *TraceParser) isHopStart(t []string) bool {
	return len(t) > 2 && t[0] == "*" && reIP.MatchString(t[1])
}

func (p *TraceParser) isHopPoint(t []string) bool {
	for _, f := range t {
		if !rePort.MatchString(f) {
			return false
		}
	}
	return true
}
