package catalog

import (
	"regexp"
	"strconv"
	"strings"
)

var numericPrefix = regexp.MustCompile(`^\d+(?:\.\d+)*`)

// preReleaseRank orders well-known pre-release labels. Labels not listed here
// are compared lexically.
var preReleaseRank = map[string]int{
	"alpha": 1, "a": 1,
	"beta": 2, "b": 2,
	"pre": 3,
	"rc":  4,
}

// CompareVersions compares two version strings using semantic version rules.
// It returns -1 if a < b, 0 if they are equal and +1 if a > b.
//
// jQuery has used several version styles over the years, all of which are
// handled: "3.7.1", "1.2" (== "1.2.0"), "4.0.0-beta.2", "3.0.0-alpha1",
// "1.4rc1" and "1.0.0-a4.1". A release always sorts above its pre-releases,
// and numeric parts are compared numerically ("1.10.0" > "1.9.1").
func CompareVersions(a, b string) int {
	an, ap := splitVersion(a)
	bn, bp := splitVersion(b)
	for i := 0; i < len(an) || i < len(bn); i++ {
		var x, y int
		if i < len(an) {
			x = an[i]
		}
		if i < len(bn) {
			y = bn[i]
		}
		if x != y {
			return cmpInt(x, y)
		}
	}
	switch {
	case ap == "" && bp == "":
		return 0
	case ap == "":
		return 1
	case bp == "":
		return -1
	}
	at, bt := tokenize(ap), tokenize(bp)
	for i := 0; i < len(at) && i < len(bt); i++ {
		if c := compareToken(at[i], bt[i]); c != 0 {
			return c
		}
	}
	return cmpInt(len(at), len(bt))
}

func splitVersion(v string) ([]int, string) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
	if i := strings.IndexByte(v, '+'); i >= 0 { // build metadata is ignored
		v = v[:i]
	}
	head := numericPrefix.FindString(v)
	var nums []int
	for _, p := range strings.Split(head, ".") {
		if p == "" {
			continue
		}
		n, _ := strconv.Atoi(p)
		nums = append(nums, n)
	}
	return nums, strings.TrimLeft(v[len(head):], "-.")
}

type token struct {
	num   int
	text  string
	isNum bool
}

// tokenize splits a pre-release label into alternating alphabetic and numeric
// runs: "beta.2" -> [beta 2], "a4.1" -> [a 4 1], "rc1" -> [rc 1].
func tokenize(s string) []token {
	var out []token
	var cur strings.Builder
	curNum := false
	flush := func() {
		if cur.Len() == 0 {
			return
		}
		t := token{text: strings.ToLower(cur.String()), isNum: curNum}
		if curNum {
			t.num, _ = strconv.Atoi(t.text)
		}
		out = append(out, t)
		cur.Reset()
	}
	for _, r := range s {
		isDigit := r >= '0' && r <= '9'
		isAlpha := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !isDigit && !isAlpha {
			flush()
			continue
		}
		if cur.Len() > 0 && isDigit != curNum {
			flush()
		}
		curNum = isDigit
		cur.WriteRune(r)
	}
	flush()
	return out
}

func compareToken(a, b token) int {
	switch {
	case a.isNum && b.isNum:
		return cmpInt(a.num, b.num)
	case a.isNum:
		return -1 // numeric identifiers have lower precedence (semver §11)
	case b.isNum:
		return 1
	}
	ra, oka := preReleaseRank[a.text]
	rb, okb := preReleaseRank[b.text]
	if oka && okb {
		return cmpInt(ra, rb)
	}
	return strings.Compare(a.text, b.text)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// IsStable reports whether v is a final release (no alpha, beta, rc, ...).
func IsStable(v string) bool {
	_, pre := splitVersion(v)
	return pre == ""
}
