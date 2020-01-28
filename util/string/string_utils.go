package stringutil

import "strings"

type StringSet []string

func StringSliceReverse(ss []string) []string {
	ret := make([]string, len(ss))
	for i, s := range ss {
		ret[len(ss)-i-1] = s
	}
	return ret
}

func (ss StringSet) Union(s StringSet) []string {
	var mm map[string]bool
	mm = make(map[string]bool)
	var ret []string
	for _, c := range ss {
		mm[c] = false
	}
	for _, c := range s {
		if _, ok := mm[c]; ok {
			mm[c] = true
		}
	}
	var foundNonSpoofed *bool
	foundNonSpoofed = new(bool)
	for k, v := range mm {
		if k == "non_spoofed" && v {
			*foundNonSpoofed = true
			continue
		}
		if v {
			ret = append(ret, k)
		}
	}
	if *foundNonSpoofed {
		ret = append([]string{"non_spoofed"}, ret...)
	}
	return ret
}

func StringArrayEquals(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i, ll := range left {
		if ll != right[i] {
			return false
		}
	}
	return true
}

func OrderStringArray(left, right []string) int {
	if len(left) > len(right) {
		return 1
	}
	if len(left) < len(right) {
		return -1
	}
	for i, ll := range left {
		cmp := strings.Compare(ll, right[i])
		if cmp != 0 {
			return cmp
		}
	}
	return 0
}

func InArray(arr []string, s string) bool {
	for _, ss := range arr {
		if ss == s {
			return true
		}
	}
	return false
}

func StringSliceMinus(l, r []string) []string {
	old := make(map[string]bool)
	var ret []string
	for _, s := range l {
		old[s] = true
	}
	for _, s := range r {
		if _, ok := old[s]; ok {
			delete(old, s)
		}
	}
	foundSpoofed := new(bool)
	for key := range old {
		if key == "non_spoofed" {
			*foundSpoofed = true
			continue
		}
		ret = append(ret, key)
	}
	if *foundSpoofed {
		ret = append([]string{"non_spoofed"}, ret...)
	}
	return ret
}

func StringSliceIndex(segs []string, seg string) int {
	for i, s := range segs {
		if s == seg {
			return i
		}
	}
	return -1
}

func CloneStringSlice(ss []string) []string {
	var ret []string
	for _, s := range ss {
		ret = append(ret, s)
	}
	return ret
}
