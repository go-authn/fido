package mds

import (
	"testing"
	"time"
)

func TestParseLevel(t *testing.T) {
	for i, n := range []string{"L1", "L1plus", "L2", "L2plus", "L3", "L3plus"} {
		l, err := ParseLevel(n)
		if err != nil || l != Level(i+1) || l.String() != n {
			t.Errorf("%s: %v %v %v", n, l, l.String(), err)
		}
	}
	for _, n := range []string{"", "l2", "L4", "L2+", "FIDO_CERTIFIED_L2", " L2"} {
		if _, err := ParseLevel(n); err == nil {
			t.Errorf("%q accepted", n)
		}
	}
	if LevelNone.String() != "none" || Level(99).String() != "none" {
		t.Error("String of an unknown level")
	}
	if !(L1 < L1plus && L1plus < L2 && L2 < L2plus && L2plus < L3 && L3 < L3plus && LevelNone < L1) {
		t.Error("order")
	}
}

func TestCertificationLevel(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	r := func(s, d string) StatusReport { return StatusReport{Status: s, EffectiveDate: d} }
	cases := []struct {
		name string
		rs   []StatusReport
		want Level
	}{
		{"none", nil, LevelNone},
		{"legacy FIDO_CERTIFIED proves no level", []StatusReport{r("FIDO_CERTIFIED", "2020-01-01")}, LevelNone},
		{"FIPS is not FIDO", []StatusReport{r("FIPS140_CERTIFIED_L2", "2020-01-01")}, LevelNone},
		{"L1 only", []StatusReport{r("FIDO_CERTIFIED", "2019-01-01"), r("FIDO_CERTIFIED_L1", "2021-01-01")}, L1},
		{"Bio shape: L1 then L2", []StatusReport{r("FIDO_CERTIFIED", "2019-05-01"), r("FIDO_CERTIFIED_L1", "2021-04-02"), r("FIDO_CERTIFIED_L2", "2022-03-01")}, L2},
		{"L3plus", []StatusReport{r("FIDO_CERTIFIED_L3plus", "2024-01-01")}, L3plus},
		{"later lower report replaces", []StatusReport{r("FIDO_CERTIFIED_L2", "2021-01-01"), r("FIDO_CERTIFIED_L1", "2023-01-01")}, L1},
		{"array order is not date order", []StatusReport{r("FIDO_CERTIFIED_L1", "2023-01-01"), r("FIDO_CERTIFIED_L2", "2021-01-01")}, L1},
		{"same date: later entry", []StatusReport{r("FIDO_CERTIFIED_L2", "2023-01-01"), r("FIDO_CERTIFIED_L1", "2023-01-01")}, L1},
		{"no dates: later entry", []StatusReport{r("FIDO_CERTIFIED_L1", ""), r("FIDO_CERTIFIED_L2", "")}, L2},
		{"future report not yet effective", []StatusReport{r("FIDO_CERTIFIED_L1", "2021-01-01"), r("FIDO_CERTIFIED_L3", "2027-01-01")}, L1},
		{"only a future report", []StatusReport{r("FIDO_CERTIFIED_L3", "2027-01-01")}, LevelNone},
		{"unparseable date is the oldest", []StatusReport{r("FIDO_CERTIFIED_L3", "soon"), r("FIDO_CERTIFIED_L1", "2021-01-01")}, L1},
		{"other statuses do not interrupt", []StatusReport{r("FIDO_CERTIFIED_L2", "2021-01-01"), r("UPDATE_AVAILABLE", "2024-01-01")}, L2},
	}
	for _, c := range cases {
		e := &Entry{StatusReports: c.rs}
		if got := e.CertificationLevel(now); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
