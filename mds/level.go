package mds

import (
	"fmt"
	"time"
)

// Level is a FIDO certification level, ordered: a higher value is a stricter
// certification. The zero value, LevelNone, is "no certification level".
//
// The order is the one of the AuthenticatorStatus enum, MDS 3.1 section
// 3.1.4.1 (Certification Related Statuses): FIDO_CERTIFIED_L1 "is the more
// strict successor of FIDO_CERTIFIED", L1plus is "more than level 1", L2 "is
// more strict than level 1+", L2plus "than level 2", L3 "than level 2+" and
// L3plus "than level 3". So L1 < L1plus < L2 < L2plus < L3 < L3plus.
type Level int

// The levels, weakest first.
const (
	LevelNone Level = iota
	L1
	L1plus
	L2
	L2plus
	L3
	L3plus
)

var levelNames = [...]string{"", "L1", "L1plus", "L2", "L2plus", "L3", "L3plus"}

// String is the short name ("L2plus"), "none" for LevelNone.
func (l Level) String() string {
	if l <= LevelNone || int(l) >= len(levelNames) {
		return "none"
	}
	return levelNames[l]
}

// ParseLevel reads a short name: "L1", "L1plus", "L2", "L2plus", "L3", "L3plus".
func ParseLevel(s string) (Level, error) {
	for i := 1; i < len(levelNames); i++ {
		if s == levelNames[i] {
			return Level(i), nil
		}
	}
	return LevelNone, fmt.Errorf("mds: %q is not a certification level (L1, L1plus, L2, L2plus, L3 or L3plus)", s)
}

// statusLevel maps an AuthenticatorStatus (3.1.4) to its level. The legacy
// FIDO_CERTIFIED is deliberately not one: it is "phased out and replaced by
// FIDO_CERTIFIED_L1", which is stricter, so it proves no level. The FIPS140
// statuses certify another scheme and are not FIDO levels either.
var statusLevel = map[string]Level{
	"FIDO_CERTIFIED_L1":     L1,
	"FIDO_CERTIFIED_L1plus": L1plus,
	"FIDO_CERTIFIED_L2":     L2,
	"FIDO_CERTIFIED_L2plus": L2plus,
	"FIDO_CERTIFIED_L3":     L3,
	"FIDO_CERTIFIED_L3plus": L3plus,
}

// CertificationLevel is the model's current FIDO certification level at now,
// LevelNone when it has none.
//
// "Current" follows MDS 3.1 section 3.1.3: "the latest StatusReport entry MUST
// reflect the current status", and a report's effectiveDate is "since when the
// status code was set" (absent: "effective while present"). So among the
// reports that name a FIDO_CERTIFIED_Lx status and are already effective at
// now, the one with the latest effectiveDate wins (a later report replaces an
// earlier one even when it is lower: a re-certification after a firmware
// update); equal or missing dates fall back to the array order, the later
// entry winning. Reports with a future date, an unknown status or an
// unparseable date are not trusted to raise the level: an unparseable date
// counts as the oldest. Revocation is not decided here: REVOKED and the
// compromise statuses are the caller's to check on every report.
func (e *Entry) CertificationLevel(now time.Time) Level {
	var best Level
	var bestDate time.Time
	found := false
	for _, r := range e.StatusReports {
		lv, ok := statusLevel[r.Status]
		if !ok {
			continue
		}
		var d time.Time
		if r.EffectiveDate != "" {
			t, err := time.Parse("2006-01-02", r.EffectiveDate)
			if err == nil {
				d = t
				if t.After(now) {
					continue
				}
			}
		}
		if !found || !d.Before(bestDate) {
			best, bestDate, found = lv, d, true
		}
	}
	return best
}
