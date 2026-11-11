package support

import (
	"github.com/wantafanta/jsrelease/internal/testutil"
	"testing"

	"github.com/wantafanta/jsrelease/internal/catalog"
)

func shipped(t *testing.T) []catalog.Release {
	return testutil.ShippedReleases(t)
}

func TestCompute(t *testing.T) {
	all := shipped(t)
	got := Compute(all)
	cases := []struct {
		lib      catalog.Library
		v        string
		text     string
		since    string
		official bool
	}{
		{catalog.Core, "4.0.0", "Supported", "", true},
		{catalog.Core, "3.7.1", "Security only", "18/01/2026", true}, // since jQuery 4.0.0
		{catalog.Core, "3.4.1", "Security only", "18/01/2026", true}, // older patch: same as its line
		{catalog.Core, "2.2.4", "Unsupported", "", true},
		{catalog.Core, "1.12.4", "Unsupported", "", true},
		{catalog.Migrate, "4.0.2", "Supported\u2020", "", false},
		{catalog.Migrate, "3.6.0", "Security only\u2020", "18/01/2026", false},
		{catalog.Migrate, "1.4.1", "Unsupported\u2020", "", false},
		{catalog.UI, "1.14.2", "Supported\u2020", "", false},
		{catalog.UI, "1.13.3", "Unsupported\u2020", "05/08/2024", false}, // since UI 1.14.0
		{catalog.UI, "1.8.24", "Unsupported\u2020", "05/10/2012", false}, // since UI 1.9.0
		{catalog.UI, "1.14.0-beta.1", "Unsupported\u2020", "", false},    // pre-release
		{catalog.Mobile, "1.4.5", "Unsupported", "07/10/2021", true},
		{catalog.Bootstrap, "5.3.8", "Supported", "", true},
		{catalog.Bootstrap, "4.6.2", "Unsupported", "01/01/2023", true},
		{catalog.Bootstrap, "3.4.1", "Unsupported", "24/07/2019", true},
		{catalog.Bootstrap, "2.3.2", "Unsupported", "19/08/2013", true},
		{catalog.Bootstrap, "1.4.0", "Unsupported\u2020", "", false},
		{catalog.Bootstrap, "6.0.0-alpha.1", "Unsupported\u2020", "", false}, // pre-release of an upcoming line
		{catalog.Moment, "2.31.0", "Security only", "", true},
		{catalog.Moment, "2.10.0", "Security only", "", true},
		{catalog.Moment, "1.7.2", "Unsupported\u2020", "", false},
		{catalog.Prototype, "1.7.3", "Unsupported\u2020", "", false},
		{catalog.Prototype, "1.6.1_rc1", "Unsupported\u2020", "", false},
	}
	for _, c := range cases {
		i, ok := got[string(c.lib)+"@"+c.v]
		if !ok {
			t.Errorf("%s %s: no status", c.lib, c.v)
			continue
		}
		if i.Text() != c.text || i.Since != c.since || i.Official != c.official {
			t.Errorf("%s %s: %q since %q official %v; want %q since %q official %v", c.lib, c.v, i.Text(), i.Since, i.Official, c.text, c.since, c.official)
		}
	}
	if len(got) != len(all) {
		t.Errorf("%d statuses for %d releases", len(got), len(all))
	}
	if j := got["core@3.7.1"].ToJSON(); j.Status != "security-only" || j.Basis != "official" || j.Source != catalog.Get(catalog.Core).Support.Source {
		t.Errorf("JSON: %+v", j)
	}
	if NewestInLine(all, catalog.Core, "3.4.1") != "3.7.1" || NewestInLine(all, catalog.Bootstrap, "4.0.0") != "4.6.2" {
		t.Error("NewestInLine")
	}
}

// TestRulesFollowNewReleases: when jQuery 5 appears, 4.x becomes security
// only and 3.x unsupported, with no change to the tool.
func TestRulesFollowNewReleases(t *testing.T) {
	all := append(shipped(t), catalog.Release{Library: catalog.Core, Name: "jQuery", Version: "5.0.0", ReleaseDate: "01/01/2030"})
	got := Compute(all)
	if got["core@5.0.0"].Status != Supported || got["core@4.0.0"].Status != SecurityOnly || got["core@3.7.1"].Status != Unsupported ||
		got["core@4.0.0"].Since != "01/01/2030" {
		t.Errorf("after jQuery 5: 5=%v 4=%v (since %s) 3=%v", got["core@5.0.0"].Status, got["core@4.0.0"].Status, got["core@4.0.0"].Since, got["core@3.7.1"].Status)
	}
	all = append(shipped(t), catalog.Release{Library: catalog.Bootstrap, Name: "Bootstrap", Version: "6.0.0", TagDate: "01/01/2030", TagURL: "x"})
	got = Compute(all)
	if got["bootstrap@6.0.0"].Status != Supported || got["bootstrap@5.3.8"].Text() != "Security only\u2020" {
		t.Errorf("after Bootstrap 6: 6=%v 5=%v", got["bootstrap@6.0.0"].Text(), got["bootstrap@5.3.8"].Text())
	}
}
