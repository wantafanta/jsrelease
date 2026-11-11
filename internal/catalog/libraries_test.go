package catalog

import (
	"regexp"
	"testing"
)

// TestRegistry checks every library definition is complete, so a new entry
// can't silently miss a field another package relies on.
func TestRegistry(t *testing.T) {
	policies := map[string]bool{PolicyTwoMajors: true, PolicyFollowCore: true, PolicyLatestLine: true,
		PolicyDeprecated: true, PolicyMajorsWithEOL: true, PolicyMaintenance: true, PolicyInactive: true}
	formats := map[string]bool{"prototype": true, "moment": true, "underscore": true}
	seen := map[Library]bool{}
	for _, d := range Libraries {
		if d.ID == "" || d.Name == "" || d.Repo == "" || seen[d.ID] {
			t.Errorf("%q: missing ID, name or repository, or duplicate", d.ID)
		}
		seen[d.ID] = true
		if d.NPM == "" && d.NVDVendor == "" {
			t.Errorf("%s: no advisory source (npm package or NVD vendor)", d.ID)
		}
		if !policies[d.Support.Policy] {
			t.Errorf("%s: unknown support policy %q", d.ID, d.Support.Policy)
		}
		if d.Source == FromGitHub {
			if _, err := regexp.Compile(d.TagPattern); err != nil || d.TagPattern == "" {
				t.Errorf("%s: bad tag pattern: %v", d.ID, err)
			}
			if d.MinReleases <= 0 || d.DateNote == "" {
				t.Errorf("%s: MinReleases and DateNote are required", d.ID)
			}
			if d.Changelog != "" && !formats[d.ChangelogFormat] {
				t.Errorf("%s: CHANGELOG without a known format", d.ID)
			}
		}
		if Get(d.ID).Name != d.Name || d.ID.DisplayName() != d.Name {
			t.Errorf("%s: lookup", d.ID)
		}
	}
	if len(AllLibraries) != len(Libraries) || !Core.IsJQuery() || Bootstrap.IsJQuery() || Library("nope").IsJQuery() {
		t.Error("derived lists")
	}
}
