package version

import (
	"fmt"
	"runtime"
)

// Version represents the current version of Delve.
type Version struct {
	Major    string
	Minor    string
	Patch    string
	Metadata string
	Build    string
}

var (
	// DelveVersion is the current version of Delve.
	DelveVersion = Version{
		Major: "1", Minor: "23", Patch: "1", Metadata: "",
		Build: "$Id: 2eba762d75437d380e48fc42213853f13aa2904d $",
	}
)

func (v Version) String() string {
	fixBuild(&v)
	ver := fmt.Sprintf("Version: %s.%s.%s", v.Major, v.Minor, v.Patch)
	if v.Metadata != "" {
		ver += "-" + v.Metadata
	}
	return fmt.Sprintf("%s\nBuild: %s", ver, v.Build)
}

var buildInfo = func() string {
	return ""
}

func BuildInfo() string {
	return fmt.Sprintf("%s\n%s", runtime.Version(), buildInfo())
}

var fixBuild = func(v *Version) {
	// does nothing
}
