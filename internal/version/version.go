package version

import (
	"runtime/debug"
	"time"
)

var (
	Version   = "dev"
	GitCommit = "none"
	BuildDate = "unknown"
)

func init() {
	if Version != "dev" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if info.Main.Version != "" {
		Version = info.Main.Version
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			GitCommit = s.Value
		case "vcs.time":
			if t, err := time.Parse(time.RFC3339, s.Value); err == nil {
				BuildDate = t.UTC().Format("20060102")
			} else {
				BuildDate = s.Value
			}
		}
	}
}
