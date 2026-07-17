package main

import (
	"encoding/json"
	"io"
	"runtime"
	"runtime/debug"
)

// These values are injected by scripts/build-release.sh. Defaults keep local
// development builds explicit instead of pretending to be a release.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
	toolchain = "unknown"
)

type versionMetadata struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	Toolchain string `json:"toolchain"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
	Modified  bool   `json:"vcs_modified"`
}

func currentVersionMetadata() versionMetadata {
	metadata := versionMetadata{Name: "sakhtar-wg", Version: version, Commit: commit, BuildDate: buildDate, Toolchain: toolchain, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	if metadata.Toolchain == "unknown" {
		metadata.Toolchain = runtime.Version()
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				if metadata.Commit == "unknown" {
					metadata.Commit = setting.Value
				}
			case "vcs.modified":
				metadata.Modified = setting.Value == "true"
			}
		}
	}
	return metadata
}

func writeVersion(w io.Writer, asJSON bool) error {
	metadata := currentVersionMetadata()
	if asJSON {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(metadata)
	}
	_, err := io.WriteString(w, metadata.Name+" "+metadata.Version+" commit="+metadata.Commit+" built="+metadata.BuildDate+" toolchain="+metadata.Toolchain+" "+metadata.GOOS+"/"+metadata.GOARCH+"\n")
	return err
}
