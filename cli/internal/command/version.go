package command

import (
	"fmt"
	"runtime"
)

// Значения версии проставляет линковщик на релизных сборках (goreleaser, см.
// .goreleaser.yaml) через -ldflags -X. При сборке из исходников (sec.sh или
// `go build`) остаются дефолты — так релизный бинарь отличим от локального.
var (
	version = "dev"
	commit  = ""
	date    = ""
)

// versionString — строка для `sec version` / `sec --version`.
func versionString() string {
	s := "sec " + version
	if commit != "" {
		s += " (" + commit
		if date != "" {
			s += ", " + date
		}
		s += ")"
	}
	return s + " " + runtime.GOOS + "/" + runtime.GOARCH
}

func versionCommand([]string) int {
	fmt.Println(versionString())
	return 0
}
