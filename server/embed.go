package main

import "embed"

//go:embed reveal.html
var revealHTML []byte

//go:embed index.html
var indexHTML []byte

//go:embed favicon.svg
var faviconSVG []byte

//go:embed fonts/*.woff2
var fontsFS embed.FS
