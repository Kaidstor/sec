package main

import _ "embed"

//go:embed reveal.html
var revealHTML []byte

//go:embed index.html
var indexHTML []byte

//go:embed favicon.svg
var faviconSVG []byte
