// Package main is the component entrypoint. It pulls in the generated
// wasi:http/incoming-handler export (which wires our Handle function to the
// host) and provides an empty main so the toolchain has something to build.
package main

import _ "wit_component/internal/wit_exports"

func main() {}
