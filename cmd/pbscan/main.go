package main

import (
	"os"

	"github.com/pingback-sh/pbscan/internal/app"
)

func main() {
	os.Exit(app.Run(os.Args[1:], app.IO{In: os.Stdin, Out: os.Stdout, Err: os.Stderr}))
}
