package main

import (
	"fmt"
	"os"

	"github.com/laurenschristian/adgctl/internal/cli"
)

var version = "dev"

func main() {
	cli.Version = version
	if err := cli.Root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
