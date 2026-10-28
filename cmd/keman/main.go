package main

import (
	"context"
	"os"

	"github.com/kirank55/keman/internal/cli"
)

func main() {
	os.Exit(cli.Run(context.Background(), os.Args[1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr))
}
