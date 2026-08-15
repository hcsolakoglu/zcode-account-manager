package main

import (
	"context"
	"fmt"
	"os"

	"github.com/hcsolakoglu/zcode-account-manager/internal/commands"
)

func main() {
	ctx, stop := commandSignalContext(context.Background())
	defer stop()
	if err := commands.RunContext(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
