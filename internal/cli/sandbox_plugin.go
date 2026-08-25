package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/trknhr/envvault/internal/sandboxplugin"
)

type sandboxPluginServeArgs struct {
	gatewayListen string
	gatewayHost   string
}

func (a App) runSandboxPluginServe(ctx context.Context, parsed sandboxPluginServeArgs, stdout, stderr io.Writer) int {
	broker := &sandboxplugin.Broker{
		Profiles:      a.profiles,
		Secrets:       a.secrets,
		Now:           a.now,
		ListenAddress: parsed.gatewayListen,
		AdvertiseHost: parsed.gatewayHost,
	}
	if err := broker.Validate(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	input := a.stdin
	if input == nil {
		input = os.Stdin
	}
	serveCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := (sandboxplugin.Server{Broker: broker}).Serve(serveCtx, input, stdout); err != nil {
		if errors.Is(err, context.Canceled) && serveCtx.Err() != nil {
			return 0
		}
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
