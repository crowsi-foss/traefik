package tcp

import (
	"context"

	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/middlewares/tcp/accesslog"
	"github.com/traefik/traefik/v3/pkg/tcp"
)

// NewAccessLogBuilder creates a new access log middleware builder.
func NewAccessLogBuilder(config *dynamic.TCPAccessLog) (func(context.Context, tcp.Handler) (tcp.Handler, error), error) {
	return func(ctx context.Context, next tcp.Handler) (tcp.Handler, error) {
		return accesslog.NewHandler(ctx, next, config, "accesslog")
	}, nil
}
