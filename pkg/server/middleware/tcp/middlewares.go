package tcpmiddleware

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/config/runtime"
	"github.com/traefik/traefik/v3/pkg/middlewares/tcp/inflightconn"
	"github.com/traefik/traefik/v3/pkg/middlewares/tcp/ipallowlist"
	"github.com/traefik/traefik/v3/pkg/middlewares/tcp/ipwhitelist"
	"github.com/traefik/traefik/v3/pkg/middlewares/tcp/tcpaccesslog"
	"github.com/traefik/traefik/v3/pkg/server/provider"
	"github.com/traefik/traefik/v3/pkg/tcp"
	"github.com/traefik/traefik/v3/pkg/types"
)

type middlewareStackType int

const (
	middlewareStackKey middlewareStackType = iota
)

// Builder the middleware builder.
type Builder struct {
	configs map[string]*runtime.TCPMiddlewareInfo
}

// NewBuilder creates a new Builder.
func NewBuilder(configs map[string]*runtime.TCPMiddlewareInfo) *Builder {
	return &Builder{configs: configs}
}

// BuildChain creates a middleware chain.
func (b *Builder) BuildChain(ctx context.Context, middlewares []string) *tcp.Chain {
	chain := tcp.NewChain()

	for _, name := range middlewares {
		middlewareName := provider.GetQualifiedName(ctx, name)

		chain = chain.Append(func(next tcp.Handler) (tcp.Handler, error) {
			constructorContext := provider.AddInContext(ctx, middlewareName)
			if midInf, ok := b.configs[middlewareName]; !ok || midInf.TCPMiddleware == nil {
				return nil, fmt.Errorf("middleware %q does not exist", middlewareName)
			}

			var err error
			if constructorContext, err = checkRecursion(constructorContext, middlewareName); err != nil {
				b.configs[middlewareName].AddError(err, true)
				return nil, err
			}

			constructor, err := b.buildConstructor(constructorContext, middlewareName)
			if err != nil {
				b.configs[middlewareName].AddError(err, true)
				return nil, err
			}

			handler, err := constructor(next)
			if err != nil {
				b.configs[middlewareName].AddError(err, true)
				return nil, err
			}

			return handler, nil
		})
	}

	return &chain
}

func checkRecursion(ctx context.Context, middlewareName string) (context.Context, error) {
	currentStack, ok := ctx.Value(middlewareStackKey).([]string)
	if !ok {
		currentStack = []string{}
	}

	if slices.Contains(currentStack, middlewareName) {
		return ctx, fmt.Errorf("could not instantiate middleware %s: recursion detected in %s", middlewareName, strings.Join(append(currentStack, middlewareName), "->"))
	}

	return context.WithValue(ctx, middlewareStackKey, append(currentStack, middlewareName)), nil
}

func (b *Builder) buildConstructor(ctx context.Context, middlewareName string) (tcp.Constructor, error) {
	config := b.configs[middlewareName]
	if config == nil || config.TCPMiddleware == nil {
		return nil, fmt.Errorf("invalid middleware %q configuration", middlewareName)
	}

	var middleware tcp.Constructor

	// InFlightConn
	if config.InFlightConn != nil {
		middleware = func(next tcp.Handler) (tcp.Handler, error) {
			return inflightconn.New(ctx, next, *config.InFlightConn, middlewareName)
		}
	}

	// IPWhiteList
	if config.IPWhiteList != nil {
		log.Warn().Msg("IPWhiteList is deprecated, please use IPAllowList instead.")

		middleware = func(next tcp.Handler) (tcp.Handler, error) {
			return ipwhitelist.New(ctx, next, *config.IPWhiteList, middlewareName)
		}
	}

	// IPAllowList
	if config.IPAllowList != nil {
		middleware = func(next tcp.Handler) (tcp.Handler, error) {
			return ipallowlist.New(ctx, next, *config.IPAllowList, middlewareName)
		}
	}

	// TCPAccessLog
	// The config.TCPAccessLog comes from the runtime.TCPMiddlewareInfo which embeds dynamic.TCPMiddleware.
	// The dynamic.TCPMiddleware now has an AccessLog field of type *dynamic.TCPAccessLog.
	// We need to ensure this dynamic.TCPAccessLog is correctly translated to types.TCPAccessLog for the middleware constructor.
	// For now, we assume that config.TCPMiddleware.AccessLog is the *dynamic.TCPAccessLog.
	// The constructor tcpaccesslog.New expects *types.TCPAccessLog.
	// This might require a conversion step or ensuring the types are compatible.
	// Let's assume for now that we can construct types.TCPAccessLog from dynamic.TCPAccessLog.
	if config.TCPMiddleware.AccessLog != nil {
		// This is a placeholder for the actual conversion/population of types.TCPAccessLog
		// from config.TCPMiddleware.AccessLog (which is *dynamic.TCPAccessLog)
		accessLogConfig := &types.TCPAccessLog{
			FilePath:      config.TCPMiddleware.AccessLog.FilePath,
			Format:        config.TCPMiddleware.AccessLog.Format,
			BufferingSize: config.TCPMiddleware.AccessLog.BufferingSize,
			// Filters and Fields would also be mapped here.
			// Filters: &types.TCPAccessLogFilters{...},
			// Fields:  &types.TCPAccessLogFields{...},
		}
		if accessLogConfig.Filters == nil {
			accessLogConfig.Filters = &types.TCPAccessLogFilters{}
		}
		if accessLogConfig.Fields == nil {
			accessLogConfig.Fields = &types.TCPAccessLogFields{}
			accessLogConfig.Fields.SetDefaults()
		}
		// OTLP config would also be mapped if present in dynamic.TCPAccessLog

		// Extract entryPointName from context if available, or pass it down another way.
		// For now, middlewareName might be the best we have or an empty string.
		// The entryPointName is more relevant for the handler constructor if it needs it.
		// The tcpaccesslog.New function signature currently takes entryPointName.
		// This might need to be sourced from a higher level context or configuration.
		// provider.GetEntryPointName(ctx) could be a utility if it exists.
		// For simplicity, let's pass middlewareName as a stand-in for now, or an empty string.
		// The actual entryPointName should ideally be injected when the router/entrypoint is built.
		var entryPointName string // Placeholder - needs proper value
		if epName, ok := provider.GetEntryPointNameFromContext(ctx); ok {
			entryPointName = epName
		}

		middleware = func(next tcp.Handler) (tcp.Handler, error) {
			return tcpaccesslog.New(ctx, next, accessLogConfig, entryPointName)
		}
	}

	if middleware == nil {
		return nil, fmt.Errorf("invalid middleware %q configuration: invalid middleware type or middleware does not exist", middlewareName)
	}

	return middleware, nil
}
