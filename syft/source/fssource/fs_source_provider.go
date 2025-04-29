package fssource

import (
	"context"
	"io/fs"

	"github.com/anchore/syft/syft/source"
)

// FSSourceProvider is a source.Provider implementation for fs.FS sources.
type FSSourceProvider struct {
	fs      fs.FS
	exclude source.ExcludeConfig
	alias   source.Alias
	base    string
}

// NewSourceProvider creates a new provider for fs.FS sources.
func NewSourceProvider(filesystem fs.FS, exclude source.ExcludeConfig, alias source.Alias, base string) source.Provider {
	return &FSSourceProvider{
		fs:      filesystem,
		exclude: exclude,
		alias:   alias,
		base:    base,
	}
}

// Name returns the name of the provider.
func (f FSSourceProvider) Name() string {
	return "fs-source"
}

// Provide returns a source object for the fs.FS implementation.
func (f FSSourceProvider) Provide(_ context.Context) (source.Source, error) {
	return New(
		Config{
			Filesystem: f.fs,
			Base:       basePath(f.base),
			Exclude:    f.exclude,
			Alias:      f.alias,
		},
	)
}

// basePath ensures a base path is set
func basePath(base string) string {
	if base == "" {
		base = "/"
	}
	return base
}