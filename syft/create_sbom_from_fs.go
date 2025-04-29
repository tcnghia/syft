package syft

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/fssource"
)

// CreateSBOMFromFS creates an SBOM from the given fs.FS with the given configuration.
// This is a convenience function for using an fs.FS implementation without having to create
// a source object manually.
func CreateSBOMFromFS(ctx context.Context, filesystem fs.FS, config *CreateSBOMConfig) (*sbom.SBOM, error) {
	if config == nil {
		config = DefaultCreateSBOMConfig()
	}

	// Create a source from the filesystem
	src, err := fssource.New(fssource.Config{
		Filesystem: filesystem,
		Base:       "/",
		Exclude:    config.SourceConfig.Exclusions,
		Alias:      config.SourceConfig.Alias,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create FS source: %w", err)
	}

	// Create the SBOM using the source
	return CreateSBOM(ctx, src, config)
}

// GetSourceFromFS creates a source.Source from an fs.FS implementation with the given configuration.
func GetSourceFromFS(ctx context.Context, filesystem fs.FS, cfg *GetSourceConfig) (source.Source, error) {
	if cfg == nil {
		cfg = DefaultGetSourceConfig()
	}

	// Create a source provider for the fs.FS
	provider := fssource.NewSourceProvider(
		filesystem,
		cfg.SourceProviderConfig.Exclusions,
		cfg.SourceProviderConfig.Alias,
		"",
	)

	// Create the source
	return provider.Provide(ctx)
}