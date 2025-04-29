package fssource

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"

	"github.com/opencontainers/go-digest"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/internal"
)

var _ source.Source = (*fsSource)(nil)

// Config represents configuration parameters for a fs.FS source object.
type Config struct {
	Filesystem fs.FS
	Base       string
	Exclude    source.ExcludeConfig
	Alias      source.Alias
}

// fsSource implements source.Source for an fs.FS implementation.
type fsSource struct {
	id       artifact.ID
	config   Config
	resolver *fsResolver
	mutex    *sync.Mutex
}

// New creates a new source object from the provided fs.FS implementation.
func New(cfg Config) (source.Source, error) {
	return &fsSource{
		id:     deriveIDFromFS(cfg),
		config: cfg,
		mutex:  &sync.Mutex{},
	}, nil
}

// deriveIDFromFS generates an artifact ID from the given filesystem config. If an alias is provided, then
// the artifact ID is derived exclusively from the alias name and version. Otherwise, a base ID is used.
func deriveIDFromFS(cfg Config) artifact.ID {
	var info string
	if !cfg.Alias.IsEmpty() {
		// Use alias name and version as the artifact ID.
		info = fmt.Sprintf("%s@%s", cfg.Alias.Name, cfg.Alias.Version)
	} else {
		log.Warn("no explicit name and version provided for fs source, deriving generic artifact ID (which is not ideal)")
		info = "fs-source"
	}

	return internal.ArtifactIDFromDigest(digest.SHA256.FromString(filepath.Clean(info)).String())
}

func (s fsSource) ID() artifact.ID {
	return s.id
}

func (s fsSource) Describe() source.Description {
	name := "fs-source"
	version := ""
	if !s.config.Alias.IsEmpty() {
		a := s.config.Alias
		if a.Name != "" {
			name = a.Name
		}
		if a.Version != "" {
			version = a.Version
		}
	}
	return source.Description{
		ID:      string(s.id),
		Name:    name,
		Version: version,
		Metadata: source.DirectoryMetadata{
			Path: "fs-source",
			Base: s.config.Base,
		},
	}
}

func (s *fsSource) FileResolver(_ source.Scope) (file.Resolver, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.resolver == nil {
		res, err := newFSResolver(s.config.Filesystem, s.config.Base, s.config.Exclude)
		if err != nil {
			return nil, fmt.Errorf("unable to create fs resolver: %w", err)
		}

		s.resolver = res
	}

	return s.resolver, nil
}

func (s *fsSource) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.resolver = nil
	return nil
}