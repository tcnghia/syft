package fssource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

var _ file.Resolver = (*fsResolver)(nil)

// fsResolver is a file resolver that provides access to files in fs.FS implementations.
type fsResolver struct {
	fs           fs.FS
	base         string
	filetree     filetree.Reader
	index        filetree.IndexReader
	searchContext filetree.Searcher
}

// newFSResolver creates a new resolver from the given fs.FS implementation,
// filtering the files according to the given exclusion configuration.
func newFSResolver(filesystem fs.FS, base string, exclude source.ExcludeConfig) (*fsResolver, error) {
	// Create a new resolver
	resolver := &fsResolver{
		fs:   filesystem,
		base: base,
	}

	// Build the file tree and index
	tree, index, err := resolver.buildIndex(exclude)
	if err != nil {
		return nil, fmt.Errorf("unable to build fs index: %w", err)
	}

	resolver.filetree = tree
	resolver.index = index
	resolver.searchContext = filetree.NewSearchContext(tree, index)

	return resolver, nil
}

// buildIndex creates a file tree and index by walking the fs.FS.
func (r *fsResolver) buildIndex(exclude source.ExcludeConfig) (filetree.Reader, filetree.IndexReader, error) {
	tree := filetree.New()
	index := filetree.NewIndex()

	// Convert exclusion patterns to a function that checks paths against patterns
	exclusions := []string{}
	for _, excludePattern := range exclude.Paths {
		excludePattern = strings.TrimPrefix(excludePattern, "./")
		exclusions = append(exclusions, excludePattern)
	}

	// Walk the filesystem
	err := fs.WalkDir(r.fs, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip excluded paths
		for _, exclusion := range exclusions {
			matches, err := filepath.Match(exclusion, path)
			if err != nil {
				log.Warnf("invalid exclusion pattern=%q : %+v", exclusion, err)
				continue
			}
			if matches {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
		}

		// Get file info
		info, err := d.Info()
		if err != nil {
			log.Warnf("unable to get file info for path=%q : %+v", path, err)
			return nil
		}

		// Add entry to the tree and index
		var ref *stereoscopeFile.Reference
		if d.IsDir() {
			ref, err = tree.AddDir(stereoscopeFile.Path(path))
		} else {
			ref, err = tree.AddFile(stereoscopeFile.Path(path))
		}

		if err != nil {
			return fmt.Errorf("unable to add path=%q to tree: %w", path, err)
		}

		// Create metadata for the file
		fileType := stereoscopeFile.TypeFromMode(info.Mode())

		metadata := stereoscopeFile.Metadata{
			Path:     path,
			Type:     fileType,
			FileInfo: info,
		}

		// Add to index
		index.Add(*ref, metadata)

		return nil
	})

	if err != nil {
		return nil, nil, fmt.Errorf("failed to walk filesystem: %w", err)
	}

	return tree, index, nil
}

// HasPath indicates if the given path exists in the underlying source.
func (r *fsResolver) HasPath(userPath string) bool {
	cleanPath := cleanPath(userPath)
	return r.filetree.HasPath(stereoscopeFile.Path(cleanPath))
}

// FilesByPath returns all file.References that match the given paths.
func (r *fsResolver) FilesByPath(userPaths ...string) ([]file.Location, error) {
	var locations []file.Location

	for _, userPath := range userPaths {
		cleanPath := cleanPath(userPath)

		// Find the file in the tree
		ref, err := r.searchContext.SearchByPath(cleanPath, filetree.FollowBasenameLinks)
		if err != nil {
			log.Tracef("unable to find file by path=%q : %+v", userPath, err)
			continue
		}

		if !ref.HasReference() {
			continue
		}

		entry, err := r.index.Get(*ref.Reference)
		if err != nil {
			log.Warnf("unable to get file by path=%q : %+v", userPath, err)
			continue
		}

		// Don't consider directories
		if entry.IsDir() {
			continue
		}

		// Create location
		if ref.HasReference() {
			locations = append(locations,
				file.NewVirtualLocationFromDirectory(
					string(ref.RealPath), // the actual path
					cleanPath,            // the path used to access this file
					*ref.Reference,
				),
			)
		}
	}

	return locations, nil
}

// FilesByGlob returns all file.References that match the given path glob pattern.
func (r *fsResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	uniqueFileIDs := stereoscopeFile.NewFileReferenceSet()
	uniqueLocations := make([]file.Location, 0)

	for _, pattern := range patterns {
		pathPattern := cleanPath(pattern)
		
		refVias, err := r.searchContext.SearchByGlob(pathPattern, filetree.FollowBasenameLinks)
		if err != nil {
			return nil, err
		}
		
		for _, refVia := range refVias {
			if !refVia.HasReference() || uniqueFileIDs.Contains(*refVia.Reference) {
				continue
			}
			
			entry, err := r.index.Get(*refVia.Reference)
			if err != nil {
				return nil, fmt.Errorf("unable to get file metadata for reference %s: %w", refVia.RealPath, err)
			}

			// Don't consider directories
			if entry.IsDir() {
				continue
			}

			loc := file.NewVirtualLocationFromDirectory(
				string(refVia.RealPath),    // the actual path
				string(refVia.RequestPath), // the path used to access this file
				*refVia.Reference,
			)
			uniqueFileIDs.Add(*refVia.Reference)
			uniqueLocations = append(uniqueLocations, loc)
		}
	}

	return uniqueLocations, nil
}

// RelativeFileByPath fetches a single file at the given path relative to another file.
func (r *fsResolver) RelativeFileByPath(_ file.Location, path string) *file.Location {
	paths, err := r.FilesByPath(path)
	if err != nil {
		return nil
	}
	if len(paths) == 0 {
		return nil
	}

	return &paths[0]
}

// FileContentsByLocation fetches file contents for a single file reference.
func (r *fsResolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	if location.RealPath == "" {
		return nil, errors.New("empty path given")
	}

	entry, err := r.index.Get(location.Reference())
	if err != nil {
		return nil, err
	}

	// Don't consider directories
	if entry.Type == stereoscopeFile.TypeDirectory {
		return nil, fmt.Errorf("cannot read contents of non-file %q", location.Reference().RealPath)
	}

	// Open the file from the filesystem
	f, err := r.fs.Open(location.RealPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open file: %w", err)
	}

	return f, nil
}

// AllLocations returns all file references.
func (r *fsResolver) AllLocations(ctx context.Context) <-chan file.Location {
	results := make(chan file.Location)
	go func() {
		defer close(results)
		for _, ref := range r.filetree.AllFiles(stereoscopeFile.AllTypes()...) {
			select {
			case <-ctx.Done():
				return
			case results <- file.NewLocationFromDirectory(string(ref.RealPath), ref):
				continue
			}
		}
	}()
	return results
}

// FileMetadataByLocation returns file metadata for a single file reference.
func (r *fsResolver) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	entry, err := r.index.Get(location.Reference())
	if err != nil {
		return file.Metadata{}, fmt.Errorf("location: %+v : %w", location, os.ErrNotExist)
	}

	return entry.Metadata, nil
}

// FilesByMIMEType returns all file references with the given MIME Type.
func (r *fsResolver) FilesByMIMEType(types ...string) ([]file.Location, error) {
	uniqueFileIDs := stereoscopeFile.NewFileReferenceSet()
	uniqueLocations := make([]file.Location, 0)

	refVias, err := r.searchContext.SearchByMIMEType(types...)
	if err != nil {
		return nil, err
	}
	
	for _, refVia := range refVias {
		if !refVia.HasReference() {
			continue
		}
		if uniqueFileIDs.Contains(*refVia.Reference) {
			continue
		}
		
		location := file.NewVirtualLocationFromDirectory(
			string(refVia.RealPath),
			string(refVia.RequestPath),
			*refVia.Reference,
		)
		uniqueFileIDs.Add(*refVia.Reference)
		uniqueLocations = append(uniqueLocations, location)
	}

	return uniqueLocations, nil
}

// Stringer to represent a fs.FS source
func (r fsResolver) String() string {
	return "fs:fs-source"
}

// cleanPath normalizes the given path to avoid issues with paths
func cleanPath(p string) string {
	return path.Clean(p)
}