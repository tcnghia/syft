package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// exampleDirectory implements a simple fs.FS that uses the local file system
// but limited to a specific directory for demonstration purposes.
type exampleDirectory struct {
	root string
}

func (d exampleDirectory) Open(name string) (fs.File, error) {
	fullPath := d.root
	if name != "." {
		fullPath = fmt.Sprintf("%s/%s", d.root, name)
	}
	return os.Open(fullPath)
}

func main() {
	// Set your directory here
	dirPath := "/path/to/your/directory"
	if len(os.Args) > 1 {
		dirPath = os.Args[1]
	}

	// Method 1: Using CreateSBOMFromFS directly
	fmt.Println("Method 1: Using CreateSBOMFromFS")
	useFSDirectly(dirPath)

	// Method 2: Using GetSourceFromFS and then CreateSBOM
	fmt.Println("\nMethod 2: Using GetSourceFromFS")
	useSource(dirPath)
}

func useFSDirectly(dirPath string) {
	// Create a filesystem implementation
	filesystem := exampleDirectory{root: dirPath}

	// Create SBOM configuration
	config := syft.DefaultCreateSBOMConfig()
	config.SourceConfig.Alias = source.Alias{
		Name:    "example-fs-sbom",
		Version: "1.0.0",
	}

	// Create SBOM directly from the filesystem
	s, err := syft.CreateSBOMFromFS(context.Background(), filesystem, config)
	if err != nil {
		panic(err)
	}

	// Format and display the SBOM
	displaySBOM(*s)
}

func useSource(dirPath string) {
	// Create a filesystem implementation
	filesystem := exampleDirectory{root: dirPath}

	// Create a source from the filesystem
	sourceConfig := syft.DefaultGetSourceConfig()
	sourceConfig.SourceProviderConfig.Alias = source.Alias{
		Name:    "example-fs-source",
		Version: "1.0.0",
	}

	src, err := syft.GetSourceFromFS(context.Background(), filesystem, sourceConfig)
	if err != nil {
		panic(err)
	}

	// Create SBOM from the source
	config := syft.DefaultCreateSBOMConfig()
	s, err := syft.CreateSBOM(context.Background(), src, config)
	if err != nil {
		panic(err)
	}

	// Format and display the SBOM
	displaySBOM(*s)
}

func displaySBOM(s sbom.SBOM) {
	// Format as JSON
	bytes, err := format.Encode(s, syftjson.NewFormatEncoder())
	if err != nil {
		panic(err)
	}

	// Display package count
	fmt.Printf("Found %d packages\n", len(s.Artifacts.Packages.Sorted()))

	// Save to file
	err = os.WriteFile("sbom.json", bytes, 0644)
	if err != nil {
		panic(err)
	}
	
	fmt.Println("SBOM saved to sbom.json")
}