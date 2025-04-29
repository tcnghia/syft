package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/format/table"
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
		fullPath = filepath.Join(d.root, name)
	}
	return os.Open(fullPath)
}

func main() {
	// By default, scan the Syft codebase which has Go packages
	dirPath := findSyftRootDir()
	if len(os.Args) > 1 {
		dirPath = os.Args[1]
	}

	fmt.Printf("Scanning directory: %s\n\n", dirPath)

	// Method 1: Using CreateSBOMFromFS directly
	fmt.Println("Method 1: Using CreateSBOMFromFS with custom fs.FS")
	useFSDirectly(dirPath)

	// Method 2: Using GetSourceFromFS and then CreateSBOM
	fmt.Println("\nMethod 2: Using GetSourceFromFS and then CreateSBOM")
	useSource(dirPath)

	// Method 3: Using standard library os.DirFS
	fmt.Println("\nMethod 3: Using standard library os.DirFS")
	useOsDirFS(dirPath)
}

// findSyftRootDir attempts to find the Syft root directory
func findSyftRootDir() string {
	// Start with the current directory
	dir, err := os.Getwd()
	if err != nil {
		return "/tmp"
	}

	// Find the Syft root directory
	current := dir
	for {
		// Check for common Syft directories/files
		syftGoFile := filepath.Join(current, "syft", "lib.go")
		if _, err := os.Stat(syftGoFile); err == nil {
			return current
		}

		// Move up to parent directory
		parent := filepath.Dir(current)
		if parent == current {
			// Reached the root without finding Syft, return current example directory
			return dir
		}
		current = parent
	}
}

func useFSDirectly(dirPath string) {
	// Create a filesystem implementation
	filesystem := exampleDirectory{root: dirPath}

	// Create SBOM configuration
	config := syft.DefaultCreateSBOMConfig()

	// Create SBOM directly from the filesystem
	s, err := syft.CreateSBOMFromFS(context.Background(), filesystem, config)
	if err != nil {
		fmt.Printf("Error creating SBOM: %v\n", err)
		return
	}

	// Format and display the SBOM
	displaySBOM(*s, "method1-sbom.json")
}

func useSource(dirPath string) {
	// Create a filesystem implementation
	filesystem := exampleDirectory{root: dirPath}

	// Create a source from the filesystem
	sourceConfig := syft.DefaultGetSourceConfig()
	sourceConfig.SourceProviderConfig.WithAlias(source.Alias{
		Name:    "example-fs-source",
		Version: "1.0.0",
	})

	src, err := syft.GetSourceFromFS(context.Background(), filesystem, sourceConfig)
	if err != nil {
		fmt.Printf("Error getting source: %v\n", err)
		return
	}

	// Create SBOM from the source
	config := syft.DefaultCreateSBOMConfig()
	s, err := syft.CreateSBOM(context.Background(), src, config)
	if err != nil {
		fmt.Printf("Error creating SBOM: %v\n", err)
		return
	}

	// Format and display the SBOM
	displaySBOM(*s, "method2-sbom.json")
}

func useOsDirFS(dirPath string) {
	// Use the standard library's os.DirFS function
	filesystem := os.DirFS(dirPath)

	// Create SBOM configuration
	config := syft.DefaultCreateSBOMConfig()

	// Create SBOM directly from the filesystem
	s, err := syft.CreateSBOMFromFS(context.Background(), filesystem, config)
	if err != nil {
		fmt.Printf("Error creating SBOM: %v\n", err)
		return
	}

	// Format and display the SBOM
	displaySBOM(*s, "method3-sbom.json")
}

func displaySBOM(s sbom.SBOM, filename string) {
	// Format as table for display
	tableBytes, err := format.Encode(s, table.NewFormatEncoder())
	if err != nil {
		fmt.Printf("Error encoding SBOM as table: %v\n", err)
	} else {
		// Display a summary of the found packages
		pkgCount := len(s.Artifacts.Packages.Sorted())
		fmt.Printf("Found %d packages\n", pkgCount)
		
		// Display a preview of the packages if any found
		if pkgCount > 0 {
			fmt.Println("\nPackage preview:")
			// Just show the first few lines of the table output
			lines := 0
			for _, b := range tableBytes {
				if b == '\n' {
					lines++
					if lines > 10 {
						fmt.Println("... (more packages not shown)")
						break
					}
				}
				fmt.Print(string([]byte{b}))
			}
			fmt.Println()
		}
	}

	// Format as JSON for saving
	jsonBytes, err := format.Encode(s, syftjson.NewFormatEncoder())
	if err != nil {
		fmt.Printf("Error encoding SBOM as JSON: %v\n", err)
		return
	}

	// Save to file
	err = os.WriteFile(filename, jsonBytes, 0644)
	if err != nil {
		fmt.Printf("Error writing SBOM to file: %v\n", err)
		return
	}
	
	fmt.Printf("SBOM saved to %s\n", filename)
}