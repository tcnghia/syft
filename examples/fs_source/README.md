# Using Syft with Go fs.FS

This example demonstrates how to use Syft as a library with Go's `fs.FS` interface. This approach allows you to generate SBOMs from any implementation of the `fs.FS` interface, such as embedded files, in-memory filesystems, or custom virtual filesystems.

## How to Use fs.FS with Syft

There are two primary ways to use Syft with an `fs.FS` implementation:

### Method 1: Use CreateSBOMFromFS (Direct)

The most direct way is to call `syft.CreateSBOMFromFS` with your `fs.FS` implementation:

```go
import (
    "context"
    "io/fs"
    
    "github.com/anchore/syft/syft"
    "github.com/anchore/syft/syft/source"
)

// Your fs.FS implementation
filesystem := myFSImplementation{}

// Configure options
config := syft.DefaultCreateSBOMConfig()
config.SourceConfig.Alias = source.Alias{
    Name:    "my-project",
    Version: "1.0.0",
}

// Create SBOM directly from the filesystem
sbom, err := syft.CreateSBOMFromFS(context.Background(), filesystem, config)
if err != nil {
    // handle error
}
```

### Method 2: Get Source from fs.FS

If you need more control over the source creation, you can use `syft.GetSourceFromFS` to create a source object:

```go
import (
    "context"
    "io/fs"
    
    "github.com/anchore/syft/syft"
    "github.com/anchore/syft/syft/source"
)

// Your fs.FS implementation
filesystem := myFSImplementation{}

// Configure the source
sourceConfig := syft.DefaultGetSourceConfig()
sourceConfig.SourceProviderConfig.Alias = source.Alias{
    Name:    "my-project",
    Version: "1.0.0",
}

// Get a source from the filesystem
src, err := syft.GetSourceFromFS(context.Background(), filesystem, sourceConfig)
if err != nil {
    // handle error
}

// Create an SBOM from that source
sbom, err := syft.CreateSBOM(context.Background(), src, nil)
if err != nil {
    // handle error
}
```

## Custom fs.FS Implementation

You can use any implementation of `fs.FS`, such as the `os.DirFS` function, embedded files with `embed.FS`, or your own custom implementation:

```go
// Using os.DirFS
dirFS := os.DirFS("/path/to/directory")
sbom, err := syft.CreateSBOMFromFS(context.Background(), dirFS, nil)

// Using embedded files
//go:embed resources
var embeddedFiles embed.FS
sbom, err := syft.CreateSBOMFromFS(context.Background(), embeddedFiles, nil)

// Custom implementation
type myFS struct {
    // your implementation
}

func (m myFS) Open(name string) (fs.File, error) {
    // your implementation
}

myFilesystem := myFS{}
sbom, err := syft.CreateSBOMFromFS(context.Background(), myFilesystem, nil)
```

## Running This Example

1. Edit the `main.go` file to point to a directory of your choice
2. Run the example: `go run main.go /path/to/your/directory`
3. Check the generated `sbom.json` file

## Advantages of Using fs.FS

- **Flexibility**: Work with any filesystem implementation that supports the `fs.FS` interface
- **In-memory analysis**: Generate SBOMs from in-memory file systems without creating temporary files
- **Embedded files**: Directly analyze embedded files in your Go applications
- **Virtual filesystems**: Work with custom virtual filesystem implementations