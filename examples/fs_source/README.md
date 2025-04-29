# Using Syft with Go fs.FS

This example demonstrates how to use Syft as a library with Go's `fs.FS` interface. This approach allows you to generate SBOMs from any implementation of the `fs.FS` interface, such as embedded files, in-memory filesystems, or custom virtual filesystems.

## How to Use fs.FS with Syft

There are three primary ways to use Syft with an `fs.FS` implementation, all demonstrated in this example:

### Method 1: Use CreateSBOMFromFS with Custom fs.FS

The most direct way is to call `syft.CreateSBOMFromFS` with your custom `fs.FS` implementation:

```go
import (
    "context"
    "io/fs"
    
    "github.com/anchore/syft/syft"
)

// Your custom fs.FS implementation
filesystem := customFSImplementation{}

// Configure options
config := syft.DefaultCreateSBOMConfig()

// Create SBOM directly from the filesystem
sbom, err := syft.CreateSBOMFromFS(context.Background(), filesystem, config)
if err != nil {
    // handle error
}
```

### Method 2: Get Source from fs.FS then Create SBOM

If you need more control over the source creation, you can use `syft.GetSourceFromFS` to create a source object:

```go
import (
    "context"
    "io/fs"
    
    "github.com/anchore/syft/syft"
    "github.com/anchore/syft/syft/source"
)

// Your fs.FS implementation
filesystem := customFSImplementation{}

// Configure the source
sourceConfig := syft.DefaultGetSourceConfig()
sourceConfig.SourceProviderConfig.WithAlias(source.Alias{
    Name:    "my-project",
    Version: "1.0.0",
})

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

### Method 3: Using Standard Library os.DirFS

You can use the standard library's `os.DirFS` function to create an `fs.FS` from a directory:

```go
import (
    "context"
    "os"
    
    "github.com/anchore/syft/syft"
)

// Use standard library os.DirFS
filesystem := os.DirFS("/path/to/directory")

// Create SBOM from the filesystem
sbom, err := syft.CreateSBOMFromFS(context.Background(), filesystem, nil)
if err != nil {
    // handle error
}
```

## Other fs.FS Implementations

The `fs.FS` interface is very versatile and can be implemented in many ways:

```go
// Using embedded files
//go:embed resources
var embeddedFiles embed.FS
sbom, err := syft.CreateSBOMFromFS(context.Background(), embeddedFiles, nil)

// Using in-memory file system
memFS := fstest.MapFS{
    "file.txt": &fstest.MapFile{
        Data: []byte("content"),
        Mode: 0644,
    },
}
sbom, err := syft.CreateSBOMFromFS(context.Background(), memFS, nil)

// Using a zip file as a filesystem
zipFile, _ := zip.OpenReader("archive.zip")
defer zipFile.Close()
sbom, err := syft.CreateSBOMFromFS(context.Background(), zipFile, nil)
```

## Running This Example

1. Run the example pointing to a directory of your choice:
   ```
   go run main.go /path/to/your/directory
   ```

2. Check the generated SBOM files:
   - `method1-sbom.json` - Created using direct CreateSBOMFromFS with custom fs.FS
   - `method2-sbom.json` - Created using source from GetSourceFromFS
   - `method3-sbom.json` - Created using standard library os.DirFS

If no argument is provided, the example will use `/tmp` as the default directory.

## Advantages of Using fs.FS

- **Flexibility**: Work with any filesystem implementation that supports the `fs.FS` interface
- **In-memory analysis**: Generate SBOMs from in-memory file systems without creating temporary files
- **Embedded files**: Directly analyze embedded files in your Go applications
- **Virtual filesystems**: Work with custom virtual filesystem implementations
- **No temporary files**: Process files directly without creating temporary copies on disk