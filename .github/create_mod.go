// Command create_mod packs a module directory into the module zip format
// served by proxy.golang.org, using golang.org/x/mod/zip.
//
// Usage: create_mod <module-path> <version> <dir> <out.zip>
package main

import (
	"log"
	"os"

	"golang.org/x/mod/module"
	"golang.org/x/mod/zip"
)

func main() {
	if len(os.Args) != 5 {
		log.Fatalf("usage: %s <module-path> <version> <dir> <out.zip>", os.Args[0])
	}
	mv := module.Version{Path: os.Args[1], Version: os.Args[2]}
	f, err := os.Create(os.Args[4])
	if err != nil {
		log.Fatal(err)
	}
	if err := zip.CreateFromDir(f, mv, os.Args[3]); err != nil {
		f.Close()
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
}
