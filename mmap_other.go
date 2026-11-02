//go:build !unix

package main

import "os"

// mapFile falls back to reading the whole file into memory on platforms without
// mmap support. The returned closer is a no-op.
func mapFile(path string) ([]byte, func() error, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return data, func() error { return nil }, nil
}
