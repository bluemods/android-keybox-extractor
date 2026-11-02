//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

// Linux allows mapping large files without putting them all into RAM at once
func mapFile(path string) ([]byte, func() error, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}

	size := info.Size()
	if size == 0 {
		return []byte{}, func() error { return nil }, nil
	}
	if size != int64(int(size)) {
		return nil, nil, fmt.Errorf("file too large to map on this platform: %d bytes", size)
	}

	data, err := syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return nil, nil, fmt.Errorf("mmap: %w", err)
	}

	return data, func() error { return syscall.Munmap(data) }, nil
}
