//go:build !linux && !darwin

package redactor

import "io/fs"

func changeTime(fs.FileInfo) int64 { return 0 }
