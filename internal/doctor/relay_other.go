//go:build !unix

package doctor

import "os"

func ownedByUser(os.FileInfo) bool { return false }
