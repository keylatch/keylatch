package path

import "strings"

// Parts parses a canonical path string into PathParts.
// A canonical path must have exactly 4 slash-separated segments:
// namespace/category/provider[":"+account]/field
//
// Returns ErrInvalidPath for empty string or wrong segment count.
func Parts(canonical string) (PathParts, error) {
	if canonical == "" {
		return PathParts{}, ErrInvalidPath
	}

	segments := strings.SplitN(canonical, "/", 4)
	if len(segments) != 4 {
		return PathParts{}, ErrInvalidPath
	}

	for _, s := range segments {
		if s == "" {
			return PathParts{}, ErrInvalidPath
		}
	}

	providerSegment := segments[2]
	provider := providerSegment
	account := ""

	if idx := strings.LastIndex(providerSegment, ":"); idx != -1 {
		provider = providerSegment[:idx]
		account = providerSegment[idx+1:]
		if provider == "" || account == "" {
			return PathParts{}, ErrInvalidPath
		}
	}

	return PathParts{
		Namespace: segments[0],
		Category:  segments[1],
		Provider:  provider,
		Account:   account,
		Field:     segments[3],
	}, nil
}
