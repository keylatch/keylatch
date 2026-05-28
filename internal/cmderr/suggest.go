package cmderr

// SuggestProvider returns the closest known slug from knownSlugs if the
// Levenshtein distance between input and that slug is <= threshold.
// Returns "" if no slug is within the threshold.
func SuggestProvider(input string, knownSlugs []string, threshold int) string {
	best := ""
	bestDist := threshold + 1 // one beyond threshold so any match beats it

	for _, slug := range knownSlugs {
		if slug == input {
			// Exact match — not a typo, no suggestion needed.
			return ""
		}
		d := Distance(input, slug)
		if d <= threshold && d < bestDist {
			bestDist = d
			best = slug
		}
	}
	return best
}
