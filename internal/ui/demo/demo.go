// Package demo provides stub data for demo mode.
//
// Demo mode:
//   - Uses fixture connections with canary-free data.
//   - No real API calls are made.
//   - /api/status includes {"demo": true, "demo_banner": "..."}.
//   - All credential values are replaced with the string "demo-value-hidden".
//     This is not a real credential — it cannot be used.
package demo

// Connection is a value-free demo connection fixture.
type Connection struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Status   string `json:"status"`
	Risk     string `json:"risk"`
}

// Connections returns the demo fixture connections.
// Values are intentionally omitted (value-free principle).
func Connections() []Connection {
	return []Connection{
		{Name: "demo-openrouter", Provider: "openrouter", Status: "ok", Risk: "low"},
		{Name: "demo-github", Provider: "github", Status: "untested", Risk: "medium"},
		{Name: "demo-anthropic", Provider: "anthropic", Status: "ok", Risk: "low"},
	}
}

// StatusExtra returns additional fields for /api/status in demo mode.
func StatusExtra() map[string]interface{} {
	return map[string]interface{}{
		"demo":        true,
		"demo_banner": "Demo mode — no real credentials are stored",
	}
}
