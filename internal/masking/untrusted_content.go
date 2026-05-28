package masking

// UntrustedContentLabel is injected into response envelopes for content from
// providers known to return user-supplied data that may contain prompt injections.
const UntrustedContentLabel = "__keylatch_untrusted_tool_data__"

// UntrustedContentProviders is the set of provider IDs that return user/content data.
var UntrustedContentProviders = map[string]bool{
	"gmail":         true,
	"slack":         true,
	"notion":        true,
	"dropbox":       true,
	"google-docs":   true,
	"github-issues": true,
	"zendesk":       true,
	"intercom":      true,
	"hubspot":       true,
	"salesforce":    true,
}

// ContentHandling describes how untrusted content is processed.
type ContentHandling string

const (
	// ContentHandlingLabel wraps content fields with UntrustedContentLabel.
	ContentHandlingLabel ContentHandling = "label"
	// ContentHandlingStrip removes content fields, returning metadata only.
	ContentHandlingStrip ContentHandling = "strip"
	// ContentHandlingSummarize returns a placeholder pending summarization.
	ContentHandlingSummarize ContentHandling = "summarize"
)

// UntrustedContentPolicy configures how untrusted content is handled.
type UntrustedContentPolicy struct {
	Handling                          ContentHandling
	MaxContentChars                   int
	RequireApprovalOnWriteCombination bool
}
