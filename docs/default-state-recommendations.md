---
provider_defaults:
  oauth: gateway_default
  aws: gateway_default
  gmail: gateway_default
  dropbox: gateway_default
  cloudflare: gateway_default
ttl_defaults:
  ai_api: 3600
  general: 86400
masking_defaults:
  sensitive_search_routes: metadata_only
content_source_defaults:
  prompt_injection_labels: enabled
---

# Default State Recommendations

This file defines the expected default configuration produced by a clean `keylatch bootstrap`.
The `release-gates/default-state-regression.sh` script validates a fresh bootstrap matches
these values before allowing a release to publish.
