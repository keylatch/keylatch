# my-rules

Prefer small diffs.

<!-- keylatch:begin -->
## Keylatch

Credentials come from Keylatch. Run commands that need one with `keylatch run <connection> -- <command>` or the `keylatch_run` MCP tool, and list the available connections with `keylatch list`. Never ask the user for an API key, read credential files or print the environment: Keylatch denies it and the guard hook blocks it.
<!-- keylatch:end -->
