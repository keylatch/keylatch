---
title: Goose
harness: goose
---

# Goose

Support level: launch only

Goose has permission modes but no pre-tool hook, so Keylatch edits none of its files. Start it through Keylatch:

```sh
keylatch launch -- goose
```

`keylatch agent install goose` prints this and changes nothing. The session runs as a registered agent: Keylatch serves it placeholders and gateway credentials, never the stored values. The `goose` process in a command's ancestry is detected.
