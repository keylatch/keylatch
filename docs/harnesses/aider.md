---
title: Aider
harness: aider
---

# Aider

Support level: launch only

Aider has no hook mechanism, so Keylatch edits none of its files. Start it through Keylatch:

```sh
keylatch launch -- aider
```

`keylatch agent install aider` prints this and changes nothing. The session runs as a registered agent: Keylatch serves it placeholders and gateway credentials, never the stored values. Aider sets no environment marker; `AIDER_SESSION=1` is a manual label, and the `aider` process in a command's ancestry is detected.
