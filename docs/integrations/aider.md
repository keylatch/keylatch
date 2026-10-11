# Keylatch Integration — Aider

Aider has no pre-tool hook API, so there is no guard to install. Keylatch protects Aider sessions by launching it under a session ticket:

```bash
keylatch launch -- aider
```

Every process below the launcher is treated as an agent session, so `keylatch get` is blocked and values reach commands only through `keylatch run`.

Aider sets no environment variable of its own. When it is started some other way, set `CREDENTIALS_LLM_SESSION=aider` in the shell rc so the session guard applies.

`keylatch install-guard aider` prints this guidance and installs nothing.
