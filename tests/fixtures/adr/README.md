# ADR ingest fixtures

Three collected sessions, one per tool, in the exact shape the collector POSTs
to `/api/v1/adr/sessions`.

| File | Tool | What it is |
|---|---|---|
| `claude_benign.json` | Claude Code | Ordinary debugging. Clean posture, nothing to find. |
| `cursor_suspicious_benign.json` | Cursor | A bulk table export. Triage should escalate it; reasoning should clear it. |
| `codex_malicious.json` | Codex | Production dump uploaded off-host, then the shell history cleared. Bad posture too. |

They are **generated, not written**: `generate.py` builds real `AgentEvent`
objects from `adr_sensor`'s own schema and serialises them the way
`transport.py` does. A schema change therefore breaks the generator rather than
quietly leaving these files asserting something the collector never sends.

To regenerate, from the platform root:

```bash
python umai-service/tests/fixtures/adr/generate.py UMAI-ADR/Sensor umai-service/tests/fixtures/adr
```

The generator needs the `UMAI-ADR` repository checked out beside this one. The
test suite does **not** — it reads the committed JSON, so it runs anywhere.

Used by `tests/test_adr_end_to_end.py`.
