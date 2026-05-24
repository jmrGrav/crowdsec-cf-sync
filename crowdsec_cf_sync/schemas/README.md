# IPC Contract Schemas — crowdsec-cf-sync

JSON Schema (Draft 2020-12) documents for every structured data boundary in the daemon.

These schemas **document existing formats** — they do not add runtime validation
or change any payload. `additionalProperties: true` is intentional: the runtime
already tolerates extra fields and schemas must reflect that.

## Files

| Schema | Direction | Path / endpoint |
|--------|-----------|----------------|
| [`wal-entry.schema.json`](wal-entry.schema.json) | Python internal | `/var/log/crowdsec/cf-sync-wal.jsonl` (one entry per line) |
| [`state-envelope.schema.json`](state-envelope.schema.json) | Python internal | All six `*.json` state files |
| [`lua-sync.schema.json`](lua-sync.schema.json) | Python → Lua | `/run/crowdsec-lua/bans.json` |
| [`lua-events.schema.json`](lua-events.schema.json) | Lua → Python | `/run/crowdsec-lua/events.jsonl` (one entry per line) |
| [`health.schema.json`](health.schema.json) | Python → HTTP client | `GET http://localhost:8765/health` |

## IPC boundaries at a glance

```
OpenResty (Lua)  ──events.jsonl──▶  Python daemon  ──bans.json──▶  OpenResty (Lua)
                                          │
                                    cf-sync-wal.jsonl   (crash-durable audit)
                                    *.json state files  (atomic, checksummed)
                                    GET /health         (HTTP status endpoint)
```

## Known issues

- `cmd_wal_inspect` and `cmd_wal_replay` read `e["action"]` / `e["ip"]` but
  entries are written with `e["op"]` / `e["target"]`. Both commands silently
  return empty results on any real WAL. Fix tracked separately.

## Versioning

- **WAL**: no format version field; stable since initial implementation.
- **State envelope**: `version: 1` (STATE_VERSION). V3 flat files (no version key) are read-compatible and migrated to V4 on next save.
- **Lua sync**: `version` is a per-session monotonic counter, not a format version.
- **Lua events**: no version field; format is stable.
- **Health**: `state_version: 1` reflects STATE_VERSION; format itself is unversioned.
