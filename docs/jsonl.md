# AgentLogix JSONL Schema

AgentLogix writes one JSON object per line.

Common fields:
- `type`: `exec` | `file` | `net`
- `timestamp`: RFC3339Nano UTC
- `pid`, `ppid`, `uid`: optional numeric process metadata
- `detail`: event-specific object

## Exec Event

```json
{"type":"exec","timestamp":"2026-02-12T12:34:56.123456789Z","pid":1234,"ppid":1200,"uid":1000,"detail":{"filename":"/usr/bin/git","argv":["git","status"],"comm":"git","cwd":"/workspace","kernel_time_ns":1234567890}}
```

Fields in `detail`:
- `filename`: executable path (best effort)
- `argv`: arguments (truncated by `--argv-max` and `--argv-max-bytes`)
- `comm`: task comm
- `cwd`: working directory (best effort)
- `kernel_time_ns`: monotonic kernel timestamp from tracer

## File Event

```json
{"type":"file","timestamp":"2026-02-12T12:35:01.000000000Z","pid":1234,"detail":{"op":"modify","path":"/workspace/src/main.go","size_before":1001,"size_after":1042,"hash_before":"...","hash_after":"...","hash_truncated":false}}
```

Fields in `detail`:
- `op`: `create` | `modify` | `delete`
- `path`: affected path
- `size_before`, `size_after`: bytes (if known)
- `hash_before`, `hash_after`: SHA-256 (best effort)
- `hash_truncated`: true when file hash was capped by `--hash-max-bytes`

## Net Event

```json
{"type":"net","timestamp":"2026-02-12T12:35:10.000000000Z","pid":1234,"detail":{"op":"connect","proto":"unknown","dst_ip":"140.82.121.4","dst_port":443}}
{"type":"net","timestamp":"2026-02-12T12:35:10.100000000Z","pid":1234,"detail":{"op":"send","proto":"unknown","dst_ip":"140.82.121.4","dst_port":443,"bytes":517}}
{"type":"net","timestamp":"2026-02-12T12:35:10.200000000Z","pid":1234,"detail":{"op":"recv","proto":"unknown","dst_ip":"140.82.121.4","dst_port":443,"bytes":2048}}
```

Fields in `detail`:
- `op`: `connect` | `send` | `recv`
- `proto`: `tcp` | `udp` | `unknown` (best effort)
- `dst_ip`, `dst_port`: remote endpoint (best effort)
- `bytes`: sent/received bytes for `send`/`recv`
