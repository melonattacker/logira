# Custom Rules Examples

These example rules use the same YAML format as `internal/detect/rules/default_rules.yaml`.

Use them with:

```bash
./logira run --rules ./examples/rules/quickstart.yaml -- <command...>
```

## Quickstart Sample (`quickstart.yaml`)

Contains three safe demo rules:

- `XE900`: matches an exec command containing `logira-demo-marker`
- `XF900`: matches writes to `/tmp/logira-demo-note.txt`
- `XN900`: matches network `send` activity (works reliably for the curl demo)

### Try the exec rule

```bash
./logira run --rules ./examples/rules/quickstart.yaml -- \
  bash -lc 'echo logira-demo-marker'
```

### Try the file rule

```bash
./logira run --rules ./examples/rules/quickstart.yaml -- \
  bash -lc 'echo hi > /tmp/logira-demo-note.txt'
```

### Try the net rule (localhost)

Terminal 1:

```bash
python3 -m http.server 8000
```

Terminal 2:

```bash
./logira run --rules ./examples/rules/quickstart.yaml -- \
  bash -lc 'curl -s http://127.0.0.1:8000 >/dev/null'
```

Then inspect detections:

```bash
./logira explain last
./logira query last --type detection
```

Note:
For localhost requests, some kernels/environments may emit `send`/`recv` events without a matching `connect` detection event or destination metadata. The sample rule intentionally matches `op: send` to stay easy to demo.
