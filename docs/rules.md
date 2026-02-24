# Detection Rules (Custom YAML)

logira supports per-run custom detection rules via:

```bash
./logira run --rules ./my-rules.yaml -- <command...>
```

Custom rules use the same YAML format as the built-in rules in `internal/detect/rules/default_rules.yaml`.

## Behavior Summary

- Built-in rules are always active.
- `--rules` appends your custom rules to the built-in set for that run.
- Rule IDs must be unique across the merged set (built-in + custom).
- Invalid YAML / invalid rule schema causes `logira run` to fail before the run starts.
- File event retention is rule-driven:
  - file events are only recorded if they match at least one active file rule
  - adding file rules may increase stored file-event volume

## Top-Level YAML Format

```yaml
rules:
  - id: "X001"
    title: "Example rule"
    type: "exec"   # exec | file | net
    severity: "low" # info | low | medium | high
    when:
      exec:
        contains_all: ["curl", "|", "sh"]
    message: "possible curl pipe to shell: {{exec.filename}}"
```

## Common Rule Fields

Each rule entry under `rules:` supports:

- `id` (required): unique rule ID string
- `title` (required): human-readable name
- `type` (required): `exec` | `file` | `net`
- `severity` (required): `info` | `low` | `medium` | `high`
- `when` (required): type-specific condition block (`when.exec`, `when.file`, or `when.net`)
- `message` (required): detection message template

## Rule Types

### `exec` Rules

Use `when.exec`:

```yaml
when:
  exec:
    contains_all: ["curl", "|", "sh"]
    contains_any: ["bash", "dash"]
```

Fields:

- `contains_all`: all strings must be present
- `contains_any`: at least one string must be present

Notes:

- Matching is case-insensitive.
- Matching is performed against a combined lowercase string of `filename + " " + argv...`.
- `contains_all` and `contains_any` can be used together.

### `file` Rules

Use `when.file`:

```yaml
when:
  file:
    prefix: "$HOME/.ssh/"
    op_in: ["create", "modify"]
    require_exec_bit: false
```

Supported fields:

- Path selector (exactly one required):
  - `prefix`: directory-prefix match (single)
  - `prefix_any`: list of directory prefixes (OR)
  - `path_in`: exact path list (OR)
  - `path_regex`: regular expression match
- `op_in` (required): allowed file operations
- `require_exec_bit` (optional): if `true`, file must have an executable bit set at evaluation time

Allowed `op_in` values:

- `create`
- `modify`
- `delete`
- `open`
- `read`

Notes:

- Exactly one of `prefix`, `prefix_any`, `path_in`, `path_regex` must be set.
- `$HOME` is supported in file paths and `path_regex` and is expanded to the audited user's home directory.
- `path_regex` is matched against the normalized absolute path.
- `require_exec_bit: true` uses a best-effort `stat(2)` at evaluation time; missing files or stat failures do not match.

### `net` Rules

Use `when.net`:

```yaml
when:
  net:
    op: "connect"
    dst_port_in: [443, 8443]
    dst_ip_in: ["169.254.169.254"]
```

Supported fields:

- `op` (optional): `connect` | `send` | `recv` (best-effort observed values)
- `dst_port_gte` (optional): integer lower bound (0-65535)
- `dst_port_in` (optional): exact allowed destination ports
- `dst_ip_in` (optional): exact allowed destination IP strings

Notes:

- Fields combine with AND semantics.
- If no `when.net` fields are set, the rule matches all net events of type `net`.
- If destination metadata is unavailable for an event, `dst_ip` / `dst_port` matching may fail.
- Depending on kernel/environment, you may see `send`/`recv` without a useful `connect` event for some traffic (especially localhost demos).

## Message Templates

`message` uses Go `text/template` under the hood, but logira supports a shorthand namespace style:

- `{{file.path}}`
- `{{net.dst_ip}}`
- `{{exec.filename}}`

These are normalized internally to Go template form.

Available template fields by rule type:

- `file`
  - `path`
  - `op`
- `net`
  - `op`
  - `proto`
  - `dst_ip`
  - `dst_port`
  - `bytes`
- `exec`
  - `filename`
  - `argv`
  - `comm`
  - `cwd`

Template behavior:

- Missing keys are treated as zero values (best-effort data may be empty).
- If template rendering fails, logira falls back to the raw `message` string.

## Validation / Common Errors

Examples of invalid rules that `logira run --rules` will reject:

- duplicate rule ID (including collision with built-in rules)
- invalid `type` / `severity`
- missing `message`, `id`, or `title`
- `file` rule without a path selector
- `file` rule with more than one path selector
- `file.op_in` missing or containing unsupported values
- invalid `path_regex`
- `net.dst_port_in` values outside `0..65535`

## Examples

- Quick trial rules: [`examples/rules/quickstart.yaml`](../examples/rules/quickstart.yaml)
- Trial commands and notes: [`examples/rules/README.md`](../examples/rules/README.md)

