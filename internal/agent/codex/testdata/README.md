# Codex 0.147 JSONL fixture

`exec-0.147-todo-command.jsonl` is a sanitized, otherwise verbatim stdout
capture from `codex-cli 0.147.0` running `codex exec --json`. It is the v0
parser baseline and demonstrates the emitted `thread.started`, `turn.started`,
`turn.completed`, `agent_message`, `todo_list`, and `command_execution` shapes.

No `plan_update` shape is assumed. New item mappings require an additional live
0.147 fixture demonstrating that shape.
