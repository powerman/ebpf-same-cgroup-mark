# General rules for the project

## Project Context (Reference)

Simple eBPF firewall helper: set `SO_MARK` on a TCP client socket
when the destination listener socket lives in the same cgroup.

The Go code in this repo is just a thin loader for the BPF program.
The BPF program source lives in `bpf/same-cgroup-mark.c`.

### Tasks

Use these commands for corresponding tasks:

- `mise run fmt` — fixes formatting.
- `mise run lint` — runs all linters.
- `mise run build` — build everything (BPF + Go binary).
- `mise run build:bpf` — compile BPF object file only.
- `mise run test` — run all tests.
- `mise run cover:go:total` — show Go test coverage total.

## Mandatory Rules

### Repository Safety

- DO NOT create, amend, squash, rebase,
  or otherwise modify existing commits.
- DO NOT switch branches.
- DO NOT perform any network git operations
  inside this repository
  (e.g. `git push`, `git pull`, `git fetch`).
- You MAY use `git stash` if necessary,
  but clean up after yourself.
- You MAY use `git restore` for reverting local changes.
- Do not delete, rewrite, or mass-modify files
  outside the explicit scope of the task.
- Avoid destructive shell commands
  (e.g. `rm -rf`, recursive operations)
  unless explicitly required.

### Shell Script Minimalism

- Keep shell scripts as small and direct as possible.
- Do NOT turn simple launchers into supervisors.
  If lifecycle control belongs to an explicit shutdown command or the host service manager,
  keep it there.
- Do NOT add `trap` handlers,
  signal-forwarding glue,
  PID bookkeeping,
  custom exit-status plumbing,
  polling loops,
  `wait_for_*` helpers,
  manual socket deletion,
  `fuser -k`,
  or other defensive shell machinery
  unless a concrete reproduced failure requires exactly that code.
- Prefer one direct `exec` of the real process over wrapper logic.
  If the script only starts one long-lived command,
  extra shell structure is probably wrong.
- When a readiness check is truly needed,
  use the smallest predicate that matches the real dependency.
  Do NOT stack equivalent checks just to feel safer.
- Before adding any non-trivial shell branch or helper function,
  first prove that a simpler script is insufficient.
  If you cannot name the exact failure mode,
  do not add the code.

### Golang CLI App Architecture

- Use [Kong](https://github.com/alecthomas/kong) for CLI parsing.
- Keep command handlers thin:
  each command is a struct with a `Run(<App>) error` method.
  The handler parses its own flags and delegates to App.
- Minimize `main.go`:
  define the CLI struct, parse with Kong, call `ctx.Run(app)`.
- CLI handling code is placed in `internal/cli` rather than `package main`.
  This is a deliberate architectural choice:
  it enables importing and testing this code from the separate `test/` Go module,
  which is not possible with a root-level `package main`.

### Coding Standards

#### Semantic Linefeeds (comments and documentation only)

Start each sentence on a new line.
Break long sentences at natural pauses —
after commas, semicolons, conjunctions,
or between logical clauses.
Do NOT hard-wrap to a fixed column width.
The goal is meaningful diffs:
one changed idea = one changed line.

NOTE: The above example does not mean you should break into very short lines as shown.

#### Documentation (markdown)

- Write new documentation in English.
- Avoid adding new documentation
  unless specifically requested by user.
- Update existing documentation together with code changes
  ONLY if otherwise existing documentation became incorrect.
- Keep lines within 96 characters.
  Do NOT break semantically single line unless it won't fit into 96 characters.

#### Commenting

- Write new comments in English.
- Do not add redundant comments
  that restate obvious code behavior.
- Explain rationale, intent, trade-offs,
  and non-obvious behavior.
- Use full sentences in comments and documentation.
- Keep lines within 96 characters.
  Do NOT break semantically single line unless it won't fit into 96 characters.
- NEVER include architecture details and namespace-related gotchas into comments,
  add them into corresponding documentation files instead!
  Script comments may only refer docs on these topics, not duplicate or replace it.

#### Golang Dependency Injection

- Expose business logic through an `App` interface.
- Inject external-world access (OS, exec, filesystem, outgoing adapters)
  as an interface dependency of `App`,
  so tests can mock all system calls.
- The production implementation wraps real OS calls directly.

### Golang Testing

- Tests must only test the project's own code, not stdlib or third-party libraries.
  Mock external dependencies (OS, exec) and test your logic, not the underlying library.
- Use a **separate `test/` Go module** (`test/go.mod`) for test dependencies.
  This prevents supply chain attacks by keeping test dependencies out of `go.mod`
  of the main module — `go build` / `go install` won't download them.
  Tests live in `test/internal/` (mirroring `internal/`), import the main module
  via `replace` in `test/go.mod`, and use `package internal_test`.
- Use an **external test package** (`package xxx_test`), including main package.
- Name test functions as `TestFunc_Variant`, `TestTypeMethod_Variant` (`_Variant` optional).
- Place test functions in same order as tested code.
- Use `github.com/powerman/check` for assertions,
  begin most tests with `tt.Parallel()` and `t := check.T(tt).MustAll()`,
  use shortcut methods when available instead of `t.True(complex expression)`
  (e.g. `t.Nil(err)`, `t.Match(err, "substr")`, `t.Len(res)`, etc.
- Extensively use test helpers to reduce code duplication within and between tests.
- Use [gomock](https://go.uber.org/mock/mockgen) by default for interaction-based tests,
  where the assertions are about exact calls, arguments, call counts, matchers, or ordering:

  ```text
  //go:generate mise run mockgen
  ```

- Use [go-mockgen](https://github.com/unknwon/go-mockgen) for stateful fakes,
  when tests are clearer as world-state transitions than as long EXPECT() chains,
  especially when a dependency needs default behavior plus queued per-call overrides
  and optional post-hoc inspection of call history.
  List interface names explicitly with `-i` in `//go:generate`,
  because stateful mocks are expected to be relatively rare.

  ```text
  //go:generate mise run go-mockgen -i Интерфейс1 -i …
  ```

### Gotchas

- If `mise.lock` does not exist, create it with `touch mise.lock`.
- When verifying that `go build` succeeds, use `go build -o /dev/null .`
  to avoid leaving a binary in the repository root.
- `mise run test` and `mise run cover:*` run from `test/` directory.
