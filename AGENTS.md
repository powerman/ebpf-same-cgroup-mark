# General rules for the project

## Project Context (Reference)

Simple eBPF firewall helper: set `SO_MARK` on a TCP client socket
when the destination listener socket lives in the same cgroup.

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
