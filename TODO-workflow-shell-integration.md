# Task 5 — shell-only privileged integration workflow

## What

Add a separate GitHub Actions workflow that validates the real packet-marking behavior end-to-end using only shell commands.

## Why

The project now has strong unit coverage, but the actual cgroup-based socket marking path still needs a privileged runtime check on a real kernel.
A separate workflow keeps this experiment isolated from the existing regular test workflow.

## How

- Create a new workflow file instead of modifying `test.yml`.
- Build the binary and embedded BPF object.
- Load the program as root.
- Set up firewall logging and dedicated cgroup v2 groups.
- Use `nc -l` and `nc` from shell to drive positive and negative cases.
- Verify the mark through firewall/kernel logs and clean everything up at the end.

## Non-goals

- Do not add Go-based integration tests in this task.
- Do not merge this workflow into `test.yml` in this task.
- Do not add privileged BPF checks to ordinary local `mise run test`.
