# Contributing to rust-DDS

## Requirements

All commits must include a DCO sign-off:

```
Signed-off-by: Your Name <your-email@example.com>
```

Use `git commit -s` to add it automatically.

## Branch Workflow

1. Fork or branch from `main`
2. Create a feature branch: `git checkout -b feat/<feature-name>`
3. Implement changes with tests
4. Run validation: `cargo test && cargo clippy -- -D warnings && cargo fmt --check`
5. Commit with sign-off: `git commit -s`
6. Push and open a pull request against `main`

## Quality Gates

Before opening a PR, ensure:

- [ ] `cargo build` succeeds
- [ ] `cargo test` passes
- [ ] `cargo clippy -- -D warnings` is clean
- [ ] `cargo fmt --check` is clean
- [ ] Requirements in `requirements.json` are updated for any new behaviour
- [ ] DCO sign-off present on every commit

## Requirements Traceability

New behaviour must be traced to a requirement in `requirements.json`.
Mark implementation with `//fusa:req REQ-XXX-NNN` and tests with `//fusa:test REQ-XXX-NNN`.

Never renumber or reuse existing requirement IDs. Append new requirements only.

## License

Mozilla Public License v2.0.
Copyright (c) 2026 Matt Jones.
