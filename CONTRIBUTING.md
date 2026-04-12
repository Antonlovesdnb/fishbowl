# Contributing to Fishbowl

## Getting started

```bash
git clone https://github.com/Antonlovesdnb/fishbowl.git
cd fishbowl

# Option 1: compile-check without installing Rust (uses Docker)
docker run --rm -v "$PWD":/src -w /src rust:slim cargo check

# Option 2: full local build
cargo install --path .
fishbowl build-image
```

You need a container runtime (Docker Desktop, Colima, OrbStack, or Rancher Desktop) for testing.

## Running tests

```bash
make test-launch      # smoke test: container boots, mounts work, logs export
make test-audit       # env mutation auditing
make test-discovery   # credential env var discovery
make test-file-access # mounted credential access tracking
make test-workspace   # workspace credential discovery
make test-network     # outbound network monitoring
```

## Project structure

See [AGENTS.md](AGENTS.md) for the file layout and [CLAUDE.md](CLAUDE.md) for detailed conventions.

## Key conventions

- **Observation-only.** Fishbowl audits, it doesn't block. Don't add enforcement.
- **Project content is untrusted.** Nothing from the repo should silently import host credentials. See the trust boundary rules in CLAUDE.md.
- **Credential values are never intentionally logged.** Env var previews show first 4 chars + length only.
- **Minimal CLI surface.** Hide power-user flags. New features should auto-detect or live in config.
- **Update docs with code.** If you change behavior, update README.md, CLAUDE.md, and the relevant docs/ file.

## Submitting changes

1. Fork the repo and create a branch
2. Make your changes
3. Ensure `cargo check` passes with zero warnings
4. Update documentation if behavior changed
5. Open a pull request with a clear description of what and why

## Security

If you find a security issue, please open a GitHub issue. This is a security tool for developer workflows — responsible disclosure is appreciated but the repo is open source and the threat model is documented in the README.

## License

By contributing, you agree that your contributions will be licensed under the same terms as the project.
