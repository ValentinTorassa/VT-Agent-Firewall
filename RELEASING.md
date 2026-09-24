# Releasing

1. Bump `version` in `pyproject.toml` and add the entry to `CHANGELOG.md`.
2. Tag and push: `git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`.
3. `.github/workflows/release.yml` runs the tests, checks that the tag matches the
   version, builds the sdist and wheel, and creates the GitHub release with them.

## PyPI (one-time setup)

Publishing uses PyPI trusted publishing: GitHub proves the workflow's identity with
OIDC and no API token is stored anywhere.

1. On pypi.org (logged in): *Your projects → Publishing → Add a new pending
   publisher* with
   - PyPI project name: `vt-agent-firewall`
   - Owner: `ValentinTorassa`, repository: `VT-Agent-Firewall`
   - Workflow: `release.yml`, environment: `pypi`
2. In the GitHub repository settings, create the environment `pypi` and the
   repository variable `PYPI_PUBLISH` with the value `true`.
3. Publish an existing tag without retagging: *Actions → Release → Run workflow*
   with the tag (e.g. `v0.1.0`).
