# Changelog

## 0.1.0 — 2026-09-24

First public release, the reference implementation for the talk *"Dónde se rompe
OAuth cuando el que llama es un agente"* (OWASP Village, Ekoparty 2026).

- **Gateway pipeline:** normalize → default-deny policy → human approval → append-only
  audit → executor, fail-closed when parsing fails or the audit store is unavailable.
- **Delegated credentials (`api.call`):** a token broker holds the user's grant and
  refresh token; each allowed call gets its own token for one audience and one scope,
  valid five minutes, with the agent as actor. The policy decides each operation
  before any token exists. Revocation kills live tokens.
- **The four OAuth failure modes** as paired tests (`tests/test_delegation.py`):
  the naive pattern where the attack works, and the same attack stopped.
- **MCP proxy** (`vt-agent-firewall-mcp`): the gateway in front of any stdio MCP
  server. Filters `tools/list`, checks path arguments, blocks unregistered tools,
  pins the server's code by SHA-256. Checked against
  `@modelcontextprotocol/server-filesystem` 0.2.0.
- Threat model mapped to the OWASP Top 10 for LLM Applications (2025) and the OWASP
  Top 10 for Agentic Applications (2026).
- Apache-2.0. Standard library only, Python 3.11+.
