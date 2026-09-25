# Binary Ninja MCP for RE agents

Licensed under Apache-2.0. See [LICENSE](LICENSE) for the full license text.

## What is available

The Node bridge exposes 17 tools with input and output schemas. A local HTTP server inside Binary Ninja executes them. Every binary query requires `binary_id` from `list_binaries`, and every result identifies the binary. Requests are serialized inside Binary Ninja. Read responses have bounded pages; errors set MCP `isError`.

| Task | Tools |
| --- | --- |
| Choose and identify a view | `list_binaries`, `binary_info` |
| Locate evidence | `find_functions`, `find_strings`, `function_at`, `entry_points`, `list_imports`, `list_exports` |
| Inspect code and data | `inspect_function`, `related_functions`, `function_il`, `xrefs_to`, `read_bytes`, `read_comment`, `memory_map` |
| Add checked annotations | `rename_function`, `set_comment` |

For a paged response, use `next_offset` until `truncated` is false. `function_il` returns at most 200 instructions, `xrefs_to` at most 200 references, `find_functions` and `find_strings` at most 200 records, and `read_bytes` at most 4096 bytes. String values are capped at 4096 characters. The two annotation tools require the previous name or comment and fail if it changed after the agent read it. They modify Binary Ninja analysis state; save the database in Binary Ninja when the changes are ready to keep.

`binary_info(include_sha256=true)` hashes the **current original file on disk**. A saved BNDB may describe different bytes; check that separately when exact provenance matters.

## Local installation

1. Put this entire repository in a stable location. Keep `.git` if you want its local history.
2. In `bridge`, run `npm ci` and `npm run build` with Node.js 18 or newer.
3. Install the repository root as a manual Binary Ninja plugin. On Windows, the user plugin folder is `%APPDATA%\Binary Ninja\plugins`; the root has the required `__init__.py`. A directory junction to this repository also works. See [Binary Ninja's manual plugin installation guide](https://docs.binary.ninja/guide/plugins.html).
4. Disable any separately installed upstream Binary Ninja MCP plugin so both plugins do not try to use port 9009. Restart Binary Ninja, open a binary, and start **Plugins → MCP Server → Start MCP Server**.
5. Point your MCP client's stdio configuration to `node` with the absolute path to `bridge/dist/index.js` as its argument. The bridge connects to `localhost:9009` by default. Start a fresh MCP client session after changing its configuration.

The plugin no longer edits MCP client configuration automatically. Do not use the upstream `npx binary-ninja-mcp` package with this fork; it runs the upstream bridge.

## Development checks

From the repository root:

```text
python -m pip install -r requirements-dev.txt
ruff check .
ruff format --check .
ty check
python -m unittest discover -s tests -p 'test_agent_*.py' -v
python -m compileall -q plugin
node bridge/node_modules/typescript/bin/tsc -p bridge/tsconfig.json
node tests/test_mcp_contract.mjs
```

The Python type check treats Binary Ninja and PySide6 imports as `Any` because their SDKs ship with the application and are not available in CI. The tests cover pagination, binary binding, annotation conflicts, schema exposure, structured MCP results, and error signaling without needing a Binary Ninja process. A live Binary Ninja test is still required after installing this fork.

## Scope

The HTTP backend listens on loopback only. It exposes the 17 bridge operations rather than upstream's broad set of HTTP routes. This is the MCP foundation for a reverse engineering workflow; the Sol/Luna agent coordinator, evidence database, and Cheat Engine integration are separate components.
