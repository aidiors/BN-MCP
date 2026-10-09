# Binary Ninja MCP for RE agents

Licensed under Apache-2.0. See [LICENSE](LICENSE) for the full license text.

## What is available

The Node bridge provides 21 tools with input and output schemas. A local HTTP server inside Binary Ninja executes requests one at a time. Each binary query requires a `binary_id` from `list_binaries`. Results include that ID. Read responses are paginated. Errors set MCP `isError`.

| Task | Tools |
| --- | --- |
| Choose and identify a view | `list_binaries`, `binary_info` |
| Find functions and data | `find_functions`, `find_strings`, `function_at`, `entry_points`, `list_imports`, `list_exports` |
| Inspect code and data | `inspect_function`, `related_functions`, `function_il`, `decompile_function`, `disassemble_function`, `basic_blocks`, `stack_frame`, `xrefs_to`, `read_bytes`, `read_comment`, `memory_map` |
| Edit annotations | `rename_function`, `set_comment` |

Use `next_offset` until `truncated` is false. Each page contains at most 200 records. `read_bytes` returns at most 4096 bytes. String values are limited to 4096 characters. Annotation tools require the previous name or comment and fail if it has changed. Save the database in Binary Ninja to keep annotations.

`binary_info(include_sha256=true)` hashes the current original file on disk. A saved BNDB may contain different bytes.

Each `binary_id` identifies one BinaryView. Views and file sessions have separate IDs, even when they share a path. Closed or unknown IDs return an error. `list_binaries` includes `view_type`. HTTP queries do not change the active GUI view.

String searches cover the full value, including text beyond the displayed 4096 characters. References and values are read in blocks. Stack frame queries convert only the requested page. Imports include imported functions, addresses, data and external symbols. Exports use the loader's global or weak binding and include PE forwarder metadata.

## Local installation

1. Put this entire repository in a stable location. Keep `.git` if you want its local history.
2. In `bridge`, run `npm ci` and `npm run build` with Node.js 18 or newer.
3. Install the repository root as a manual Binary Ninja plugin. On Windows, the user plugin folder is `%APPDATA%\Binary Ninja\plugins`. The root contains the required `__init__.py`. A directory junction to this repository also works. See [Binary Ninja's manual plugin installation guide](https://docs.binary.ninja/guide/plugins.html).
4. Disable any separately installed upstream Binary Ninja MCP plugin so both plugins do not try to use port 9009. Restart Binary Ninja, open a binary, and start **Plugins → MCP Server → Start MCP Server**.
5. Point your MCP client's stdio configuration to `node` with the absolute path to `bridge/dist/index.js` as its argument. The bridge connects to `127.0.0.1:9009` by default. Start a fresh MCP client session after changing its configuration.

Configure the MCP client manually. Use this repository's bridge. The upstream `npx binary-ninja-mcp` package runs a different bridge.

The HTTP server rejects requests with an `Origin` header, a non-local `Host`, or an annotation body without `application/json`. For authentication, set **MCP Server → HTTP Authentication Token** in Binary Ninja or use `BINJA_MCP_TOKEN` in its environment. Set `BINJA_MCP_TOKEN` to the same value in the bridge environment. Restart the server after changing settings. An empty token disables authentication. Keep the server on loopback.

Stopping the server closes connections and cancels queued operations outside the GUI thread. Headers and request bodies have a five-second read deadline. An SDK operation already running can finish and apply its changes. The status stays **Stopping** until it finishes. Restart is blocked during that time.

## Development checks

From the repository root:

```text
python -m pip install -r requirements-dev.txt
npm --prefix bridge ci
pre-commit install
pre-commit run --all-files
```

The hooks run Ruff, ty, Python tests, Python compilation, the TypeScript build, and MCP tests. They require Python, Node.js 18 or newer, and installed bridge dependencies. Binary Ninja and PySide6 imports are treated as `Any` because their SDKs are unavailable in CI. Integration tests cover view IDs, HTTP connections, shutdown, worker limits, annotation conflicts and all 21 tools. They use the project's HTTP client and backend with test doubles for SDK objects.

For a headless check with an installed Binary Ninja SDK and license:

```text
python tests/verify_binary_ninja.py --sdk-path "<Binary Ninja installation>/python"
```

The script loads `example/chal`, checks all routes and both annotation tools, restores annotations, and closes the file without saving a database. Use `--binary <path>` to check another file. User plugins are disabled in the test process. Check GUI tab changes, file close notifications and the status indicator after restarting Binary Ninja.

Query and view selection code is in `binary_operations.py`, `view_registry.py`, `read_only_queries.py` and `symbol_queries.py`. Older operations are in `legacy_operations.py`. They have no HTTP routes.

## Scope

The HTTP backend listens on loopback and supports 21 MCP tools through 20 routes. Agent coordination, an evidence database and Cheat Engine integration are outside this repository's scope.
