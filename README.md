# Binary Ninja MCP for RE agents

Licensed under Apache-2.0. See [LICENSE](LICENSE) for the full license text.

## What is available

The Node bridge provides 29 tools with input and output schemas. A local HTTP server inside Binary Ninja executes analysis requests one at a time. Each binary query requires a `binary_id` from `list_binaries`. Results include that ID. Read responses are paginated. Errors set MCP `isError`.

| Task | Tools |
| --- | --- |
| Choose and identify a view | `list_binaries`, `binary_info` |
| Find functions and data | `find_functions`, `find_strings`, `function_at`, `entry_points`, `list_imports`, `list_exports` |
| Inspect code and data | `inspect_function`, `related_functions`, `function_il`, `decompile_function`, `disassemble_function`, `basic_blocks`, `stack_frame`, `xrefs_to`, `read_bytes`, `read_comment`, `memory_map` |
| Edit annotations | `rename_function`, `set_comment` |
| Read function context | `function_context`, `call_sites`, `function_variables`, `inspect_type`, `analysis_status` |
| Improve decompilation | `edit_variable`, `set_function_type`, `define_type` |

Use `next_offset` until `truncated` is false. Each page contains at most 200 records. `read_bytes` returns at most 4096 bytes. String values are limited to 4096 characters. Annotation tools check previous values or revisions and reject stale edits. Save the database in Binary Ninja to keep annotations.

`binary_info(include_sha256=true)` hashes the current original file on disk. A saved BNDB may contain different bytes.

Each `binary_id` identifies one BinaryView. Views and file sessions have separate IDs, even when they share a path. Closed or unknown IDs return an error. `list_binaries` includes `view_type`. HTTP queries do not change the active GUI view.

String searches cover the full value, including text beyond the displayed 4096 characters. References and values are read in blocks. Stack frame queries convert only the requested page. Imports include imported functions, addresses, data and external symbols. Exports use the loader's global or weak binding and include PE forwarder metadata.

## Function analysis

`inspect_function` returns the signature, parameters, calling convention, address ranges, size and edit revision. `function_context` combines selected decompilation, outgoing calls, variables and callers in one request. Defaults are 80 code lines, 20 items per other section and a 32768-character JSON budget. Use `include` to request only the sections needed. Each section has its own `next_offset`. Continue with `decompile_function`, `call_sites`, `function_variables` or `related_functions`. `unavailable` reports sections the SDK could not provide.

Decompilation retains `lines` and adds `records` with text, address, IL index when available and page line index. Text is limited to 4096 characters per record. Rendered Pseudo C does not always have an IL index or address. Line indices are page positions and can change after analysis updates.

`call_sites` returns incoming or outgoing calls, argument expressions and the SDK's possible values. Values can be constants, bounded sets, ranges or unresolved. The tools report missing information without guessing targets. Arguments are limited to 32 per call and sets or ranges to 16 entries.

Set `include_refs=true` on `find_strings` to include references and containing functions. `ref_limit` defaults to 5 and is capped at 20. Continue truncated references with `xrefs_to`.

## Improving decompilation

1. Read `function_variables` for variable IDs, names, types and revisions. Read `inspect_function` for the function prototype revision.
2. Use `edit_variable` with a function start address, variable ID and `expected_revision`. Supply `new_name`, `new_type` or both. Different variables can be edited from the same read.
3. Use `inspect_type` to read a named type. `define_type` accepts exactly one C type declaration. Pass its current revision, or `null` when the name is absent. Extra type, variable or function declarations are rejected.
4. Use `set_function_type` to apply a C function prototype with the revision from `inspect_function`. The declaration's function name does not rename the function.
5. Poll `analysis_status` until `ready` is true, then read variables or decompilation again. Edits return the requested annotation. Derived types and code may still reflect the previous analysis when the edit returns.

Edits create Binary Ninja Undo entries and request analysis without waiting for completion. Repeated writes with the same revision are rejected even before analysis finishes. Prototype changes invalidate variable revisions for that function. Revisions check annotation state and edits made through this server. They are not snapshots of all analysis results. `analysis_status` can be read while another analysis request is running.

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

The hooks run Ruff, ty, Python tests, Python compilation, the TypeScript build, and MCP tests. They require Python, Node.js 18 or newer, and installed bridge dependencies. Binary Ninja and PySide6 imports are treated as `Any` because their SDKs are unavailable in CI. Integration tests cover view IDs, HTTP connections, shutdown, worker limits, annotation conflicts, context budgets and all 29 tools. They use the project's HTTP client and backend with test doubles for SDK objects.

For a headless check with an installed Binary Ninja SDK and license:

```text
python tests/verify_binary_ninja.py --sdk-path "<Binary Ninja installation>/python"
```

The script loads `example/chal`, checks all routes, annotations and decompilation edits, tests Undo, and closes the file without saving a database. Use `--binary <path>` to check another file with functions, calls and typed variables. User plugins are disabled in the test process. Check GUI tab changes, file close notifications and the status indicator after restarting Binary Ninja.

Query and view selection code is in `binary_operations.py`, `view_registry.py`, `read_only_queries.py`, `symbol_queries.py` and `function_analysis.py`. Checked type and variable edits are in `decompilation_edits.py`. Older operations are in `legacy_operations.py`. They have no HTTP routes.

## Scope

The HTTP backend listens on loopback and supports 29 MCP tools through 25 routes. Agent coordination, an evidence database and Cheat Engine integration are outside this repository's scope.
