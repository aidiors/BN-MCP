# Binary Ninja MCP feature gaps

The initial comparison was made on September 25, 2026 using this repository, the Binary Ninja user guide and the Python API documentation. This document includes subsequent additions. Binary Ninja's built-in MCP tool list can change between releases.

## Available tools

[bridge/src/agent_tools.ts](../bridge/src/agent_tools.ts) registers 29 tools. They cover view selection, binary metadata, function context, signatures, variables, call arguments, named types, analysis status, strings, IL, disassembly, decompilation, basic blocks, stack frames, xrefs, bytes, entry points, sections, segments, imports, exports and comments. Checked edits can rename functions and variables, set comments, apply prototypes and define types. Binary queries require `binary_id`. List responses are paginated.

`decompile_function`, `disassemble_function`, `basic_blocks` and `stack_frame` were added after the initial comparison. They return at most 200 records per page. Decompilation uses the registered Pseudo C renderer and falls back to HLIL with addresses.

## Missing features

| Priority | Feature | Current support | Proposed addition |
| --- | --- | --- | --- |
| High | Value tracing | Call arguments include expressions and possible values. IL and SSA can be read. | Add bounded definition and use traversal within a function. |
| Medium | Analysis control | `analysis_status` reports state and progress. Edits request analysis. IL requests can wait when analysis was skipped. | Add explicit updates and jobs for long queries with status and cancellation. |
| Medium | Type discovery and data variables | Named types and function variables can be read and edited. General type search and data variable queries are missing. | Add paginated type search and typed global data queries. |
| Medium | Binary structure | Imports, exports, strings, entry points and memory maps are available. General symbol queries, data variable lists and relocations are missing. | Add paginated symbol, data variable and relocation queries with address filters. |
| Medium | File management | The tools list open views. Files must be opened and databases saved in the GUI. | Add open, close and save operations if clients need to manage files without the GUI. |
| Low | Address expressions and data formats | Addresses accept decimal or `0x` strings. `read_bytes` returns hex. List queries have no address range filters. | Add Binary Ninja address expressions, range filters and base64 output where needed. |
| Low | Function metrics | Signatures, parameters, ranges and size are available. | Add complexity metrics and search filters based on calls and size. |

## Suggested order

1. Add bounded SSA definition and use traversal.
2. Add jobs and explicit analysis updates.
3. Add data variable, symbol, relocation and type search queries.
4. Add address and call filters to searches. Keep byte patches as a separate operation.
5. Add file management if clients need to open and save analysis without GUI actions.

These priorities reflect reverse engineering use cases. The Binary Ninja MCP guide describes file management, analysis, binary structure and function details. The Python API documents the underlying BinaryView and Function data.

## References

- [Binary Ninja MCP Server User Guide](https://docs.binary.ninja/guide/mcp.html)
- [BinaryView Python API](https://api.binary.ninja/binaryninja.binaryview-module.html)
- [Function Python API](https://api.binary.ninja/binaryninja.function-module.html)
- Source files: [agent_tools.ts](../bridge/src/agent_tools.ts), [agent_http_server.py](../plugin/server/agent_http_server.py), [binary_operations.py](../plugin/core/binary_operations.py), [endpoints.py](../plugin/api/endpoints.py)
