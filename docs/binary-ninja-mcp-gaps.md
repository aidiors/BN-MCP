# Binary Ninja MCP feature gaps

This comparison was made on September 25, 2026 using this repository, the Binary Ninja user guide and the Python API documentation. It compares feature categories. Binary Ninja's built-in MCP tool list can change between releases.

## Available tools

[bridge/src/agent_tools.ts](../bridge/src/agent_tools.ts) registers 21 tools. They cover view selection, binary metadata, functions, strings, callers and callees, IL, disassembly, decompilation, basic blocks, stack frames, xrefs, bytes, entry points, sections, segments, imports, exports and comments. Annotation tools can rename functions and set address comments. Binary queries require `binary_id`. List responses are paginated.

`decompile_function`, `disassemble_function`, `basic_blocks` and `stack_frame` were added after the initial comparison. They return at most 200 records per page. Decompilation uses the registered Pseudo C renderer and falls back to HLIL with addresses.

## Missing features

| Priority | Feature | Current support | Proposed addition |
| --- | --- | --- | --- |
| High | Function summary | `inspect_function` returns the name, address and symbol. Basic blocks and stack layout have separate tools. | Add signatures, address ranges and complexity metrics. |
| High | Analysis control | No tool reports analysis progress, starts an update, waits for completion or stops analysis. IL requests may wait for analysis when `analysis_skipped` is set. | Add status and explicit analysis updates so clients can check whether results are ready. |
| Medium | Types and variables | Writes are limited to function names and address comments. Older endpoint methods handle types and variables but have no `/agent/` routes. | Add prototype, type and variable queries. Require expected previous values for type and variable edits. |
| Medium | Binary structure | Imports, exports, strings, entry points and memory maps are available. General symbol queries, data variable lists and relocations are missing. | Add paginated symbol, data variable and relocation queries with address filters. |
| Medium | File management | The tools list open views. Files must be opened and databases saved in the GUI. | Add open, close and save operations if clients need to manage files without the GUI. |
| Low | Address expressions and data formats | Addresses accept decimal or `0x` strings. `read_bytes` returns hex. List queries have no address range filters. | Add Binary Ninja address expressions, range filters and base64 output where needed. |

## Suggested order

1. Add signatures, ranges and metrics to function summaries.
2. Add analysis status and update tools.
3. Add data variable, symbol, relocation and type queries.
4. Add type and local variable edits with checks against the current value. Keep byte patches as a separate operation.
5. Add file management if clients need to open and save analysis without GUI actions.

These priorities reflect reverse engineering use cases. The Binary Ninja MCP guide describes file management, analysis, binary structure and function details. The Python API documents the underlying BinaryView and Function data.

## References

- [Binary Ninja MCP Server User Guide](https://docs.binary.ninja/guide/mcp.html)
- [BinaryView Python API](https://api.binary.ninja/binaryninja.binaryview-module.html)
- [Function Python API](https://api.binary.ninja/binaryninja.function-module.html)
- Source files: [agent_tools.ts](../bridge/src/agent_tools.ts), [agent_http_server.py](../plugin/server/agent_http_server.py), [binary_operations.py](../plugin/core/binary_operations.py), [endpoints.py](../plugin/api/endpoints.py)
