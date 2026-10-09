
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { BinjaHttpClient } from "./client.js";

const binaryId = z.string().min(1).describe("view_id from list_binaries. Required on every binary query.");
const identifier = z.string().min(1).describe("Function name or start address, e.g. 0x140001000");
const address = z.string().regex(/^(0x[0-9a-fA-F]+|[0-9]+)$/)
  .describe("Virtual address in 0x-prefixed hex or decimal");
const offset = z.number().int().min(0).default(0);
const limit = z.number().int().min(1).max(200).default(100);
const page = { offset: z.number().int(), limit: z.number().int(),
  next_offset: z.number().int().nullable(), truncated: z.boolean() };
const namedAddress = z.object({ name: z.string(), address: z.string() }).passthrough();
const functionSummary = z.object({ name: z.string(), address: z.string() });

async function result(request: Promise<Record<string, unknown>>) {
  try {
    const data = await request;
    return { content: [{ type: "text" as const, text: JSON.stringify(data) }],
      structuredContent: data };
  } catch (error) {
    return { content: [{ type: "text" as const,
      text: error instanceof Error ? error.message : String(error) }], isError: true };
  }
}

export function registerAgentTools(server: McpServer, client: BinjaHttpClient): void {
  server.registerTool("list_binaries", {
    description: "List open Binary Ninja views. Use view_id as binary_id in all other tools.",
    inputSchema: {},
    outputSchema: z.object({ binaries: z.array(z.object({
      id: z.string(), view_id: z.string(), filename: z.string().nullable(),
      basename: z.string().nullable(), active: z.boolean(), selectors: z.array(z.string()),
      view_type: z.string().nullable().optional(),
    })) }),
    annotations: { readOnlyHint: true },
  }, async () => result(client.requestJson("/binaries")));

  server.registerTool("binary_info", {
    description: "Identify a binary view: path, architecture, address range, and optional SHA-256 of the current original file on disk. A saved BNDB may contain older bytes.",
    inputSchema: { binary_id: binaryId, include_sha256: z.boolean().default(false) },
    outputSchema: z.object({ binary_id: z.string(), loaded: z.boolean(), view_id: z.string(),
      database_path: z.string().nullable(), original_path: z.string().nullable(),
      architecture: z.string().nullable(), view_type: z.string().nullable(),
      view_start: z.string().nullable(), view_end: z.string().nullable(),
      original_sha256: z.string().nullable(), hash_status: z.string() }),
    annotations: { readOnlyHint: true },
  }, async ({ binary_id, include_sha256 }) => result(client.requestJson("/agent/identity",
    { binaryId: binary_id, includeSha256: include_sha256 })));

  server.registerTool("find_functions", {
    description: "List functions in address order. Optionally filter names by a case-insensitive substring. Continue with next_offset while truncated is true.",
    inputSchema: { binary_id: binaryId, query: z.string().default(""), offset, limit },
    outputSchema: z.object({ binary_id: z.string(), functions: z.array(namedAddress), query: z.string(), ...page }),
    annotations: { readOnlyHint: true },
  }, async ({ binary_id, query, offset, limit }) => result(client.requestJson("/agent/functions",
    { binaryId: binary_id, query, offset, limit })));

  server.registerTool("find_strings", {
    description: "List strings with an optional case-insensitive substring filter. Search covers the full value. Returned values are limited to 4096 characters.",
    inputSchema: { binary_id: binaryId, query: z.string().default(""), offset, limit },
    outputSchema: z.object({ binary_id: z.string(), strings: z.array(z.object({ address: z.string().nullable(),
      length: z.number().nullable(), type: z.string(), value: z.string(),
      value_truncated: z.boolean() })), query: z.string(), ...page }),
    annotations: { readOnlyHint: true },
  }, async ({ binary_id, query, offset, limit }) => result(client.requestJson("/agent/strings",
    { binaryId: binary_id, query, offset, limit })));

  server.registerTool("inspect_function", {
    description: "Get exact function identity and symbol information by name or start address.",
    inputSchema: { binary_id: binaryId, identifier },
    outputSchema: z.object({ binary_id: z.string(), name: z.string(), raw_name: z.string(), address: z.string(),
      symbol: z.object({ type: z.string(), full_name: z.string() }).nullable() }),
    annotations: { readOnlyHint: true },
  }, async ({ binary_id, identifier }) => result(client.requestJson("/agent/function",
    { binaryId: binary_id, identifier })));

  server.registerTool("function_at", {
    description: "Find functions containing an arbitrary virtual address, including addresses inside a function.",
    inputSchema: { binary_id: binaryId, address },
    outputSchema: z.object({ binary_id: z.string(), address: z.string(),
      functions: z.array(namedAddress) }),
    annotations: { readOnlyHint: true },
  }, async ({ binary_id, address }) => result(client.requestJson("/agent/functionAt",
    { binaryId: binary_id, address })));

  server.registerTool("related_functions", {
    description: "List callers or callees by function name or start address. Analysis updates may change their order. Use xrefs_to for call-site addresses.",
    inputSchema: { binary_id: binaryId, identifier,
      relation: z.enum(["callers", "callees"]), offset, limit },
    outputSchema: z.object({ binary_id: z.string(),
      function: namedAddress, relation: z.enum(["callers", "callees"]),
      functions: z.array(namedAddress), ...page }),
    annotations: { readOnlyHint: true },
  }, async ({ binary_id, identifier, relation, offset, limit }) =>
    result(client.requestJson("/agent/relatedFunctions",
      { binaryId: binary_id, identifier, relation, offset, limit })));

  server.registerTool("function_il", {
    description: "Read a page of HLIL, MLIL or LLIL with addresses. SSA is available for MLIL and LLIL. Continue with next_offset.",
    inputSchema: { binary_id: binaryId, identifier,
      view: z.enum(["hlil", "mlil", "llil"]).default("hlil"),
      ssa: z.boolean().default(false), offset,
      limit: z.number().int().min(1).max(200).default(80) },
    outputSchema: z.object({ binary_id: z.string(), function: z.object({ name: z.string(), address: z.string() }).passthrough(),
      view: z.string(), ssa: z.boolean(), lines: z.array(z.string()), ...page }),
    annotations: { readOnlyHint: true },
  }, async ({ binary_id, identifier, view, ssa, offset, limit }) =>
    result(client.requestJson("/agent/il", { binaryId: binary_id, identifier, view, ssa, offset, limit })));

  server.registerTool("decompile_function", {
    description: "Page rendered Pseudo C for a function, falling back to address-prefixed HLIL if Pseudo C rendering is unavailable.",
    inputSchema: { binary_id: binaryId, identifier, offset,
      limit: z.number().int().min(1).max(200).default(80) },
    outputSchema: z.object({ binary_id: z.string(), function: functionSummary,
      representation: z.enum(["pseudo_c", "hlil"]), lines: z.array(z.string()), ...page }),
    annotations: { readOnlyHint: true },
  }, async ({ binary_id, identifier, offset, limit }) =>
    result(client.requestJson("/agent/decompile",
      { binaryId: binary_id, identifier, offset, limit })));

  server.registerTool("disassemble_function", {
    description: "Page native disassembly lines with virtual addresses for a function.",
    inputSchema: { binary_id: binaryId, identifier, offset,
      limit: z.number().int().min(1).max(200).default(80) },
    outputSchema: z.object({ binary_id: z.string(), function: functionSummary,
      lines: z.array(z.string()), ...page }),
    annotations: { readOnlyHint: true },
  }, async ({ binary_id, identifier, offset, limit }) =>
    result(client.requestJson("/agent/disassembly",
      { binaryId: binary_id, identifier, offset, limit })));

  server.registerTool("basic_blocks", {
    description: "Page a function's CFG blocks with address ranges, exit state, and outgoing branch edges.",
    inputSchema: { binary_id: binaryId, identifier, offset, limit },
    outputSchema: z.object({ binary_id: z.string(), function: functionSummary,
      blocks: z.array(z.object({ index: z.number().int(), start: z.string(), end: z.string(),
        length: z.number().int(), instruction_count: z.number().int(), can_exit: z.boolean(),
        has_undetermined_outgoing_edges: z.boolean(),
        outgoing_edges: z.array(z.object({ type: z.string(), target: z.string().nullable(),
          fall_through: z.boolean(), back_edge: z.boolean() })) })), ...page }),
    annotations: { readOnlyHint: true },
  }, async ({ binary_id, identifier, offset, limit }) =>
    result(client.requestJson("/agent/basicBlocks",
      { binaryId: binary_id, identifier, offset, limit })));

  server.registerTool("stack_frame", {
    description: "Page a function's stack variables with names, storage offsets, sizes, and types.",
    inputSchema: { binary_id: binaryId, identifier, offset, limit },
    outputSchema: z.object({ binary_id: z.string(), function: functionSummary,
      variables: z.array(z.object({ name: z.string(), offset: z.string(),
        size: z.string(), type: z.string() })), ...page }),
    annotations: { readOnlyHint: true },
  }, async ({ binary_id, identifier, offset, limit }) =>
    result(client.requestJson("/agent/stackFrame",
      { binaryId: binary_id, identifier, offset, limit })));

  server.registerTool("xrefs_to", {
    description: "Page inbound code and/or data references to an address. Each code reference includes its containing function when known.",
    inputSchema: { binary_id: binaryId, address, offset, limit,
      include_code: z.boolean().default(true), include_data: z.boolean().default(true) },
    outputSchema: z.object({ binary_id: z.string(), target: z.object({ address: z.string() }),
      references: z.array(z.object({ kind: z.enum(["code", "data"]),
        address: z.string().nullable(), function: z.string().nullable().optional(),
        function_start: z.string().nullable().optional() })), ...page }),
    annotations: { readOnlyHint: true },
  }, async ({ binary_id, address, offset, limit, include_code, include_data }) =>
    result(client.requestJson("/agent/xrefs", { binaryId: binary_id, address, offset, limit,
      includeCode: include_code, includeData: include_data })));

  server.registerTool("read_bytes", {
    description: "Read at most 4096 bytes at a virtual address. Returns hex and reports partial reads.",
    inputSchema: { binary_id: binaryId, address,
      length: z.number().int().min(1).max(4096).default(256) },
    outputSchema: z.object({ binary_id: z.string(), address: z.string(), requested_length: z.number().int(),
      actual_length: z.number().int(), hex: z.string(), partial: z.boolean() }),
    annotations: { readOnlyHint: true },
  }, async ({ binary_id, address, length }) => result(client.requestJson("/agent/bytes",
    { binaryId: binary_id, address, length })));

  server.registerTool("read_comment", {
    description: "Read the address comment before a conditional update.",
    inputSchema: { binary_id: binaryId, address },
    outputSchema: z.object({ binary_id: z.string(), address: z.string(), comment: z.string().nullable() }),
    annotations: { readOnlyHint: true },
  }, async ({ binary_id, address }) => result(client.requestJson("/agent/comment",
    { binaryId: binary_id, address })));

  server.registerTool("rename_function", {
    description: "Rename a function at its exact start address only if its current name equals expected_name. Fails on stale observations.",
    inputSchema: { binary_id: binaryId, address,
      expected_name: z.string().min(1), new_name: z.string().min(1).max(256) },
    outputSchema: z.object({ binary_id: z.string(), success: z.literal(true), action: z.literal("rename_function"),
      address: z.string(), old_name: z.string(), new_name: z.string() }),
    annotations: { readOnlyHint: false, destructiveHint: false },
  }, async ({ binary_id, address, expected_name, new_name }) =>
    result(client.postJsonStrict("/agent/annotate",
      { binary_id, action: "rename_function", address, expected_name, new_name })));

  server.registerTool("set_comment", {
    description: "Set an address comment only if it equals expected_comment. Read it first with read_comment. Pass null if absent.",
    inputSchema: { binary_id: binaryId, address,
      expected_comment: z.string().nullable(), comment: z.string().max(16000) },
    outputSchema: z.object({ binary_id: z.string(), success: z.literal(true), action: z.literal("set_comment"),
      address: z.string(), comment: z.string() }),
    annotations: { readOnlyHint: false, destructiveHint: false },
  }, async ({ binary_id, address, expected_comment, comment }) =>
    result(client.postJsonStrict("/agent/annotate",
      { binary_id, action: "set_comment", address, expected_comment, comment })));

  server.registerTool("entry_points", {
    description: "List executable entry points in the selected binary.",
    inputSchema: { binary_id: binaryId },
    outputSchema: z.object({ binary_id: z.string(), entry_points: z.array(z.record(z.unknown())) }),
    annotations: { readOnlyHint: true },
  }, async ({ binary_id }) => result(client.requestJson("/agent/entryPoints", { binaryId: binary_id })));

  server.registerTool("memory_map", {
    description: "Page segments or sections with address ranges and available permissions or metadata.",
    inputSchema: { binary_id: binaryId,
      kind: z.enum(["segments", "sections"]), offset, limit },
    outputSchema: z.object({ binary_id: z.string(),
      kind: z.enum(["segments", "sections"]),
      regions: z.array(z.object({ name: z.string().nullable(),
        start: z.string(), end: z.string() }).passthrough()), ...page }),
    annotations: { readOnlyHint: true },
  }, async ({ binary_id, kind, offset, limit }) => result(client.requestJson("/agent/memoryMap",
    { binaryId: binary_id, kind, offset, limit })));

  for (const kind of ["imports", "exports"] as const) {
    server.registerTool(`list_${kind}`, {
      description: `Page ${kind} in the selected binary. Continue with next_offset.`,
      inputSchema: { binary_id: binaryId, offset, limit },
      outputSchema: z.object({ binary_id: z.string(), [kind]: z.array(namedAddress), ...page }),
      annotations: { readOnlyHint: true },
    }, async ({ binary_id, offset, limit }) => result(client.requestJson(`/agent/${kind}`,
      { binaryId: binary_id, offset, limit })));
  }
}
