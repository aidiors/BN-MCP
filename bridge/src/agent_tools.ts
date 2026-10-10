
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
const functionDetails = z.object({ name: z.string(), raw_name: z.string(), address: z.string(),
  symbol: z.object({ type: z.string(), full_name: z.string().nullable() }).nullable(),
  signature: z.string().nullable(), return_type: z.string().nullable(), calling_convention: z.string().nullable(),
  parameters: z.array(z.object({ name: z.string().nullable(), type: z.string().nullable() })),
  parameters_truncated: z.boolean(), ranges: z.array(z.object({ start: z.string().nullable(), end: z.string().nullable() })),
  ranges_truncated: z.boolean(), total_bytes: z.number().nullable(), is_thunk: z.boolean(),
  analysis_skipped: z.boolean(), revision: z.string() });
const variableSummary = z.object({ id: z.string(), name: z.string().nullable(), type: z.string().nullable(),
  size: z.number().nullable(), storage: z.string(), source: z.string(), parameter: z.boolean(), revision: z.string() });
const variablesPage = z.object({ function: functionSummary, variables: z.array(variableSummary), ...page });
const possibleValues = z.object({ kind: z.string(), value: z.string().nullable().optional(),
  unavailable_reason: z.string().optional(),
  values: z.array(z.string().nullable()).optional(),
  ranges: z.array(z.object({ start: z.string(), end: z.string(), step: z.string() })).optional(),
  truncated: z.boolean().optional() });
const callsPage = z.object({ function: functionSummary, direction: z.enum(["outgoing", "incoming"]),
  calls: z.array(z.object({ address: z.string().nullable(), caller: functionSummary,
    il_index: z.number().nullable(), il: z.literal("mlil"), text: z.string().nullable(),
    target: z.string().nullable(), target_name: z.string().nullable(), target_values: possibleValues,
    arguments: z.array(z.object({ index: z.number().int(), expression: z.string().nullable(), possible_values: possibleValues })),
    arguments_truncated: z.boolean(), unavailable_reason: z.string().nullable() })), ...page });
const analysisStatus = z.object({ state: z.string(), ready: z.boolean(), completed: z.number().nullable(), total: z.number().nullable() });
const codeRecord = z.object({ text: z.string(), text_truncated: z.boolean(), address: z.string().nullable(),
  il_index: z.number().nullable(), line_index: z.number().int() });
const decompiledPage = z.object({ function: functionSummary, representation: z.enum(["pseudo_c", "hlil"]),
  lines: z.array(z.string()), records: z.array(codeRecord), ...page });
const expectedRevision = z.string().length(64).describe("Revision from the latest read. A mismatch rejects the edit.");

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
    inputSchema: { binary_id: binaryId, query: z.string().default(""), offset, limit,
      include_refs: z.boolean().default(false), ref_limit: z.number().int().min(1).max(20).default(5) },
    outputSchema: z.object({ binary_id: z.string(), strings: z.array(z.object({ address: z.string().nullable(),
      length: z.number().nullable(), type: z.string(), value: z.string(),
      value_truncated: z.boolean(), references: z.array(z.record(z.unknown())).optional(),
      references_truncated: z.boolean().optional() })), query: z.string(), ...page }),
    annotations: { readOnlyHint: true },
  }, async ({ binary_id, query, offset, limit, include_refs, ref_limit }) => result(client.requestJson("/agent/strings",
    { binaryId: binary_id, query, offset, limit, includeRefs: include_refs, refLimit: ref_limit })));

  server.registerTool("inspect_function", {
    description: "Read function identity, signature, parameters, ranges and revision by name or start address. Use revision for checked prototype edits.",
    inputSchema: { binary_id: binaryId, identifier },
    outputSchema: functionDetails.extend({ binary_id: z.string() }),
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
    outputSchema: decompiledPage.extend({ binary_id: z.string() }),
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

  server.registerTool("analysis_status", {
    description: "Read analysis state without waiting behind code queries. Poll ready after changing types or variables.",
    inputSchema: { binary_id: binaryId },
    outputSchema: analysisStatus.extend({ binary_id: z.string() }),
    annotations: { readOnlyHint: true },
  }, async ({ binary_id }) => result(client.requestJson("/agent/analysisStatus", { binaryId: binary_id })));

  server.registerTool("function_context", {
    description: "Read selected function context in one request. Each section has pagination. max_chars bounds serialized context. Continue shortened sections with their dedicated tools.",
    inputSchema: { binary_id: binaryId, identifier,
      include: z.array(z.enum(["decompile", "calls", "variables", "callers"])).min(1).max(4).default(["decompile", "calls", "variables"]),
      line_limit: z.number().int().min(1).max(200).default(80),
      item_limit: z.number().int().min(1).max(100).default(20),
      max_chars: z.number().int().min(2048).max(65536).default(32768) },
    outputSchema: z.object({ binary_id: z.string(), function: functionDetails,
      sections: z.object({ decompile: decompiledPage.optional(), calls: callsPage.optional(),
        variables: variablesPage.optional(), callers: z.object({ function: namedAddress, relation: z.literal("callers"),
          functions: z.array(namedAddress), ...page }).optional() }),
      unavailable: z.record(z.string()), analysis: analysisStatus, budget_truncated: z.boolean() }),
    annotations: { readOnlyHint: true },
  }, async ({ binary_id, identifier, include, line_limit, item_limit, max_chars }) =>
    result(client.requestJson("/agent/functionContext", { binaryId: binary_id, identifier, include: include.join(","),
      lineLimit: line_limit, itemLimit: item_limit, maxChars: max_chars })));

  server.registerTool("call_sites", {
    description: "Read incoming or outgoing call sites with MLIL argument expressions and known possible values. Unknown targets remain unresolved. Continue with next_offset.",
    inputSchema: { binary_id: binaryId, identifier, direction: z.enum(["outgoing", "incoming"]).default("outgoing"), offset, limit },
    outputSchema: callsPage.extend({ binary_id: z.string() }),
    annotations: { readOnlyHint: true },
  }, async ({ binary_id, identifier, direction, offset, limit }) => result(client.requestJson("/agent/callSites",
    { binaryId: binary_id, identifier, direction, offset, limit })));

  server.registerTool("function_variables", {
    description: "Read local and parameter variables with IDs, types and revisions. Use the ID and revision for checked variable edits.",
    inputSchema: { binary_id: binaryId, identifier, offset, limit },
    outputSchema: variablesPage.extend({ binary_id: z.string() }),
    annotations: { readOnlyHint: true },
  }, async ({ binary_id, identifier, offset, limit }) => result(client.requestJson("/agent/variables",
    { binaryId: binary_id, identifier, offset, limit })));

  server.registerTool("inspect_type", {
    description: "Read a named type definition and revision. A missing type returns found=false and revision=null. Continue definition lines with next_offset.",
    inputSchema: { binary_id: binaryId, name: z.string().min(1).max(256), offset, limit },
    outputSchema: z.object({ binary_id: z.string(), name: z.string(), found: z.boolean(), type: z.string().nullable(),
      size: z.number().nullable(), alignment: z.number().nullable(), revision: z.string().nullable(), lines: z.array(z.string()), ...page }),
    annotations: { readOnlyHint: true },
  }, async ({ binary_id, name, offset, limit }) => result(client.requestJson("/agent/type", { binaryId: binary_id, name, offset, limit })));

  server.registerTool("edit_variable", {
    description: "Change a variable name, type or both using its ID and current revision. The edit is undoable and requests analysis. Read variables again after analysis.",
    inputSchema: { binary_id: binaryId, address, variable_id: z.string().min(1).max(64), expected_revision: expectedRevision,
      new_name: z.string().min(1).max(256).optional(), new_type: z.string().min(1).max(4096).optional() },
    outputSchema: z.object({ binary_id: z.string(), success: z.literal(true), action: z.literal("edit_variable"), address: z.string(),
      previous: variableSummary, variable_id: z.string(), requested_name: z.string(), requested_type: z.string().nullable(),
      analysis_requested: z.literal(true) }),
    annotations: { readOnlyHint: false, destructiveHint: false },
  }, async (args) => result(client.postJsonStrict("/agent/annotate", { ...args, action: "edit_variable" })));

  server.registerTool("set_function_type", {
    description: "Apply a C function prototype if the revision from inspect_function still matches. The edit is undoable and requests analysis. Function names are unchanged.",
    inputSchema: { binary_id: binaryId, address, expected_revision: expectedRevision, declaration: z.string().min(1).max(8192) },
    outputSchema: z.object({ binary_id: z.string(), success: z.literal(true), action: z.literal("set_function_type"), address: z.string(),
      previous: z.object({ signature: z.string().nullable(), revision: z.string() }), requested_signature: z.string().nullable(),
      analysis_requested: z.literal(true) }),
    annotations: { readOnlyHint: false, destructiveHint: false },
  }, async (args) => result(client.postJsonStrict("/agent/annotate", { ...args, action: "set_function_type" })));

  server.registerTool("define_type", {
    description: "Create or replace exactly one named C type. Use the revision from inspect_type, or null if absent. The edit is undoable and requests analysis.",
    inputSchema: { binary_id: binaryId, name: z.string().min(1).max(256), declaration: z.string().min(1).max(16384),
      expected_revision: expectedRevision.nullable() },
    outputSchema: z.object({ binary_id: z.string(), success: z.literal(true), action: z.literal("define_type"), name: z.string(),
      previous_revision: z.string().nullable(), revision: z.string(), analysis_requested: z.literal(true) }),
    annotations: { readOnlyHint: false, destructiveHint: false },
  }, async (args) => result(client.postJsonStrict("/agent/annotate", { ...args, action: "define_type" })));
}
