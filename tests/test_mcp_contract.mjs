import assert from "node:assert/strict";
import { test } from "node:test";
import { McpServer } from "../bridge/node_modules/@modelcontextprotocol/sdk/dist/esm/server/mcp.js";
import { Client } from "../bridge/node_modules/@modelcontextprotocol/sdk/dist/esm/client/index.js";
import { InMemoryTransport } from "../bridge/node_modules/@modelcontextprotocol/sdk/dist/esm/inMemory.js";
import { registerAgentTools } from "../bridge/dist/agent_tools.js";
import { BinjaHttpClient } from "../bridge/dist/client.js";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { once } from "node:events";
import { fileURLToPath } from "node:url";

test("agent tools expose schemas, structured results, and MCP errors", async () => {
  const requests = [];
  const functionDetails = { name: "entry", raw_name: "entry", address: "0x1000", symbol: null,
    signature: "int32_t()", return_type: "int32_t", calling_convention: null, parameters: [],
    parameters_truncated: false, ranges: [], ranges_truncated: false, total_bytes: 1,
    is_thunk: false, analysis_skipped: false, revision: "0".repeat(64) };
  const fakeHttp = {
    async requestJson(endpoint, params = {}) {
      requests.push({ endpoint, params });
      if (endpoint === "/agent/function") {
        if (params.identifier === "missing") throw new Error("Function not found");
        return { binary_id: params.binaryId, ...functionDetails };
      }
      if (endpoint === "/agent/functions") return {
        binary_id: params.binaryId, functions: [{ name: "entry", address: "0x1000" }],
        query: params.query, offset: params.offset, limit: params.limit,
        next_offset: null, truncated: false,
      };
      if (endpoint === "/binaries") return { binaries: [] };
      const base = { binary_id: params.binaryId };
      const page = { offset: params.offset, limit: params.limit,
        next_offset: null, truncated: false };
      if (endpoint === "/agent/decompile") return { ...base, ...page,
        function: { name: "entry", address: "0x1000" }, representation: "pseudo_c", lines: ["return 1;"],
        records: [{ text: "return 1;", text_truncated: false, address: "0x1000", il_index: null, line_index: 0 }] };
      if (endpoint === "/agent/disassembly") return { ...base, ...page,
        function: { name: "entry", address: "0x1000" }, lines: ["00001000 ret"] };
      if (endpoint === "/agent/basicBlocks") return { ...base, ...page,
        function: { name: "entry", address: "0x1000" }, blocks: [] };
      if (endpoint === "/agent/stackFrame") return { ...base, ...page,
        function: { name: "entry", address: "0x1000" }, variables: [] };
      if (endpoint === "/agent/identity") return { ...base, loaded: true, view_id: "7",
        database_path: null, original_path: null, architecture: "x86_64",
        view_type: "PE", view_start: "0x1000", view_end: "0x2000",
        original_sha256: null, hash_status: "not_requested" };
      if (endpoint === "/agent/strings") return { ...base, ...page, query: params.query,
        strings: [{ address: "0x1200", length: 4, type: "Ascii", value: "test",
          value_truncated: false }] };
      if (endpoint === "/agent/functionAt") return { ...base, address: params.address,
        functions: [{ name: "entry", address: "0x1000" }] };
      if (endpoint === "/agent/relatedFunctions") return { ...base, ...page,
        function: { name: "entry", address: "0x1000" }, relation: params.relation,
        functions: [] };
      if (endpoint === "/agent/il") return { ...base, ...page,
        function: { name: "entry", address: "0x1000" }, view: params.view,
        ssa: params.ssa, lines: ["00001000        return"] };
      if (endpoint === "/agent/xrefs") return { ...base, ...page,
        target: { address: params.address }, references: [{ kind: "data", address: "0x1100" }] };
      if (endpoint === "/agent/bytes") return { ...base, address: params.address,
        requested_length: params.length, actual_length: 1, hex: "90", partial: true };
      if (endpoint === "/agent/comment") return { ...base, address: params.address, comment: null };
      if (endpoint === "/agent/entryPoints") return { ...base, entry_points: [] };
      if (endpoint === "/agent/memoryMap") return { ...base, ...page, kind: params.kind,
        regions: [{ name: ".text", start: "0x1000", end: "0x2000" }] };
      if (endpoint === "/agent/imports") return { ...base, ...page, imports: [] };
      if (endpoint === "/agent/exports") return { ...base, ...page, exports: [] };
      throw new Error(`unexpected endpoint: ${endpoint}`);
    },
    async postJsonStrict(endpoint, body) {
      assert.equal(endpoint, "/agent/annotate");
      return body.action === "rename_function"
        ? { binary_id: body.binary_id, success: true, action: body.action,
            address: body.address, old_name: body.expected_name, new_name: body.new_name }
        : { binary_id: body.binary_id, success: true, action: body.action,
            address: body.address, comment: body.comment };
    },
  };
  const server = new McpServer({ name: "test-bn", version: "1" });
  registerAgentTools(server, fakeHttp);
  const client = new Client({ name: "test-client", version: "1" });
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  try {
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    const listed = await client.listTools();
    assert.equal(listed.tools.length, 29);
    for (const name of ["analysis_status", "function_context", "call_sites", "function_variables",
      "inspect_type", "edit_variable", "set_function_type", "define_type"]) {
      const tool = listed.tools.find(tool => tool.name === name);
      assert.ok(tool?.inputSchema.properties.binary_id, `${name} lacks binary binding`);
      assert.ok(tool.outputSchema, `${name} lacks output schema`);
    }
    const functions = listed.tools.find(tool => tool.name === "find_functions");
    assert.ok(functions.inputSchema.properties.binary_id);
    assert.ok(functions.outputSchema.properties.functions);
    const good = await client.callTool({ name: "find_functions", arguments: { binary_id: "7" } });
    assert.equal(good.isError, undefined);
    assert.equal(good.structuredContent.binary_id, "7");
    assert.equal(requests.at(-1).params.limit, 100);
    const successCases = [
      ["list_binaries", {}],
      ["binary_info", { binary_id: "7" }],
      ["find_strings", { binary_id: "7" }],
      ["function_at", { binary_id: "7", address: "0x1000" }],
      ["related_functions", { binary_id: "7", identifier: "entry", relation: "callers" }],
      ["function_il", { binary_id: "7", identifier: "entry" }],
      ["inspect_function", { binary_id: "7", identifier: "entry" }],
      ["decompile_function", { binary_id: "7", identifier: "entry" }],
      ["disassemble_function", { binary_id: "7", identifier: "entry" }],
      ["basic_blocks", { binary_id: "7", identifier: "entry" }],
      ["stack_frame", { binary_id: "7", identifier: "entry" }],
      ["xrefs_to", { binary_id: "7", address: "0x1000" }],
      ["read_bytes", { binary_id: "7", address: "0x1000" }],
      ["read_comment", { binary_id: "7", address: "0x1000" }],
      ["entry_points", { binary_id: "7" }],
      ["memory_map", { binary_id: "7", kind: "sections" }],
      ["list_imports", { binary_id: "7" }],
      ["list_exports", { binary_id: "7" }],
      ["rename_function", { binary_id: "7", address: "0x1000",
        expected_name: "entry", new_name: "start" }],
      ["set_comment", { binary_id: "7", address: "0x1000",
        expected_comment: null, comment: "checked" }],
    ];
    for (const [name, args] of successCases) {
      const response = await client.callTool({ name, arguments: args });
      assert.notEqual(response.isError, true, `${name} returned an error`);
      assert.ok(response.structuredContent, `${name} lacks structured content`);
    }
    const bad = await client.callTool({ name: "inspect_function",
      arguments: { binary_id: "7", identifier: "missing" } });
    assert.equal(bad.isError, true);
    assert.match(bad.content[0].text, /Function not found/);
  } finally {
    await client.close();
    await server.close();
  }
});

test("all 29 MCP tools cross the real TypeScript HTTP client and Python backend", { timeout: 15000 }, async () => {
  const fixtureProcess = spawn(process.env.PYTHON ?? "python", ["-u", fileURLToPath(new URL("agent_http_fixture.py", import.meta.url))],
    { stdio: ["pipe", "pipe", "pipe"] });
  const exited = once(fixtureProcess, "exit");
  let stderr = "";
  fixtureProcess.stderr.setEncoding("utf8").on("data", chunk => { stderr += chunk; });
  const lines = createInterface({ input: fixtureProcess.stdout });
  const server = new McpServer({ name: "integration-bn", version: "1" });
  const client = new Client({ name: "integration-client", version: "1" });
  try {
    const line = await Promise.race([once(lines, "line").then(([value]) => value),
      exited.then(() => { throw new Error(`Python fixture exited: ${stderr}`); })]);
    const { port, view_id: binary_id } = JSON.parse(line);
    registerAgentTools(server, new BinjaHttpClient({ host: "127.0.0.1", port, authToken: "test-only-token" }));
    const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    const calls = [
      ["list_binaries", {}], ["binary_info", { binary_id }],
      ["find_functions", { binary_id }], ["find_strings", { binary_id }],
      ["inspect_function", { binary_id, identifier: "sub_1000" }],
      ["function_at", { binary_id, address: "0x1001" }],
      ["related_functions", { binary_id, identifier: "0x1000", relation: "callers" }],
      ["function_il", { binary_id, identifier: "0x1000" }],
      ["decompile_function", { binary_id, identifier: "0x1000" }],
      ["disassemble_function", { binary_id, identifier: "0x1000" }],
      ["basic_blocks", { binary_id, identifier: "0x1000" }],
      ["stack_frame", { binary_id, identifier: "0x1000" }],
      ["xrefs_to", { binary_id, address: "0x1000" }],
      ["read_bytes", { binary_id, address: "0x1000" }],
      ["read_comment", { binary_id, address: "0x1000" }],
      ["entry_points", { binary_id }], ["memory_map", { binary_id, kind: "sections" }],
      ["list_imports", { binary_id }], ["list_exports", { binary_id }],
      ["rename_function", { binary_id, address: "0x1000", expected_name: "sub_1000", new_name: "renamed" }],
      ["set_comment", { binary_id, address: "0x1000", expected_comment: null, comment: "checked" }],
      ["analysis_status", { binary_id }],
      ["function_context", { binary_id, identifier: "0x1000", include: ["decompile", "calls", "variables", "callers"] }],
      ["call_sites", { binary_id, identifier: "0x1000" }],
      ["function_variables", { binary_id, identifier: "0x1000" }],
      ["inspect_type", { binary_id, name: "Record" }],
    ];
    assert.equal(calls.length, 26);
    for (const [name, args] of calls) {
      const response = await client.callTool({ name, arguments: args });
      assert.notEqual(response.isError, true, `${name}: ${JSON.stringify(response.content)}`);
      assert.ok(response.structuredContent, `${name} lacks structured content`);
      if (name !== "list_binaries") assert.equal(response.structuredContent.binary_id, binary_id);
    }
    const variables = (await client.callTool({ name: "function_variables", arguments: { binary_id, identifier: "0x1000" } })).structuredContent.variables;
    const variable = variables[0];
    const edit = await client.callTool({ name: "edit_variable", arguments: {
      binary_id, address: "0x1000", variable_id: variable.id, expected_revision: variable.revision,
      new_name: "length", new_type: "uint64_t" } });
    assert.notEqual(edit.isError, true, JSON.stringify(edit.content));
    assert.equal(edit.structuredContent.requested_name, "length");
    const stale = await client.callTool({ name: "edit_variable", arguments: {
      binary_id, address: "0x1000", variable_id: variable.id, expected_revision: variable.revision, new_name: "stale" } });
    assert.equal(stale.isError, true);
    assert.match(stale.content[0].text, /409/);
    const info = (await client.callTool({ name: "inspect_function", arguments: { binary_id, identifier: "0x1000" } })).structuredContent;
    const prototype = await client.callTool({ name: "set_function_type", arguments: {
      binary_id, address: "0x1000", expected_revision: info.revision, declaration: "int parse(char *buffer)" } });
    assert.notEqual(prototype.isError, true, JSON.stringify(prototype.content));
    const definition = await client.callTool({ name: "define_type", arguments: {
      binary_id, name: "Record", expected_revision: null, declaration: "struct Record { int length; };" } });
    assert.notEqual(definition.isError, true, JSON.stringify(definition.content));
    const type = (await client.callTool({ name: "inspect_type", arguments: { binary_id, name: "Record" } })).structuredContent;
    assert.equal(type.found, true);
    assert.equal(type.revision, definition.structuredContent.revision);
    const stringRefs = await client.callTool({ name: "find_strings", arguments: { binary_id, include_refs: true } });
    assert.ok(Array.isArray(stringRefs.structuredContent.strings[0].references));
    const conflict = await client.callTool({ name: "set_comment", arguments: {
      binary_id, address: "0x1000", expected_comment: null, comment: "stale" } });
    assert.equal(conflict.isError, true);
    assert.match(conflict.content[0].text, /409/);
  } finally {
    await client.close();
    await server.close();
    lines.close();
    fixtureProcess.stdin.end();
    const timer = setTimeout(() => fixtureProcess.kill(), 3000);
    await exited;
    clearTimeout(timer);
  }
});
