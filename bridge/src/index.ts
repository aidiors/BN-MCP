#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createClient } from "./client.js";
import { registerAgentTools } from "./agent_tools.js";


function parseArgs(): { host: string; port: number } {
  const args = process.argv.slice(2);
  let host = "localhost";
  let port = 9009;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    switch (arg) {
      case "--host":
        if (i + 1 < args.length) {
          host = args[++i];
        }
        break;
      case "--port":
        if (i + 1 < args.length) {
          port = parseInt(args[++i], 10);
        }
        break;
      case "--help":
      case "-h":
        console.log(`Binary Ninja MCP Server

Usage: node dist/index.js [options]

Options:
  --host <host>     Binary Ninja MCP server host (default: localhost)
  --port <port>     Binary Ninja MCP server port (default: 9009)
  --help, -h        Show this help message

Environment variables:
  BINJA_MCP_HOST    Binary Ninja MCP server host
  BINJA_MCP_PORT    Binary Ninja MCP server port
`);
        process.exit(0);
        break;
    }
  }


  if (process.env.BINJA_MCP_HOST) {
    host = process.env.BINJA_MCP_HOST;
  }
  if (process.env.BINJA_MCP_PORT) {
    port = Number(process.env.BINJA_MCP_PORT);
  }

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("port must be an integer from 1 to 65535");
  }

  return { host, port };
}


async function main(): Promise<void> {
  const { host, port } = parseArgs();

  console.error(`Binary Ninja MCP Server connecting to ${host}:${port}`);


  const server = new McpServer({
    name: "binary-ninja-mcp-agent",
    version: "2.0.0-dev.1",
  });


  const client = createClient(host, port);


  registerAgentTools(server, client);


  const transport = new StdioServerTransport();


  await server.connect(transport);
  console.error("Binary Ninja MCP Server ready");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
