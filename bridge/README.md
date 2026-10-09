# Local MCP bridge

From this directory, run `npm ci` and `npm run build`. Configure an MCP client to start `node` with the absolute path to `dist/index.js` as its argument. The bridge connects to a running Binary Ninja plugin at `127.0.0.1:9009`.

If HTTP authentication is configured in Binary Ninja, set `BINJA_MCP_TOKEN` in the bridge environment to the same token. The bridge sends it in the Authorization header and bypasses HTTP proxy environment variables for its direct local connection.

The 21 tools and their limits are documented in the [repository README](../README.md). This bridge is local development code and is not published to npm.
