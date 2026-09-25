# Local MCP bridge

From this directory, run `npm ci` and `npm run build`. Configure an MCP client to start `node` with the absolute path to `dist/index.js` as its argument. The bridge connects to a running Binary Ninja plugin at `localhost:9009`.

The 21 tools and their limits are documented in the [repository README](../README.md). This bridge is local development code and is not published to npm.
