
import axios, { AxiosInstance } from "axios";

export interface BinjaServerConfig {
  host: string;
  port: number;
  authToken?: string;
}

export class BinjaHttpClient {
  private client: AxiosInstance;

  constructor(config: BinjaServerConfig) {
    this.client = axios.create({
      baseURL: `http://${config.host}:${config.port}`,
      timeout: 30000,
      proxy: false,
      headers: config.authToken ? { Authorization: `Bearer ${config.authToken}` } : {},
    });
  }

  private async request<T extends Record<string, unknown>>(
    endpoint: string, method: "GET" | "POST",
    params: Record<string, string | number | boolean> = {},
    body?: Record<string, unknown>, timeout = 30000,
  ): Promise<T> {
    let data: unknown;
    try {
      const response = await this.client.request({ url: endpoint, method, params,
        data: body, timeout });
      data = response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const detail = error.response?.data;
        const message = detail && typeof detail === "object" && "error" in detail
          ? String(detail.error) : error.message;
        const status = error.response?.status ? `HTTP ${error.response.status} ` : "";
        const current = detail && typeof detail === "object" && "current" in detail
          ? `. Current value: ${JSON.stringify(detail.current)}` : "";
        throw new Error(`${status}${method} ${endpoint}: ${message}${current}`);
      }
      throw error;
    }
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      throw new Error(`${method} ${endpoint}: expected a JSON object`);
    }
    if ("error" in data) {
      throw new Error(`${method} ${endpoint}: ${String(data.error)}`);
    }
    return data as T;
  }

  requestJson<T extends Record<string, unknown>>(
    endpoint: string, params: Record<string, string | number | boolean> = {},
    timeout = 30000,
  ): Promise<T> {
    return this.request(endpoint, "GET", params, undefined, timeout);
  }

  postJsonStrict<T extends Record<string, unknown>>(
    endpoint: string, body: Record<string, unknown>,
  ): Promise<T> {
    return this.request(endpoint, "POST", {}, body);
  }
}

export function createClient(host = "127.0.0.1", port = 9009): BinjaHttpClient {
  return new BinjaHttpClient({ host, port, authToken: process.env.BINJA_MCP_TOKEN });
}
