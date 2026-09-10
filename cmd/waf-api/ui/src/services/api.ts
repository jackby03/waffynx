export type Status = { go_version: string; goroutines: number };
export type Metrics = { go: { heap_alloc: number; goroutines: number } };
export type Plugin = { name: string; version: string; description: string };
export type WafEvent = { type: string; timestamp: string; method: string; path: string; remote_ip: string; rule_id: string; reason: string };
let token: string | null = null;
const base = "";
export function getToken() { return token; }
export function setToken(value: string) { token = value; }
export function clearToken() { token = null; }
async function request<T>(path: string, init?: RequestInit): Promise<T> { const headers = new Headers(init?.headers); headers.set("Accept", "application/json"); if (token) headers.set("Authorization", `Bearer ${token}`); const response = await fetch(`${base}${path}`, { ...init, headers }); if (response.status === 401) { clearToken(); throw new Error("unauthorized"); } if (!response.ok) throw new Error(`API request failed (${response.status})`); return response.json() as Promise<T>; }
export const api = { login: (username: string, password: string) => request<{ token: string }>("/api/v1/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username, password }) }), status: () => request<Status>("/api/v1/status"), metrics: () => request<Metrics>("/api/v1/metrics"), plugins: () => request<Plugin[]>("/api/v1/plugins") };
