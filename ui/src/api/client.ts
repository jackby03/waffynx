import { getStoredSession } from "./session";

/**
 * The one HTTP door to the control plane.
 *
 * Three behaviours here are load-bearing and were each a real bug:
 *   1. 204 answers have no body, so `res.json()` must not run.
 *   2. The API's error envelope is `{"error": "...", "message": "..."}`, and
 *      showing the bare status code hides what actually went wrong.
 *   3. A 401 has to reach the app so it can send the user to the login screen,
 *      instead of every view rendering "HTTP 401" forever.
 */
export class ApiError extends Error {
  readonly status: number;
  /** Server-provided code, when the envelope carries one. */
  readonly code?: string;

  constructor(status: number, message: string, code?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }

  /** True when the request failed because the session is missing or expired. */
  get isUnauthorized(): boolean {
    return this.status === 401 || this.status === 403;
  }

  /** True when the backend does not implement the endpoint (optional features). */
  get isMissing(): boolean {
    return this.status === 404 || this.status === 501;
  }
}

type UnauthorizedHandler = () => void;

let onUnauthorized: UnauthorizedHandler = () => {};

/** Registers the handler invoked once per failed request with a 401. */
export function setUnauthorizedHandler(handler: UnauthorizedHandler): void {
  onUnauthorized = handler;
}

/** Thrown by callers that tolerate a 404 and want to fall back. */
export function isMissingEndpoint(err: unknown): boolean {
  return err instanceof ApiError && err.isMissing;
}

const BASE_URL = "";

function messageFromBody(body: unknown, res: Response): string {
  if (body && typeof body === "object") {
    const record = body as Record<string, unknown>;
    const message = typeof record.message === "string" ? record.message : "";
    const error = typeof record.error === "string" ? record.error : "";
    // The API often sends the same text twice ("error" + "message"); prefer the
    // longer, more specific one instead of printing it twice.
    if (message && error && message !== error) return `${error}: ${message}`;
    if (message) return message;
    if (error) return error;
  }
  if (typeof body === "string" && body.trim() !== "") {
    return body.trim().slice(0, 300);
  }
  return res.statusText || `HTTP ${res.status}`;
}

export async function apiFetch<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const session = getStoredSession();
  const headers = new Headers(options.headers ?? {});

  if (session?.token && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${session.token}`);
  }
  if (options.body !== undefined && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  headers.set("Accept", "application/json");

  let res: Response;
  try {
    res = await fetch(`${BASE_URL}${endpoint}`, { ...options, headers });
  } catch {
    // fetch only rejects on transport errors: DNS, connection refused, CORS.
    // Saying so beats a bare "Failed to fetch" in a table cell.
    throw new ApiError(0, "Control plane unreachable", "unreachable");
  }

  if (res.status === 401) {
    onUnauthorized();
  }

  if (!res.ok) {
    let body: unknown = null;
    try {
      const text = await res.text();
      body = text === "" ? null : JSON.parse(text);
    } catch {
      // Non-JSON error bodies are still worth showing, so fall through to the
      // status text rather than replacing it with a parse failure.
    }
    throw new ApiError(res.status, messageFromBody(body, res));
  }

  if (res.status === 204 || res.headers.get("Content-Length") === "0") {
    return undefined as T;
  }

  const text = await res.text();
  if (text === "") return undefined as T;
  return JSON.parse(text) as T;
}

export { BASE_URL };
