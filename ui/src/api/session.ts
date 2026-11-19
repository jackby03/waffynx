import type { UserSession } from "./types";

// The session lives in localStorage because the API authenticates with a bearer
// token and there is no cookie session yet. That trade-off is documented in the
// PR that adds cookie sessions: until then, this is the only place that knows how
// the token is stored, so swapping it later is a single-file change.
const STORAGE_KEY = "waffynx_auth";

export function getStoredSession(): UserSession | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const session = JSON.parse(raw) as UserSession;
    if (session.expires_at < Date.now()) {
      localStorage.removeItem(STORAGE_KEY);
      return null;
    }
    return session;
  } catch {
    return null;
  }
}

export function storeSession(session: UserSession): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
}

export function clearStoredSession(): void {
  localStorage.removeItem(STORAGE_KEY);
}
