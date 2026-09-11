import type { UserSession } from "../types";

export function mockLogin(username: string, password: string): UserSession {
  if (username === "admin" && password === "admin") {
    const session: UserSession = {
      token: "mock-jwt-token-" + Math.random().toString(36).substring(2),
      username: "admin",
      role: "admin",
      expires_at: Date.now() + 1000 * 60 * 60 * 8, // 8 hours
    };
    localStorage.setItem("waffynx_auth", JSON.stringify(session));
    return session;
  }
  throw new Error("Invalid username or password (use admin / admin)");
}

export function getStoredSession(): UserSession | null {
  try {
    const raw = localStorage.getItem("waffynx_auth");
    if (!raw) return null;
    const session = JSON.parse(raw) as UserSession;
    if (session.expires_at < Date.now()) {
      localStorage.removeItem("waffynx_auth");
      return null;
    }
    return session;
  } catch {
    return null;
  }
}

export function clearSession(): void {
  localStorage.removeItem("waffynx_auth");
}
