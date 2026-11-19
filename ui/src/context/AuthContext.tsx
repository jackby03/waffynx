import React, { createContext, useCallback, useContext, useEffect, useState } from "react";
import type { Role, UserSession } from "../api/types";
import { setUnauthorizedHandler } from "../api/client";
import { wafApi } from "../api/wafApi";

interface AuthContextType {
  session: UserSession | null;
  isAuthenticated: boolean;
  scopes: string[];
  login: (user: string, pass: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

function asRole(raw: string): Role {
  if (raw === "admin" || raw === "analyst" || raw === "viewer") return raw;
  return "viewer";
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [session, setSession] = useState<UserSession | null>(() => wafApi.getCurrentSession());
  const [scopes, setScopes] = useState<string[]>([]);

  const logout = useCallback(() => {
    void wafApi.logout();
    setSession(null);
    setScopes([]);
  }, []);

  const hydrateIdentity = useCallback(async () => {
    try {
      const me = await wafApi.me();
      const role = asRole(me.role);
      const updated = wafApi.updateStoredRole(role);
      if (updated) {
        setSession({ ...updated, username: me.username || updated.username });
      }
      setScopes(me.scopes ?? []);
    } catch {
      // A 401 triggers setUnauthorizedHandler below; network failures keep the stored session until retried.
    }
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(logout);
    return () => setUnauthorizedHandler(() => {});
  }, [logout]);

  useEffect(() => {
    if (session?.token) {
      void hydrateIdentity();
    }
  }, [session?.token, hydrateIdentity]);

  const login = useCallback(
    async (user: string, pass: string) => {
      const s = await wafApi.login(user, pass);
      setSession(s);
      await hydrateIdentity();
    },
    [hydrateIdentity]
  );

  return (
    <AuthContext.Provider value={{ session, isAuthenticated: Boolean(session), scopes, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextType {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
