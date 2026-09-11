import React, { createContext, useContext, useState, useEffect } from "react";
import type { UserSession } from "../api/types";
import { wafApi } from "../api/wafApi";

interface AuthContextType {
  session: UserSession | null;
  isAuthenticated: boolean;
  login: (user: string, pass: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [session, setSession] = useState<UserSession | null>(() => wafApi.getCurrentSession());

  useEffect(() => {
    // Sync session on mount
    const cur = wafApi.getCurrentSession();
    if (cur) setSession(cur);
  }, []);

  const login = async (user: string, pass: string) => {
    const s = await wafApi.login(user, pass);
    setSession(s);
  };

  const logout = () => {
    wafApi.logout();
    setSession(null);
  };

  return (
    <AuthContext.Provider value={{ session, isAuthenticated: !!session, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextType {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
