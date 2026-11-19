import React, { createContext, useCallback, useContext, useEffect, useState } from "react";

export type ColorSchemePreference = "system" | "dark" | "light";

const STORAGE_KEY = "waffynx_color_scheme";

interface ThemeContextValue {
  preference: ColorSchemePreference;
  setPreference: (next: ColorSchemePreference) => void;
}

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);

function readStoredPreference(): ColorSchemePreference {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw === "dark" || raw === "light") return raw;
  } catch {
    // Storage may be disabled; fall back to system preference.
  }
  return "system";
}

function applyMetaColorScheme(pref: ColorSchemePreference): void {
  const meta = document.querySelector<HTMLMetaElement>('meta[name="color-scheme"]');
  if (!meta) return;
  meta.content = pref === "system" ? "light dark" : pref;
}

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [preference, setPreferenceState] = useState<ColorSchemePreference>(() => readStoredPreference());

  useEffect(() => {
    applyMetaColorScheme(preference);
  }, [preference]);

  useEffect(() => {
    const handleStorage = (e: StorageEvent) => {
      if (e.key !== STORAGE_KEY) return;
      const next = e.newValue === "dark" || e.newValue === "light" ? e.newValue : "system";
      setPreferenceState(next);
    };
    window.addEventListener("storage", handleStorage);
    return () => window.removeEventListener("storage", handleStorage);
  }, []);

  const setPreference = useCallback((next: ColorSchemePreference) => {
    setPreferenceState(next);
    try {
      if (next === "system") {
        localStorage.removeItem(STORAGE_KEY);
      } else {
        localStorage.setItem(STORAGE_KEY, next);
      }
    } catch {
      // Theme still applies to the page even if persistence fails.
    }
  }, []);

  return (
    <ThemeContext.Provider value={{ preference, setPreference }}>
      {children}
    </ThemeContext.Provider>
  );
};

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used within ThemeProvider");
  return ctx;
}
