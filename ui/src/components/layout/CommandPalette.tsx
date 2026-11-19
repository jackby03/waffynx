import React, { useEffect, useMemo, useState } from "react";
import { ArrowRight, Globe, Search, Shield, Sliders, Terminal } from "lucide-react";
import { Dialog } from "../common/Dialog";
import { NAV_ITEMS, type ViewId } from "../../router/routes";
import { useWaf } from "../../context/WafContext";

interface CommandItem {
  id: string;
  group: string;
  label: string;
  meta?: string;
  icon: React.ReactNode;
  run: () => void;
}

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  onNavigate: (view: ViewId, presetQuery?: string) => void;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({ open, onClose, onNavigate }) => {
  const { sites, rules } = useWaf();
  const [query, setQuery] = useState("");
  const [selectedIdx, setSelectedIdx] = useState(0);

  useEffect(() => {
    if (open) {
      setQuery("");
      setSelectedIdx(0);
    }
  }, [open]);

  const items = useMemo<CommandItem[]>(() => {
    const navEntries: CommandItem[] = NAV_ITEMS.map((nav) => ({
      id: `nav-${nav.id}`,
      group: "Navigation",
      label: nav.label,
      meta: nav.section,
      icon: <ArrowRight size={15} />,
      run: () => {
        onNavigate(nav.id);
        onClose();
      },
    }));

    const siteEntries: CommandItem[] = sites.map((s) => ({
      id: `site-${s.host}`,
      group: "Protected Sites",
      label: s.host,
      meta: s.upstream,
      icon: <Globe size={15} />,
      run: () => {
        onNavigate("sites", s.host);
        onClose();
      },
    }));

    const ruleEntries: CommandItem[] = rules.slice(0, 60).map((r) => ({
      id: `rule-${r.id}`,
      group: "Managed Rules",
      label: `${r.id} — ${r.name}`,
      meta: `${r.severity} · ${r.action}`,
      icon: <Shield size={15} />,
      run: () => {
        onNavigate("managed-rules", r.id);
        onClose();
      },
    }));

    const quickEntries: CommandItem[] = [
      {
        id: "quick-custom-rule",
        group: "Quick Actions",
        label: "Create Custom WAF Rule",
        meta: "Sidecar policy engine",
        icon: <Sliders size={15} />,
        run: () => {
          onNavigate("custom-rules");
          onClose();
        },
      },
      {
        id: "quick-ban-ip",
        group: "Quick Actions",
        label: "Ban an IP Address",
        meta: "WAF layer enforcement",
        icon: <Terminal size={15} />,
        run: () => {
          onNavigate("firewall");
          onClose();
        },
      },
    ];

    const all = [...navEntries, ...quickEntries, ...siteEntries, ...ruleEntries];
    const q = query.trim().toLowerCase();
    if (!q) return all.slice(0, 14);

    return all
      .filter(
        (item) =>
          item.label.toLowerCase().includes(q) ||
          (item.meta ?? "").toLowerCase().includes(q) ||
          item.group.toLowerCase().includes(q)
      )
      .slice(0, 16);
  }, [query, sites, rules, onNavigate, onClose]);

  useEffect(() => {
    setSelectedIdx(0);
  }, [query]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIdx((i) => Math.min(items.length - 1, i + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIdx((i) => Math.max(0, i - 1));
    } else if (e.key === "Enter" && items[selectedIdx]) {
      e.preventDefault();
      items[selectedIdx].run();
    }
  };

  return (
    <Dialog open={open} onClose={onClose} title="Command Palette" variant="palette" hideHeader>
      <div className="palette-input-row">
        <Search size={16} color="var(--text-muted)" aria-hidden="true" />
        <label htmlFor="cmd-palette-input" className="visually-hidden">
          Jump to a view, site, or rule
        </label>
        <input
          id="cmd-palette-input"
          className="palette-input"
          placeholder="Jump to a screen, site, or rule ID (e.g., WAF-SQLI-001)…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={handleKeyDown}
          autoFocus
        />
        <span className="kbd-hint">ESC</span>
      </div>

      {items.length === 0 ? (
        <div className="empty-state" style={{ padding: "1.5rem" }}>
          <p className="empty-state-desc">No views, sites, or rules match "{query}".</p>
        </div>
      ) : (
        <ul className="palette-list" role="listbox" aria-label="Command results">
          {items.map((item, idx) => (
            <li key={item.id}>
              <button
                type="button"
                className={`palette-item ${idx === selectedIdx ? "selected" : ""}`}
                onMouseEnter={() => setSelectedIdx(idx)}
                onClick={item.run}
              >
                <span className="palette-item-left">
                  <span aria-hidden="true">{item.icon}</span>
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {item.label}
                  </span>
                </span>
                <span className="mono text-muted" style={{ fontSize: "0.71rem", flexShrink: 0 }}>
                  {item.meta || item.group}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </Dialog>
  );
};
