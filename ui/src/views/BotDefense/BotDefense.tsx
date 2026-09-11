import React, { useState } from "react";
import { KpiCard } from "../../components/common/KpiCard";
import { ToggleSwitch } from "../../components/common/ToggleSwitch";
import { Badge } from "../../components/common/Badge";

interface BotIncident {
  id: string;
  ip: string;
  tool: string;
  fingerprint_ja3: string;
  result: "challenge_failed" | "headless_detected" | "spoofed_user_agent";
  action: "deny" | "challenge";
  timestamp: string;
}

const RECENT_BOTS: BotIncident[] = [
  {
    id: "bot-101",
    ip: "45.33.32.156",
    tool: "Puppeteer / Chromium Headless",
    fingerprint_ja3: "a0e9f5d6451642100980c6f2bbe7b0e6",
    result: "headless_detected",
    action: "deny",
    timestamp: new Date(Date.now() - 1000 * 60 * 3).toISOString(),
  },
  {
    id: "bot-102",
    ip: "185.220.101.5",
    tool: "Python aiohttp scraper (No JS)",
    fingerprint_ja3: "3b5074b1b310a084efdae4040b31a4e0",
    result: "challenge_failed",
    action: "deny",
    timestamp: new Date(Date.now() - 1000 * 60 * 8).toISOString(),
  },
  {
    id: "bot-103",
    ip: "203.0.113.88",
    tool: "Fake Googlebot (Failed rDNS)",
    fingerprint_ja3: "d41d8cd98f00b204e9800998ecf8427e",
    result: "spoofed_user_agent",
    action: "deny",
    timestamp: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
  },
  {
    id: "bot-104",
    ip: "198.51.100.42",
    tool: "Playwright Automation Suite",
    fingerprint_ja3: "9a79856f6c9d09c6bc7efb5e5f396265",
    result: "headless_detected",
    action: "deny",
    timestamp: new Date(Date.now() - 1000 * 60 * 22).toISOString(),
  },
];

export const BotDefense: React.FC = () => {
  const [enableJsChallenge, setEnableJsChallenge] = useState(true);
  const [enableHeadlessDetect, setEnableHeadlessDetect] = useState(true);
  const [enableJa3Fingerprint, setEnableJa3Fingerprint] = useState(true);
  const [whitelistSearchEngines, setWhitelistSearchEngines] = useState(true);

  return (
    <div className="view-container">
      {/* 4 Standardized KPI Cards */}
      <section className="kpi-grid">
        <KpiCard
          title="Bot Mitigation Posture"
          value="Enforced"
          subtext="Behavioral heuristics & cryptographic challenges"
          badge="Anti-Automation"
          variant="critical"
        />
        <KpiCard
          title="JS PoW Challenges"
          value="1,420"
          subtext="Cryptographic proof-of-work (98.2% legitimate pass)"
          badge="Frictionless"
          variant="success"
        />
        <KpiCard
          title="Headless Browsers"
          value="348"
          subtext="Puppeteer, Selenium & Playwright mitigated"
          badge="DOM Traps"
          variant="info"
        />
        <KpiCard
          title="TLS Client Fingerprints"
          value="14 JA3 Signatures"
          subtext="Anomalous TLS ClientHello ciphers blocked"
          badge="JA3/JA4"
          variant="default"
        />
      </section>

      {/* Bot Defense Mitigation Engine Switches */}
      <section className="panel-card">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">Bot Defense Engine & Mitigation Rules</h2>
            <span className="panel-subtitle">
              Configure adaptive verification, browser environment analysis, and client fingerprinting
            </span>
          </div>
        </div>

        <div className="traffic-policies-grid">
          <div className="traffic-policy-item">
            <div className="policy-info">
              <strong>Cryptographic JavaScript Proof-of-Work (PoW) Challenge</strong>
              <p>Serves a low-CPU background mathematical puzzle to verify non-automated browser execution.</p>
            </div>
            <ToggleSwitch
              checked={enableJsChallenge}
              onChange={setEnableJsChallenge}
            />
          </div>

          <div className="traffic-policy-item">
            <div className="policy-info">
              <strong>Headless Browser & Automation Traps (Selenium / Puppeteer)</strong>
              <p>Inspects browser DOM for <code>navigator.webdriver</code> and Chromium debugging flags.</p>
            </div>
            <ToggleSwitch
              checked={enableHeadlessDetect}
              onChange={setEnableHeadlessDetect}
            />
          </div>

          <div className="traffic-policy-item">
            <div className="policy-info">
              <strong>JA3 / JA4 TLS Client Fingerprint Validation</strong>
              <p>Compares TLS handshake characteristics with known malicious automation scraping libraries.</p>
            </div>
            <ToggleSwitch
              checked={enableJa3Fingerprint}
              onChange={setEnableJa3Fingerprint}
            />
          </div>

          <div className="traffic-policy-item">
            <div className="policy-info">
              <strong>Verified Search Engine Crawler Whitelist (rDNS Validation)</strong>
              <p>Permits Googlebot, Bingbot, and DuckDuckGo via forward-confirmed reverse DNS checking.</p>
            </div>
            <ToggleSwitch
              checked={whitelistSearchEngines}
              onChange={setWhitelistSearchEngines}
            />
          </div>
        </div>
      </section>

      {/* Recent Bot Detections Table */}
      <section className="table-card">
        <div className="table-card-header">
          <div>
            <h2 className="table-title">Recent Automated Bot Detections</h2>
            <span className="table-subtitle">
              Scrapers and automated tools challenged or dropped at ingress
            </span>
          </div>
        </div>

        <div className="table-responsive">
          <table className="waf-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Source IP</th>
                <th>Detected Tool / Framework</th>
                <th>JA3 Fingerprint Hash</th>
                <th>Detection Trigger</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {RECENT_BOTS.map((bot) => (
                <tr key={bot.id}>
                  <td className="cell-time">{new Date(bot.timestamp).toLocaleTimeString()}</td>
                  <td className="cell-ip">{bot.ip}</td>
                  <td className="cell-rule">
                    <strong>{bot.tool}</strong>
                  </td>
                  <td className="cell-pattern">
                    <code>{bot.fingerprint_ja3}</code>
                  </td>
                  <td>
                    <span className="category-pill">
                      {bot.result === "headless_detected"
                        ? "HEADLESS EMULATOR"
                        : bot.result === "challenge_failed"
                        ? "JS CHALLENGE FAILED"
                        : "SPOOFED USER-AGENT"}
                    </span>
                  </td>
                  <td>
                    <Badge variant="critical">DENY (403)</Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
