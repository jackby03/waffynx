/**
 * Safe hostile payload tokenizer.
 *
 * Produces plain data segments so views render `<mark>` React elements instead of
 * ever touching `innerHTML` or `dangerouslySetInnerHTML`.
 */

export interface PayloadToken {
  text: string;
  hostile: boolean;
}

const HOSTILE_PATTERN =
  /(union\s+(?:all\s+)?select|select\s+.*?\s+from|or\s+['"]?1['"]?\s*=\s*['"]?1|sleep\s*\(|pg_sleep\s*\(|waitfor\s+delay|benchmark\s*\(|information_schema|load_file\s*\(|into\s+(?:out|dump)file|'--|"--|<\/?script[^>]*>|on(?:error|load|click|mouseover|focus)\s*=|javascript:|data:text\/html|\.\.\/|\.\.\\|\/etc\/passwd|\.git\/config|\$\{jndi:[^}]+\}|sqlmap|nikto|;\s*(?:select|insert|update|delete|drop|cat|whoami|id|sh|bash)\b)/gi;

export function tokenizeHostilePayload(input: string): PayloadToken[] {
  if (!input) return [];
  const tokens: PayloadToken[] = [];
  let lastIndex = 0;

  for (const match of input.matchAll(HOSTILE_PATTERN)) {
    const start = match.index ?? 0;
    if (start > lastIndex) {
      tokens.push({ text: input.slice(lastIndex, start), hostile: false });
    }
    tokens.push({ text: match[0], hostile: true });
    lastIndex = start + match[0].length;
  }

  if (lastIndex < input.length) {
    tokens.push({ text: input.slice(lastIndex), hostile: false });
  }

  return tokens;
}
