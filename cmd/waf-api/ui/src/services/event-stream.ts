import { clearToken, getToken, type WafEvent } from "./api";

export function streamEvents(onEvent: (event: WafEvent) => void, onState: (state: string) => void, onUnauthorized: () => void) {
  let stopped = false;
  let controller: AbortController | undefined;
  let retry = 500;
  async function connect() {
    if (stopped) return;
    controller = new AbortController();
    onState("connecting");
    try {
      const response = await fetch("/api/v1/events", { headers: { Accept: "text/event-stream", Authorization: `Bearer ${getToken() ?? ""}` }, signal: controller.signal });
      if (response.status === 401 || response.status === 403) { clearToken(); onUnauthorized(); return; }
      if (!response.ok || !response.body) throw new Error("event stream unavailable");
      onState("connected"); retry = 500;
      const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
      let buffer = "";
      while (!stopped) {
        const next = await reader.read();
        if (next.done) break;
        buffer += next.value;
        const frames = buffer.split("\n\n"); buffer = frames.pop() ?? "";
        for (const frame of frames) for (const line of frame.split("\n")) if (line.startsWith("data: ")) { try { onEvent(JSON.parse(line.slice(6)) as WafEvent); } catch { /* Ignore malformed server events. */ } }
      }
    } catch (error) { if (error instanceof DOMException && error.name === "AbortError") return; }
    if (!stopped) { onState("reconnecting"); const delay = retry; retry = Math.min(retry * 2, 30_000); window.setTimeout(connect, delay); }
  }
  void connect();
  return () => { stopped = true; controller?.abort(); };
}
