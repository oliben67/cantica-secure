// Transport abstraction — components never fetch directly. A host supplies
// either a fetch-based transport (cantica-web, Electron renderer) or a
// postMessage bridge (VS Code webview, where CSP blocks direct network access
// and the token must stay in the extension host).

export interface SecureRequest {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  path: string; // e.g. "/v1/users"
  body?: unknown;
  /** When true the request carries the current session credential (host adds it). */
  auth?: boolean;
}

export interface SecureResponse<T = unknown> {
  ok: boolean;
  status: number;
  data: T;
  /** X-Cantica-Warning header, when present. */
  warning?: string;
}

export interface Transport {
  send<T = unknown>(req: SecureRequest): Promise<SecureResponse<T>>;
}

/** fetch-based transport for cantica-web / Electron renderer. */
export function createFetchTransport(opts: {
  baseUrl: string;
  /** Returns the bearer token for authed requests, or null. */
  getToken?: () => string | null;
  fetchImpl?: typeof fetch;
}): Transport {
  const doFetch = opts.fetchImpl ?? fetch;
  const base = opts.baseUrl.replace(/\/$/, '');
  return {
    async send<T>(req: SecureRequest): Promise<SecureResponse<T>> {
      const headers: Record<string, string> = { 'Content-Type': 'application/json', Accept: 'application/json' };
      if (req.auth) {
        const token = opts.getToken?.() ?? null;
        if (token) headers.Authorization = `Bearer ${token}`;
      }
      const res = await doFetch(`${base}${req.path}`, {
        method: req.method,
        headers,
        ...(req.body !== undefined ? { body: JSON.stringify(req.body) } : {}),
      });
      let data: unknown = null;
      try { data = await res.json(); } catch { /* empty body */ }
      const warning = res.headers.get('X-Cantica-Warning') ?? undefined;
      return { ok: res.ok, status: res.status, data: data as T, ...(warning ? { warning } : {}) };
    },
  };
}

/** postMessage bridge for the VS Code webview. The host relays each request to
 *  the extension host (which holds the token) and posts the reply back. */
export function createBridgeTransport(opts: {
  post: (msg: unknown) => void;
  subscribe: (handler: (msg: unknown) => void) => () => void;
  timeoutMs?: number;
}): Transport {
  let seq = 0;
  const pending = new Map<number, (r: SecureResponse) => void>();

  opts.subscribe((raw) => {
    const msg = raw as { type?: string; id?: number; response?: SecureResponse };
    if (msg?.type === 'secure:response' && typeof msg.id === 'number') {
      const resolve = pending.get(msg.id);
      if (resolve && msg.response) { pending.delete(msg.id); resolve(msg.response); }
    }
  });

  return {
    send<T>(req: SecureRequest): Promise<SecureResponse<T>> {
      const id = ++seq;
      return new Promise<SecureResponse<T>>((resolve, reject) => {
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(new Error(`secure bridge request timed out: ${req.method} ${req.path}`));
        }, opts.timeoutMs ?? 15000);
        pending.set(id, (r) => { clearTimeout(timer); resolve(r as SecureResponse<T>); });
        opts.post({ type: 'secure:request', id, request: req });
      });
    },
  };
}
