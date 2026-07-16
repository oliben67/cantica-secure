import type { SecureRequest, SecureResponse, Transport } from '../src/transport';

type Handler = (req: SecureRequest) => SecureResponse<unknown>;

/** A scriptable in-memory transport for component/client tests. */
export function fakeTransport(routes: Record<string, Handler>): Transport & { calls: SecureRequest[] } {
  const calls: SecureRequest[] = [];
  return {
    calls,
    async send<T>(req: SecureRequest): Promise<SecureResponse<T>> {
      calls.push(req);
      const key = `${req.method} ${req.path.split('?')[0]}`;
      const h = routes[key] ?? routes[`${req.method} *`];
      if (!h) return { ok: false, status: 404, data: { detail: `no route: ${key}` } as T };
      return h(req) as SecureResponse<T>;
    },
  };
}

export const ok = <T>(data: T, warning?: string): SecureResponse<T> =>
  ({ ok: true, status: 200, data, ...(warning ? { warning } : {}) });
export const fail = (status: number, detail: string): SecureResponse<unknown> =>
  ({ ok: false, status, data: { detail } });
