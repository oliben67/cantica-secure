import React, { useEffect, useState } from 'react';
import { useSecure } from '../ThemeProvider';
import { Button, Input, Notice } from '../primitives';
import type { ApiTokenInfo } from '../types';

/** API token management (create / list / revoke). The raw token is shown once. */
export function ApiTokensPanel({ scopes = ['*'] }: { scopes?: string[] }) {
  const { client } = useSecure();
  const [tokens, setTokens] = useState<ApiTokenInfo[]>([]);
  const [name, setName] = useState('');
  const [fresh, setFresh] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const reload = React.useCallback(async () => {
    try { setTokens(await client.listTokens()); }
    catch (err) { setError(err instanceof Error ? err.message : 'Failed to load tokens'); }
  }, [client]);

  useEffect(() => { void reload(); }, [reload]);

  async function create() {
    setError(null);
    try {
      const created = await client.createToken(name.trim(), scopes);
      setFresh(created.token);
      setName('');
      await reload();
    } catch (err) { setError(err instanceof Error ? err.message : 'Create failed'); }
  }

  async function revoke(id: string) {
    setError(null);
    try { await client.deleteToken(id); await reload(); }
    catch (err) { setError(err instanceof Error ? err.message : 'Revoke failed'); }
  }

  return (
    <div className="csec-panel">
      {error ? <Notice kind="error">{error}</Notice> : null}
      {fresh ? (
        <Notice kind="info">Copy your token now — it will not be shown again:<code className="csec-token">{fresh}</code></Notice>
      ) : null}
      <div className="csec-row">
        <Input placeholder="Token name" value={name} onChange={(e) => setName(e.target.value)} />
        <Button variant="primary" disabled={!name.trim()} onClick={() => void create()}>Create token</Button>
      </div>
      {tokens.length === 0 ? <p className="csec-empty">No tokens.</p> : null}
      {tokens.map((t) => (
        <div key={t.id} className="csec-token-row">
          <span className="csec-token-name">{t.name || t.id}</span>
          <span className="csec-hint">{t.scopes.join(', ') || 'no scopes'}</span>
          <Button variant="danger" onClick={() => void revoke(t.id)}>Revoke</Button>
        </div>
      ))}
    </div>
  );
}
