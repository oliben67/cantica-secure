import React, { useState } from 'react';
import { useSecure } from '../ThemeProvider';
import { Button, Field, Input, Notice } from '../primitives';
import type { LoginResult } from '../types';

/** Password login (spec AUTH via /auth/login). Calls onSuccess with the
 *  session; warnings (spec AUTH F) are surfaced inline. */
export function LoginForm({ onSuccess }: { onSuccess?: (r: LoginResult) => void }) {
  const { client } = useSecure();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await client.login(email.trim(), password);
      setWarnings(result.warnings);
      onSuccess?.(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="csec-form" onSubmit={submit}>
      {error ? <Notice kind="error">{error}</Notice> : null}
      {warnings.map((w) => <Notice key={w} kind="warning">{w}</Notice>)}
      <Field label="Email">
        <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" required />
      </Field>
      <Field label="Password">
        <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
      </Field>
      <Button variant="primary" type="submit" disabled={busy || !email || !password}>
        {busy ? 'Signing in…' : 'Sign in'}
      </Button>
    </form>
  );
}
