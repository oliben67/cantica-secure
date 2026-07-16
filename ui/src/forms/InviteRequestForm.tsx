import React, { useState } from 'react';
import { useSecure } from '../ThemeProvider';
import { Button, Field, Input, Notice } from '../primitives';

/** Public invitation request (spec REGISTRATION C.1). When the server has no
 *  mail transport the returned token is surfaced for the enrolment step;
 *  otherwise the user is told to check their email. */
export function InviteRequestForm({ onInvitation }: { onInvitation?: (token: string) => void }) {
  const { client } = useSecure();
  const [first, setFirst] = useState('');
  const [last, setLast] = useState('');
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<null | { token: string | null }>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { invitation } = await client.requestInvitation(first.trim(), last.trim(), email.trim());
      setDone({ token: invitation });
      if (invitation) onInvitation?.(invitation);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Request failed');
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return done.token ? (
      <Notice kind="info">
        Invitation issued. Use this token to enrol your device:
        <code className="csec-token">{done.token}</code>
      </Notice>
    ) : (
      <Notice kind="info">If that email is eligible, an invitation has been sent to it.</Notice>
    );
  }

  return (
    <form className="csec-form" onSubmit={submit}>
      {error ? <Notice kind="error">{error}</Notice> : null}
      <div className="csec-row">
        <Field label="First name"><Input value={first} onChange={(e) => setFirst(e.target.value)} required /></Field>
        <Field label="Last name"><Input value={last} onChange={(e) => setLast(e.target.value)} required /></Field>
      </div>
      <Field label="Email">
        <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
      </Field>
      <Button variant="primary" type="submit" disabled={busy || !email}>
        {busy ? 'Requesting…' : 'Request invitation'}
      </Button>
    </form>
  );
}
