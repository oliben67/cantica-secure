import React, { useState } from 'react';
import { useSecure } from '../ThemeProvider';
import { Button, Field, Input, Notice } from '../primitives';
import { createEnrolmentAssertion, generateKeyPair, type KeyPairPem } from '../keys';

/** Key enrolment (spec REGISTRATION 3–8). Generates a key pair in the browser,
 *  signs the invitation, and posts the public key. The private key never leaves
 *  the client — the host persists it via onEnrolled. */
export function KeyEnrolment({
  onEnrolled,
  initialInvitation = '',
  clientId = 'cantica-secure-ui',
}: {
  onEnrolled?: (result: { canticaUserId: string; keyPair: KeyPairPem }) => void;
  initialInvitation?: string;
  clientId?: string;
}) {
  const { client } = useSecure();
  const [invitation, setInvitation] = useState(initialInvitation);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const keyPair = await generateKeyPair();
      const assertion = await createEnrolmentAssertion(keyPair.privateKey, clientId, invitation.trim());
      const { cantica_user_id } = await client.enrolKey(assertion, keyPair.publicKeyPem);
      setOk(cantica_user_id);
      onEnrolled?.({ canticaUserId: cantica_user_id, keyPair });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Enrolment failed');
    } finally {
      setBusy(false);
    }
  }

  if (ok) {
    return <Notice kind="info">Device enrolled as <strong>{ok}</strong>. You can now sign in with your key.</Notice>;
  }

  return (
    <form className="csec-form" onSubmit={submit}>
      {error ? <Notice kind="error">{error}</Notice> : null}
      <Field label="Invitation token" hint="from your invitation email">
        <Input value={invitation} onChange={(e) => setInvitation(e.target.value)} required />
      </Field>
      <Button variant="primary" type="submit" disabled={busy || !invitation.trim()}>
        {busy ? 'Enrolling…' : 'Enrol this device'}
      </Button>
    </form>
  );
}
