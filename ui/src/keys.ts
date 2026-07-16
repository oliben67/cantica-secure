// Client key machinery — the JS half of the key-based auth contract, extracted
// from cantica-studio/clients/shared/auth-core.ts. Uses Web Crypto so it runs
// in the browser (cantica-web) and Electron renderer alike; Node ≥18 exposes
// the same `crypto.subtle`.

const b64url = (buf: ArrayBuffer): string => {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const b64urlStr = (s: string): string =>
  btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function pemBody(spkiOrPkcs8: ArrayBuffer, label: 'PUBLIC KEY' | 'PRIVATE KEY'): string {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spkiOrPkcs8)));
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

export interface KeyPairPem {
  privateKey: CryptoKey;
  publicKeyPem: string;
}

/** Generate an RSA-2048 signing key pair (matches the server's RS256 verify). */
export async function generateKeyPair(subtle: SubtleCrypto = crypto.subtle): Promise<KeyPairPem> {
  const pair = await subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  );
  const spki = await subtle.exportKey('spki', pair.publicKey);
  return { privateKey: pair.privateKey, publicKeyPem: pemBody(spki, 'PUBLIC KEY') };
}

async function signJwt(
  privateKey: CryptoKey,
  claims: Record<string, unknown>,
  subtle: SubtleCrypto,
): Promise<string> {
  const header = b64urlStr(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = b64urlStr(JSON.stringify(claims));
  const signingInput = `${header}.${payload}`;
  const sig = await subtle.sign(
    'RSASSA-PKCS1-v1_5', privateKey, new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${b64url(sig)}`;
}

const nowSec = () => Math.floor(Date.now() / 1000);
const jti = () => (crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`);

/** Enrolment assertion (spec REGISTRATION 3–6): embeds the invitation JWT and
 *  is signed with the client's private key. POST to /v1/auth/register. */
export function createEnrolmentAssertion(
  privateKey: CryptoKey, clientId: string, invitationJwt: string,
  audience = 'cantica-secure', subtle: SubtleCrypto = crypto.subtle,
): Promise<string> {
  const n = nowSec();
  return signJwt(privateKey, {
    iss: clientId, sub: clientId, aud: audience,
    invitation: invitationJwt, iat: n, exp: n + 300, jti: jti(),
  }, subtle);
}

/** Authentication assertion (spec AUTH C): iss/sub carry cantica_user_id.
 *  Exchange at /v1/auth/assert for a session token. */
export function createAuthAssertion(
  privateKey: CryptoKey, canticaUserId: string,
  audience = 'cantica-secure', subtle: SubtleCrypto = crypto.subtle,
): Promise<string> {
  const n = nowSec();
  return signJwt(privateKey, {
    iss: canticaUserId, sub: canticaUserId, aud: audience, iat: n, exp: n + 300, jti: jti(),
  }, subtle);
}
