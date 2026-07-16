# @cantica/secure-ui

Themeable React forms and admin panels for **Cantica Secure**, shared by
`cantica-web` and the Cantica Studio clients so both feel unified while matching
the app they run inside.

## What's in the box

- **Forms**: `LoginForm`, `InviteRequestForm`, `KeyEnrolment`.
- **Admin panels**: `AdminUsersPanel` (activation + flags), `DirectoryMappingsPanel`,
  `ApiTokensPanel`.
- **`SessionWarningBadge`** for the `X-Cantica-Warning` header (spec AUTH F).
- **`SecureClient`** over a pluggable **`Transport`**: `createFetchTransport`
  (cantica-web / Electron renderer) or `createBridgeTransport` (VS Code webview
  postMessage — the token stays in the extension host).
- **Theming** via CSS custom properties: `canticaWebTheme` and `studioTheme`
  reference themes, or supply your own token map to `<SecureProvider theme>`.
- **Key machinery** (`generateKeyPair`, `createEnrolmentAssertion`,
  `createAuthAssertion`) — Web Crypto RS256, matching the server contract.

## Usage

```tsx
import {
  SecureProvider, createFetchTransport, canticaWebTheme, AdminUsersPanel,
} from '@cantica/secure-ui';
import '@cantica/secure-ui/styles.css';

const transport = createFetchTransport({ baseUrl: '/', getToken: () => session });

<SecureProvider transport={transport} theme={canticaWebTheme}>
  <AdminUsersPanel />
</SecureProvider>;
```

Adoption lives in Phase E of [../ROADMAP.md](../ROADMAP.md).
