# P-256 Signer Web

Public browser companion for the independent iPhone P-256 signer.

Site: https://tumf.github.io/p256-signer-web/

The iPhone app and its private repository are separate. This repository starts from a source-only Web snapshot; it does not contain the app repository's Git history, app signing credentials, device keys or release artifacts.

## Build and test

Requires Node.js 22 or later.

```sh
npm ci
npx playwright install chromium
npm test
WALLETCONNECT_PROJECT_ID=<public-project-id> npm run build
python3 -m http.server 8080 --directory dist
```

The WalletConnect project ID is a public client identifier, not a secret or permission. GitHub Actions reads it from the repository variable `WALLETCONNECT_PROJECT_ID`. The production workflow requires this variable. Local builds without an ID disable WalletConnect; malformed IDs fail the build. Add `https://tumf.github.io` to the WalletConnect project's allowed origins before live pairing.

## Hosting and trust

GitHub Pages serves only `dist/`. All script and QR generation code is local. The HTML includes a restrictive meta CSP and a no-referrer policy. Pages cannot set custom response headers: `frame-ancestors` and header-only controls are not claimed here.

The exact origin is `https://tumf.github.io`; `/p256-signer-web/` is the site path, not an origin. Other projects under that GitHub account share the same browser origin and storage trust boundary. Use a dedicated custom hostname if that shared trust boundary becomes unacceptable.

Pages cannot run a POST RPC endpoint. The existing `https://p256-signer.mini.tumf.dev` service remains the read-only relay for the four closed chains. CORS allows exactly the Pages origin on the exact RPC routes; the existing method/parameter/size/time bounds remain. The relay never accepts transaction submission or signing. Production RPC providers and credentials are operator configuration, never build inputs.

The Web offers explicit wallet connection and explicit user-controlled requests. A page load or QR download never signs or sends. Saved QR images contain connection information; do not share them and delete them after use. Existing browser records remain at the old origin and are not copied automatically.

## Licensing

Original project code remains `UNLICENSED` (all rights reserved); public visibility does not grant an open-source license. Third-party code retains its own licenses. See `licenses.json`, `vendor/` and the build's `licenses/NOTICES.txt`. WalletConnect components use the WalletConnect Community License Agreement; publication does not assert commercial entitlement or Reown endorsement.

Tests use public contract runtimes and synthetic software-key fixtures. They are not production keys or evidence of physical Secure Enclave authentication.

## Deployment

The Pages workflow tests and builds `main`, uploads only `dist/`, and deploys with the GitHub Pages OIDC workflow. No app/TestFlight release is performed here.
