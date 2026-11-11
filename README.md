# P-256 Signer Web

Public browser companion for the independent iPhone P-256 signer.

Site: https://p256-signer.tumf.dev/

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

The WalletConnect project ID is a public client identifier, not a secret or permission. GitHub Actions reads it from the repository variable `WALLETCONNECT_PROJECT_ID`. The production workflow requires this variable. Local builds without an ID disable WalletConnect; malformed IDs fail the build. Add `https://p256-signer.tumf.dev` to the WalletConnect project's allowed origins before live pairing.

## Hosting and trust

GitHub Pages serves only `dist/`. All script and QR generation code is local. The HTML includes a restrictive meta CSP and a no-referrer policy. Pages cannot set custom response headers: `frame-ancestors` and header-only controls are not claimed here.

The dedicated origin is `https://p256-signer.tumf.dev`, with the site at `/`. DNS is a DNS-only CNAME to `tumf.github.io`; GitHub Pages terminates HTTPS. It no longer shares the `tumf.github.io` browser origin or storage boundary.

Pages cannot run a POST RPC endpoint. The browser reads the four fixed public PublicNode HTTPS endpoints in `site.js`, with no API key, cookies or operator credentials. Client transport admits only the explicit read-method list; wallet submission remains a separate explicit user action. Providers see queried addresses, call data and client IP. Existing chain/code-hash/block validation remains mandatory; RPC responses are untrusted. The Tailscale-only mini service is not a Web dependency. Browser-network protections are not bypassed.

The Web offers explicit wallet connection and explicit user-controlled requests. A page load or QR download never signs or sends. Saved QR images contain connection information; do not share them and delete them after use. Existing browser records remain at the old origin and are not copied automatically.

## Licensing

Original project code remains `UNLICENSED` (all rights reserved); public visibility does not grant an open-source license. Third-party code retains its own licenses. See `licenses.json`, `vendor/` and the build's `licenses/NOTICES.txt`. WalletConnect components use the WalletConnect Community License Agreement; publication does not assert commercial entitlement or Reown endorsement.

Tests use public contract runtimes and synthetic software-key fixtures. They are not production keys or evidence of physical Secure Enclave authentication.

## Migration status

The dedicated HTTPS hostname is deployed. On 2026-11-12, `node tests/pages-live.mjs` passed five live routes, three home links, secure context/config, four browser public RPC reads, and a genuine pending WalletConnect pairing with explicit PNG download and cancellation. The saved PNG matched the displayed canvas and was deleted after verification. No wallet approval, signing or sending occurred. The relay now admits the new origin; dashboard settings were not inspected. This fulfills the prerequisite for the private app source URL/origin switch; existing installed binaries and TestFlight distribution are separate.

## Deployment

The Pages workflow tests and builds `main`, uploads only `dist/`, and deploys with the GitHub Pages OIDC workflow. No app/TestFlight release is performed here.
