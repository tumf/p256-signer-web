// Locked offline build: verifies pinned inputs, bundles self-hosted static assets with lazy WalletConnect
// and QR chunks into dist/, copies licenses verbatim and writes a SHA-256 asset manifest for serve.py.
import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as esbuild from 'esbuild';

const here = path.dirname(fileURLToPath(import.meta.url));
// REGISTRATION_DIST lets self-contained tests build into a temporary directory; serving uses dist/.
const dist = process.env.REGISTRATION_DIST ? path.resolve(process.env.REGISTRATION_DIST) : path.join(here, 'dist');
const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const read = (name) => readFileSync(path.join(here, name));
const fail = (message) => { console.error(`build failed: ${message}`); process.exit(1); };

export const PROXY_SHA256 = '103c4d3815dd2472c4a257bcd94e8b8b49ce39de453add9d8285b749bb926aa7';
export const REOWN_NOTICE = 'Portions © 2025 Reown, Inc. All Rights Reserved';
const licenses = JSON.parse(read('licenses.json'));

// 1. Pinned inputs.
if (sha256(read('vendor/proxy.json')) !== PROXY_SHA256) fail('vendor/proxy.json SHA-256 changed');
const lock = JSON.parse(read('package-lock.json'));
if (lock.lockfileVersion !== 3) fail('package-lock.json must be lockfile v3');
const sdk = lock.packages['node_modules/@safe-global/protocol-kit'];
if (sdk?.version !== '8.0.7' || sdk.integrity !== 'sha512-QKbRQmaQWHxsKB3/cogQ0JBzsnewSo2yoMvTvepicBy5N1C3FPRjiRGJBfQ/H9v881BvsLZXggbIh7e4qrjidg==') fail('Safe SDK pin/integrity drift');
for (const entry of licenses.packages) {
  if (!entry.vendored) {
    const installed = JSON.parse(read(`node_modules/${entry.package}/package.json`));
    const locked = lock.packages[`node_modules/${entry.package}`];
    if (installed.version !== entry.version || !locked || locked.version !== entry.version) {
      fail(`${entry.package} is not the pinned ${entry.version}`);
    }
  }
  const vendored = read(entry.vendorPath);
  if (sha256(vendored) !== entry.sha256) fail(`${entry.vendorPath} SHA-256 differs from licenses.json`);
  if (entry.origin) {
    const original = read(entry.origin);
    if (!original.equals(vendored)) fail(`${entry.vendorPath} is not byte-identical to ${entry.origin}`);
  }
}

// 2. Bundle. AppKit is only reachable through the default QR modal (showQrModal: true), which this
// product never enables; resolving it to a throwing module keeps it out of every chunk.
const noAppKit = {
  name: 'no-appkit',
  setup(build) {
    build.onResolve({ filter: /^@reown\/appkit/ }, (args) => ({ path: args.path, namespace: 'no-appkit' }));
    build.onLoad({ filter: /.*/, namespace: 'no-appkit' }, () => ({
      contents: 'throw new Error("AppKit is excluded from this build (showQrModal is false)");', loader: 'js',
    }));
  },
};
let metafile;
rmSync(dist, { recursive: true, force: true });
mkdirSync(path.join(dist, 'licenses'), { recursive: true });
const bundleOptions = {
  absWorkingDir: here, bundle: true, splitting: true, format: 'esm', outdir: dist,
  platform: 'browser', target: ['es2022'], minify: true, legalComments: 'none', sourcemap: false,
  define: { 'process.env.NODE_ENV': '"production"', global: 'globalThis' },
  banner: { js: `/*! ${REOWN_NOTICE}. Licenses: https://tumf.github.io/p256-signer-web/licenses/NOTICES.txt */` }, plugins: [noAppKit],
  logLevel: 'warning', metafile: true,
};
// Deployment, Safe approval, execution preparation and key-change have separate builds: the deployment bundle
// and its chunk graph stay exactly as before, and the pages share no chunk or SDK module instance.
const deployment = await esbuild.build({ ...bundleOptions, entryPoints: ['app.js'], chunkNames: 'chunks/[name]-[hash]' });
const safe = await esbuild.build({ ...bundleOptions, entryPoints: ['safe-request.js'], chunkNames: 'chunks/safe-[name]-[hash]' });
const key = await esbuild.build({ ...bundleOptions, entryPoints: ['key-change.js'], chunkNames: 'chunks/key-[name]-[hash]' });
// The separate EntryPoint prefund page: its own entry and chunk graph (no GPL EntryPoint runtime is ever bundled).
const prefund = await esbuild.build({ ...bundleOptions, entryPoints: ['prefund.js'], chunkNames: 'chunks/prefund-[name]-[hash]' });
const execute = await esbuild.build({ ...bundleOptions, entryPoints: ['safe-execute.js'], chunkNames: 'chunks/execute-[name]-[hash]' });
metafile = { inputs: { ...execute.metafile.inputs, ...deployment.metafile.inputs, ...safe.metafile.inputs, ...key.metafile.inputs,
  ...prefund.metafile.inputs } };

/** Directory (relative to here) of the innermost node_modules/<pkg|@scope/pkg> in an esbuild input path. */
function packageDir(input) {
  const at = input.lastIndexOf('node_modules/');
  if (at < 0) return null;
  const rest = input.slice(at + 'node_modules/'.length).split('/');
  const name = rest[0].startsWith('@') ? `${rest[0]}/${rest[1]}` : rest[0];
  return input.slice(0, at) + 'node_modules/' + name;
}

const LICENSE_FILE = /^(licen[cs]e|copying|notice)/i;
const authorText = (author) => (author && typeof author === 'object'
  ? [author.name, author.email && `<${author.email}>`, author.url && `(${author.url})`].filter(Boolean).join(' ')
  : author || '');

/** Every node_modules package (including nested node_modules copies) whose files esbuild bundled into any
 * chunk (all metafile inputs, conservatively including tree-shaken ones), with its declared license,
 * copyright lines and full shipped license/notice text. */
function bundledPackages() {
  const dirs = new Set(Object.keys(metafile.inputs).map(packageDir).filter(Boolean));
  if (dirs.size === 0) fail('metafile lists no bundled npm packages');
  const byId = new Map();
  for (const dir of [...dirs].sort()) {
    const meta = JSON.parse(read(`${dir}/package.json`));
    const license = typeof meta.license === 'string' ? meta.license
      : meta.license?.type || (Array.isArray(meta.licenses) && meta.licenses.map((l) => l.type).join(' OR ')) || 'UNKNOWN';
    const id = `${meta.name}@${meta.version}`;
    const entry = byId.get(id) || { id, name: meta.name, version: meta.version, license, author: authorText(meta.author),
      paths: [], texts: [] };
    entry.paths.push(dir);
    if (entry.texts.length === 0) {
      for (const file of readdirSync(path.join(here, dir)).filter((f) => LICENSE_FILE.test(f)).sort()) {
        if (statSync(path.join(here, dir, file)).isFile()) {
          entry.texts.push({ file, text: read(`${dir}/${file}`).toString('utf8').replace(/\r\n/g, '\n').trimEnd() });
        }
      }
    }
    byId.set(id, entry);
  }
  return [...byId.values()].sort((a, b) => a.id.localeCompare(b.id));
}

const MIT_TEXT = `Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction, including without
limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of
the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.`;

/** One NOTICES.txt section per bundled package: license id, copyright lines and every license text. */
function packageNotice(entry) {
  const copyright = [...new Set(entry.texts.flatMap(({ text }) => text.split('\n'))
    .map((line) => line.trim()).filter((line) => /^(copyright\b|\(c\)|©)/i.test(line)))];
  const lines = [`==== BEGIN PACKAGE ${entry.id} ====`, `name: ${entry.name}`, `version: ${entry.version}`,
    `license: ${entry.license}`, ...entry.paths.map((dir) => `path: ${dir}`)];
  if (entry.author) lines.push(`author: ${entry.author}`);
  lines.push(...(copyright.length ? copyright.map((line) => `copyright: ${line}`)
    : [`copyright: ${entry.author || 'not stated by the package'}`]));
  if (entry.texts.length === 0) {
    lines.push('---- license text: none (no license file shipped) ----',
      `no license file shipped; package.json declares license "${entry.license}"`
        + (entry.author ? ` by ${entry.author}` : ''));
    // The declared SPDX license's standard text, so the notice still carries the permission terms.
    if (entry.license === 'MIT') lines.push('', 'Standard MIT License text (SPDX MIT):', '', MIT_TEXT);
    else fail(`${entry.id} ships no license file and declares ${entry.license}; add its standard text`);
  }
  for (const { file, text } of entry.texts) lines.push(`---- license text: ${file} ----`, text);
  lines.push(`==== END PACKAGE ${entry.id} ====`, '');
  return lines;
}

// 3. Static files and verbatim licenses.
const pages = ['index.html', 'safe-request.html', 'safe-execute.html', 'key-change.html', 'prefund.html'];
const csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
  + "connect-src 'self' https://p256-signer.mini.tumf.dev wss://relay.walletconnect.com https://relay.walletconnect.com "
  + "https://verify.walletconnect.org https://verify.walletconnect.com; "
  + "frame-src https://verify.walletconnect.org https://verify.walletconnect.com; "
  + "base-uri 'none'; form-action 'none'; object-src 'none'";
for (const name of pages) {
  const pageCSP = name === 'index.html' || name === 'prefund.html' ? csp.replace(/frame-src [^;]+;/, '') : csp;
  writeFileSync(path.join(dist, name), read(name).toString().replace('<meta charset="utf-8">',
    '<meta charset="utf-8">\n<meta http-equiv="Content-Security-Policy" content="' + pageCSP + '">'));
}
cpSync(path.join(here, 'styles.css'), path.join(dist, 'styles.css'));
const projectId = process.env.WALLETCONNECT_PROJECT_ID || '';
if (projectId && !/^[0-9a-f]{32}$/.test(projectId)) fail('WALLETCONNECT_PROJECT_ID must be the public 32-hex project ID');
writeFileSync(path.join(dist, 'config.json'), JSON.stringify({ walletConnectProjectId: projectId || null,
  allowedDeploymentOrigin: 'https://tumf.github.io' }));
writeFileSync(path.join(dist, '.nojekyll'), '');
const bundled = bundledPackages();
const notices = [
  'P-256 Signer deployment Web — third-party notices', '',
  `${REOWN_NOTICE}`, '',
  ...licenses.packages.flatMap((entry) => [
    `${entry.package} ${entry.version}`, `  license: ${entry.license}`, `  source: ${entry.source}`,
    `  license text: ./${entry.servedPath} (SHA-256 ${entry.sha256})`, '']),
  'WalletConnect Community License Agreement conditions are reproduced verbatim at',
  '/licenses/walletconnect-LICENSE.md. This notice is not legal approval, registration,',
  'commercial entitlement or Reown endorsement.', '',
  'Bundled npm packages (name@version license), including nested node_modules copies:',
  ...bundled.map((entry) => `  ${entry.id} ${entry.license}`), '',
  'Per-package license texts and copyright lines (as shipped in each package):', '',
  ...bundled.flatMap(packageNotice),
];
for (const entry of licenses.packages) cpSync(path.join(here, entry.vendorPath), path.join(dist, entry.servedPath));
writeFileSync(path.join(dist, 'licenses/NOTICES.txt'), notices.join('\n'));

// 4. Asset manifest (every served file and its hash).
const files = {};
const walk = (dir) => {
  for (const name of readdirSync(dir).sort()) {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) walk(full);
    else files[path.relative(dist, full).split(path.sep).join('/')] = sha256(readFileSync(full));
  }
};
walk(dist);
const chunks = Object.keys(files).filter((name) => name.endsWith('.js'));
for (const name of chunks) {
  const text = readFileSync(path.join(dist, name), 'utf8');
  if (/appkit\/core|@reown\/appkit-|cdn\.|https:\/\/fonts\./.test(text) && !/AppKit is excluded/.test(text)) {
    fail(`${name} references AppKit or a remote resource`);
  }
  if (!text.startsWith(`/*! ${REOWN_NOTICE}`)) fail(`${name} lacks the distributed notice`);
}
const manifest = { proxySHA256: PROXY_SHA256, packages: Object.fromEntries(licenses.packages.map((e) => [e.package,
  e.version])), entry: 'app.js', files };
writeFileSync(path.join(dist, 'asset-manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log(`built ${Object.keys(files).length} assets (${chunks.length} JS chunks) into dist/`);
