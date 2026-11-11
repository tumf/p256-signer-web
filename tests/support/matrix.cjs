'use strict';
// Required Web evidence IDs (no sampling). The authority is the frozen exact inventory of delegate-deployment-fees
// (`ui-inventory.json`, active or archived): the original Web inventory expansion (every W row x variant x
// {390, 1280}; W01 also 679/680/681 and 320-text200) plus the transactional-storage rows W27/W28, with the
// wallet-delegated transformations (retired cap/consent/fee-override rows, W15.ready/blocked, W16.provider, v2
// wallet-selected-fee W20 rows and the historical v1 L20/L22 rows). `expand` still derives the original matrices so
// the inventory can be cross-checked against them.
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const INVENTORY_CHANGE = 'delegate-deployment-fees';
const INVENTORY_COUNT = 204;

/** A change's file, active or archived (newest archive first). */
function changeFile(change, file) {
  const active = path.join(root, 'openspec/changes', change, file);
  if (fs.existsSync(active)) return active;
  const archive = path.join(root, 'openspec/changes/archive');
  for (const name of fs.existsSync(archive) ? fs.readdirSync(archive).sort().reverse() : []) {
    const candidate = path.join(archive, name, file);
    if (name.endsWith(`-${change}`) && fs.existsSync(candidate)) return candidate;
  }
  throw new Error(`${change}/${file} not found`);
}

/** The original deployment matrix, active or archived. */
function matrixPath() {
  return changeFile('add-wallet-deployment-web', 'ui-state-matrix.md');
}

/** The additional storage inventory of harden-web-attempt-transactions, active or archived. */
function additionalMatrixPath() {
  return changeFile('harden-web-attempt-transactions', 'ui-state-matrix.md');
}

/** The wallet-delegated deployment matrix (W24 control list) and its frozen inventory. */
function changeMatrixPath() {
  return changeFile(INVENTORY_CHANGE, 'ui-state-matrix.md');
}

function inventoryPath() {
  return changeFile(INVENTORY_CHANGE, 'ui-inventory.json');
}

/** The frozen inventory: exact count, no duplicate IDs, every row typed with its record version. */
function inventory() {
  const data = JSON.parse(fs.readFileSync(inventoryPath(), 'utf8'));
  const states = data.states;
  if (!Array.isArray(states) || data.count !== INVENTORY_COUNT || states.length !== INVENTORY_COUNT) {
    throw new Error(`ui-inventory.json must list exactly ${INVENTORY_COUNT} rows`);
  }
  const ids = states.map((s) => s.id);
  const duplicate = ids.filter((id, i) => ids.indexOf(id) !== i);
  if (duplicate.length) throw new Error(`ui-inventory.json duplicates ${duplicate.join(', ')}`);
  for (const s of states) {
    if (![1, 2].includes(s.recordVersion) || typeof s.fixture !== 'string' || !s.viewport) {
      throw new Error(`ui-inventory.json row ${s.id} is malformed`);
    }
  }
  return states;
}

/** Every required state, in inventory order. */
function expandAll() {
  return inventory();
}

/** Original inventory rows followed by the additional storage rows (pre-delegation expansion). */
function expandOriginal() {
  return [...expand(fs.readFileSync(matrixPath(), 'utf8')),
    ...expand(fs.readFileSync(additionalMatrixPath(), 'utf8'), { whole: true })];
}

/** The W24 control names of the wallet-delegated matrix (`W24 controls: a/b/...`). */
function w24Controls() {
  const line = fs.readFileSync(changeMatrixPath(), 'utf8').split('\n').find((l) => l.startsWith('W24 controls:'));
  const listed = /^W24 controls: ([a-z/-]+)[.;]/.exec(line || '');
  if (!listed) throw new Error('delegate-deployment-fees ui-state-matrix.md W24 control list not found');
  return listed[1].split('/');
}

function expand(markdown, { whole = false } = {}) {
  const web = whole ? markdown : markdown.split('## Web inventory')[1].split('\n## ')[0];
  const rows = [];
  for (const line of web.split('\n')) {
    const match = /^\| (W\d\d)(?: `([^`]+)`)? \|/.exec(line);
    if (!match) continue;
    const variants = match[2] ? match[2].split(',').map((v) => v.trim().replace(/^\./, '')) : [null];
    for (const variant of variants) rows.push({ row: match[1], variant });
  }
  const states = [];
  for (const { row, variant } of rows) {
    const widths = row === 'W01' ? ['390', '1280', '679', '680', '681', '320-text200'] : ['390', '1280'];
    for (const width of widths) {
      const fixture = variant ? `${row}.${variant}` : row;
      const textScale = width.endsWith('-text200') ? 2 : 1;
      states.push({ id: `${fixture}.${width}`, row, variant, fixture,
        viewport: { width: Number.parseInt(width, 10), height: 900 }, textScale,
        locale: 'ja-JP', colorScheme: 'light', reducedMotion: 'reduce' });
    }
  }
  return states;
}

module.exports = { matrixPath, additionalMatrixPath, changeMatrixPath, inventoryPath, inventory, expand, expandAll,
  expandOriginal, w24Controls, INVENTORY_COUNT };

if (require.main === module) {
  const states = expandAll();
  const out = { source: `openspec/changes/${INVENTORY_CHANGE}/ui-inventory.json`, count: states.length, states };
  fs.writeFileSync(path.join(__dirname, '../ui-states.json'), JSON.stringify(out, null, 2) + '\n');
  console.log(`wrote ${states.length} required Web states`);
}
