// Synthetic wire fixtures encoded with upstream MeshCentral's actual helpers.
// No agent identities, real certificates, private keys, or production data.
const common = require('../common.js');
const { mkdirSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');

const directory = join(__dirname, '../crates/mesh-protocol/tests/fixtures');
mkdirSync(directory, { recursive: true });
const short = (value) => Buffer.from(common.ShortToStr(value), 'binary');
const int = (value) => Buffer.from(common.IntToStr(value), 'binary');
const sequence = (length, offset = 0) => Buffer.from(Array.from({ length }, (_, i) => (i + offset) & 255));
const write = (name, pieces) => writeFileSync(join(directory, `${name}.hex`), `${Buffer.concat(pieces).toString('hex')}\n`);

write('challenge', [short(1), sequence(48), sequence(48, 128)]);
const info = [short(3), int(1), int(29), int(0x01020304), int(6), sequence(48, 32), int(0x80000011)];
const name = Buffer.from('lab-ā', 'utf8');
write('agent-info', [...info, short(name.length), name]);
write('agent-info-legacy-no-name', info);
write('certificate-proof-structure-only', [short(2), short(3), Buffer.from([1, 2, 3]), Buffer.from([4, 5, 6, 7])]);
