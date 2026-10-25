// Build-time compression / gate-time verification using Node's standard library.
import {readFileSync, writeFileSync} from 'node:fs';
import {brotliCompressSync, brotliDecompressSync, constants} from 'node:zlib';

const [mode, path] = process.argv.slice(2);
if (!['compress', 'decompress'].includes(mode)) throw new Error('Invalid Brotli operation');
const input = readFileSync(path || 0);
writeFileSync(1, mode === 'decompress' ? brotliDecompressSync(input) : brotliCompressSync(input, {
  params: {[constants.BROTLI_PARAM_QUALITY]: 9},
}));
