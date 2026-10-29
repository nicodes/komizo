import fs from 'node:fs/promises';
import path from 'node:path';
import {readActionBinding, validateLock} from './setup.mjs';

const workspace = path.resolve(process.env.GITHUB_WORKSPACE || process.cwd());
const directory = path.resolve(workspace, process.env.KOMIZO_DIRECTORY || '.');
if (directory !== workspace && !directory.startsWith(workspace + path.sep)) {
  throw new Error('project directory leaves the workspace');
}
const lock = JSON.parse(await fs.readFile(path.join(directory, 'komizo.lock'), 'utf8'));
validateLock(lock, process.env.KOMIZO_ACTION_SOURCE || '', await readActionBinding(directory));
