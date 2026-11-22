import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { buildWiki } from '../build-wiki.mjs';

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'webscan-wiki-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = path.join(root, 'docs');
  const output = path.join(root, 'wiki');
  fs.mkdirSync(source);
  return { source, output, repository: 'owner/project', ref: 'abc123' };
}

test('rewrites document and source links, preserves code and generates navigation', (t) => {
  const options = fixture(t);
  fs.mkdirSync(path.join(options.source, 'nested'));
  fs.writeFileSync(path.join(options.source, 'Start.md'), '# Start\n[Next](nested/Next.md#section)\n[Source](../README.md)\n`[Code](missing.md)`\n```md\n[Code](missing.md)\n```\n[ref]: nested/Next.md\n');
  fs.writeFileSync(path.join(options.source, 'nested/Next.md'), '# Next\n');
  fs.writeFileSync(path.join(options.source, '../README.md'), '# Project\n');
  buildWiki(options);
  const start = fs.readFileSync(path.join(options.output, 'Start.md'), 'utf8');
  assert.match(start, /wiki\/nested--Next#section/);
  assert.match(start, /blob\/abc123\/README.md/);
  assert.match(start, /`\[Code\]\(missing.md\)`/);
  assert.match(start, /```md\n\[Code\]\(missing.md\)\n```/);
  assert.match(start, /\[ref\]: https:\/\/github.com\/owner\/project\/wiki\/nested--Next/);
  assert.match(fs.readFileSync(path.join(options.output, '_Sidebar.md'), 'utf8'), /\[Next\]/);
});

test('removes stale generated pages, preserves manually maintained pages and is repeatable', (t) => {
  const options = fixture(t);
  const doc = path.join(options.source, 'Old.md');
  fs.writeFileSync(doc, '# Old\n');
  buildWiki(options);
  fs.writeFileSync(path.join(options.output, 'Manual.md'), '# Manual\n');
  fs.renameSync(doc, path.join(options.source, 'New.md'));
  buildWiki(options);
  assert.equal(fs.existsSync(path.join(options.output, 'Old.md')), false);
  assert.equal(fs.existsSync(path.join(options.output, 'Manual.md')), true);
  const before = fs.readFileSync(path.join(options.output, 'Home.md'), 'utf8');
  buildWiki(options);
  assert.equal(fs.readFileSync(path.join(options.output, 'Home.md'), 'utf8'), before);
});

test('rejects colliding page names and broken links before writing', (t) => {
  const options = fixture(t);
  fs.writeFileSync(path.join(options.source, 'Home.md'), '# Reserved\n');
  assert.throws(() => buildWiki(options), /Reserved or duplicate/);
  fs.renameSync(path.join(options.source, 'Home.md'), path.join(options.source, 'Valid.md'));
  fs.writeFileSync(path.join(options.source, 'Valid.md'), '[Missing](missing.md)\n');
  assert.throws(() => buildWiki(options), /Missing or outside/);
  assert.equal(fs.existsSync(options.output), false);
});

test('rejects a stale-page manifest that could escape the output directory', (t) => {
  const options = fixture(t);
  fs.writeFileSync(path.join(options.source, 'Doc.md'), '# Document\n');
  fs.mkdirSync(options.output);
  fs.writeFileSync(path.join(options.output, '.webscan-wiki-pages.json'), '["../README.md"]');
  assert.throws(() => buildWiki(options), /Invalid generated-page manifest/);
});
