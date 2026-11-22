import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const manifestName = '.webscan-wiki-pages.json';
const reserved = new Set(['home', '_sidebar', '_footer']);
const encodePath = (value) => value.split('/').map(encodeURIComponent).join('/');

export function buildWiki({ source, output, repository, ref = 'main' }) {
  if (!/^[\w.-]+\/[\w.-]+$/.test(repository)) throw new Error('Expected repository in owner/name format.');
  const sourceRoot = path.resolve(source);
  const outputRoot = path.resolve(output);
  const repoRoot = path.dirname(sourceRoot);
  if (sourceRoot === outputRoot || outputRoot.startsWith(sourceRoot + path.sep)
      || sourceRoot.startsWith(outputRoot + path.sep)) {
    throw new Error('Source and output directories must not overlap.');
  }
  const files = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name.startsWith('.')) continue;
      const filename = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(filename);
      else if (entry.isFile() && /\.md$/i.test(entry.name)) files.push(filename);
    }
  }
  walk(sourceRoot);
  files.sort();
  if (!files.length) throw new Error('No Markdown documents found.');

  const names = new Set();
  const pages = files.map((filename) => {
    const relative = path.relative(sourceRoot, filename).split(path.sep).join('/');
    const slug = relative.replace(/\.md$/i, '').replaceAll('/', '--').replace(/[^\p{L}\p{N}_.-]/gu, '-');
    if (reserved.has(slug.toLowerCase()) || names.has(slug.toLowerCase())) {
      throw new Error(`Reserved or duplicate Wiki page name: ${relative}`);
    }
    names.add(slug.toLowerCase());
    const content = fs.readFileSync(filename, 'utf8');
    const title = content.match(/^#\s+(.+)$/m)?.[1].trim() ?? slug;
    return { filename, slug, title, content };
  });
  const wikiBase = `https://github.com/${repository}/wiki`;
  const pageByFile = new Map(pages.map((page) => [page.filename, page]));

  function rewriteTarget(target, filename, image) {
    if (/^(?:[a-z][a-z\d+.-]*:|#|\/)/i.test(target)) return target;
    const match = target.match(/^([^?#]*)([?#].*)?$/);
    let decoded;
    try { decoded = decodeURIComponent(match[1]); } catch { return target; }
    const resolved = path.resolve(path.dirname(filename), decoded);
    const suffix = match[2] ?? '';
    const page = pageByFile.get(resolved);
    if (page) return `${wikiBase}/${encodeURIComponent(page.slug)}${suffix}`;
    const relative = path.relative(repoRoot, resolved).split(path.sep).join('/');
    if (relative.startsWith('../') || !fs.existsSync(resolved)) {
      throw new Error(`Missing or outside-repository link in ${filename}: ${target}`);
    }
    return image
      ? `https://raw.githubusercontent.com/${repository}/${encodeURIComponent(ref)}/${encodePath(relative)}${suffix}`
      : `https://github.com/${repository}/blob/${encodeURIComponent(ref)}/${encodePath(relative)}${suffix}`;
  }

  function rewrite(content, filename) {
    let fence = null;
    return content.split('\n').map((line) => {
      const marker = line.match(/^\s{0,3}(`{3,}|~{3,})/);
      if (marker) {
        if (!fence) fence = marker[1];
        else if (marker[1][0] === fence[0] && marker[1].length >= fence.length) fence = null;
        return line;
      }
      if (fence) return line;
      // Preserve inline code; transform ordinary and image Markdown links.
      return line.split(/(`+[^`]*`+)/g).map((part, index) => {
        if (index % 2) return part;
        return part
          .replace(/(!?\[[^\]]*\]\()(<[^>]*>|[^\s)]+)([^)]*\))/g, (_, prefix, target, tail) => {
            const angle = target.startsWith('<');
            const rewritten = rewriteTarget(angle ? target.slice(1, -1) : target, filename, prefix.startsWith('!'));
            return prefix + (angle ? `<${rewritten}>` : rewritten) + tail;
          })
          .replace(/^(\s{0,3}\[[^\]]+\]:\s*)(<[^>]*>|\S+)(.*)$/, (_, prefix, target, tail) => {
            const angle = target.startsWith('<');
            const rewritten = rewriteTarget(angle ? target.slice(1, -1) : target, filename, false);
            return prefix + (angle ? `<${rewritten}>` : rewritten) + tail;
          });
      }).join('');
    }).join('\n');
  }

  // Render and validate everything before changing the target checkout.
  const rendered = new Map(pages.map((page) => [`${page.slug}.md`, rewrite(page.content, page.filename)]));
  const navigation = pages.map((page) => `- [${page.title}](${wikiBase}/${encodeURIComponent(page.slug)})`).join('\n');
  rendered.set('Home.md', `# Dokumentacja WebScan\n\n${navigation}\n\nŹródłem dokumentacji są [pliki Markdown w docs](https://github.com/${repository}/tree/main/docs). Zmiany należy wprowadzać w repozytorium; publikacja Wiki odbywa się automatycznie.\n`);
  rendered.set('_Sidebar.md', `[Strona główna](${wikiBase})\n\n${navigation}\n`);
  rendered.set('_Footer.md', `Dokumentacja publikowana z [katalogu docs](https://github.com/${repository}/tree/main/docs).\n`);

  fs.mkdirSync(outputRoot, { recursive: true });
  const manifestPath = path.join(outputRoot, manifestName);
  const previous = fs.existsSync(manifestPath) ? JSON.parse(fs.readFileSync(manifestPath, 'utf8')) : [];
  if (!Array.isArray(previous) || previous.some((name) => typeof name !== 'string'
      || !/^[\p{L}\p{N}_.-]+\.md$/u.test(name) || name.includes('..'))) {
    throw new Error('Invalid generated-page manifest.');
  }
  for (const name of previous) {
    if (!rendered.has(name)) fs.rmSync(path.join(outputRoot, name), { force: true });
  }
  for (const [name, content] of rendered) fs.writeFileSync(path.join(outputRoot, name), content);
  fs.writeFileSync(manifestPath, JSON.stringify([...rendered.keys()].sort(), null, 2) + '\n');
  return [...rendered.keys()];
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { values } = parseArgs({ options: {
    source: { type: 'string', default: 'docs' },
    output: { type: 'string' },
    repository: { type: 'string' },
    ref: { type: 'string', default: 'main' },
  } });
  if (!values.output || !values.repository) throw new Error('--output and --repository are required.');
  console.log(`Generated ${buildWiki(values).length} Wiki pages.`);
}
