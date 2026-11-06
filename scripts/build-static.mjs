import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateData } from './validate-data.mjs';

export const PUBLIC_FILES = [
  'index.html', 'data.json', 'combiner/index.html',
  'combiner/catalog.json', 'combiner/playbooks.json',
];
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

export async function buildStatic(root = ROOT) {
  // Read/validate everything before touching the previous build.
  const contents = new Map(await Promise.all(PUBLIC_FILES.map(async path => [path, await readFile(join(root, path))])));
  validateData(JSON.parse(contents.get('data.json')));
  const catalog = JSON.parse(contents.get('combiner/catalog.json'));
  const playbooks = JSON.parse(contents.get('combiner/playbooks.json'));
  if (!Array.isArray(catalog.skills) || catalog.count !== catalog.skills.length || catalog.count === 0) {
    throw new Error('Invalid combiner catalog');
  }
  const slugs = new Set(catalog.skills.map(skill => skill.slug));
  if (slugs.size !== catalog.count || [...slugs].some(slug => typeof slug !== 'string' || !slug)) {
    throw new Error('Invalid or duplicate catalog slug');
  }
  if (!Array.isArray(playbooks.playbooks) || playbooks.count !== playbooks.playbooks.length || playbooks.count === 0) {
    throw new Error('Invalid combiner playbooks');
  }
  for (const playbook of playbooks.playbooks) {
    if (!Array.isArray(playbook.steps) || !playbook.steps.length || playbook.steps.some(step => !slugs.has(step.slug))) {
      throw new Error('Playbook references an unknown skill');
    }
  }
  const output = join(root, 'public');
  await rm(output, { recursive: true, force: true });
  await mkdir(join(output, 'combiner'), { recursive: true });
  for (const path of PUBLIC_FILES) await writeFile(join(output, path), contents.get(path));
  return { output, files: PUBLIC_FILES.length, sources: JSON.parse(contents.get('data.json')).okCount };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await buildStatic();
  console.log(`Static build: ${result.files} public files, ${result.sources}/8 sources; no runtime required.`);
}
