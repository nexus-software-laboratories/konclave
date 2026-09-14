import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { unzipSync } from 'fflate';

import {
  MarketplaceContractError,
  createMarketplacePlan,
  marketplaceCatalogPath,
  marketplaceOutputPaths,
  marketplacePluginRoot,
} from './marketplace-contract.mjs';

const maximumArchiveBytes = 2 * 1024 * 1024;

function fail(code, message) {
  throw new MarketplaceContractError(code, message);
}

function readJson(path, description) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    fail('release_contract_invalid', `${description} is missing or invalid.`);
  }
}

function resolveManagedPath(root, path) {
  if (isAbsolute(path) || path.includes('\\')) {
    fail('marketplace_path_invalid', `Marketplace path is invalid: ${path}`);
  }
  const target = resolve(root, ...path.split('/'));
  if (target !== root && !target.startsWith(`${root}${sep}`)) {
    fail('marketplace_path_invalid', `Marketplace path escapes its root: ${path}`);
  }
  return target;
}

function readTreeFiles(root, directory) {
  const start = resolveManagedPath(root, directory);
  if (!existsSync(start)) {
    return [];
  }
  if (lstatSync(start).isSymbolicLink() || !lstatSync(start).isDirectory()) {
    fail('marketplace_tree_invalid', `Marketplace directory is unsafe: ${directory}`);
  }

  const files = [];
  const pending = [start];
  while (pending.length > 0) {
    const current = pending.pop();
    for (const name of readdirSync(current)) {
      const path = resolve(current, name);
      const status = lstatSync(path);
      if (status.isSymbolicLink()) {
        fail('marketplace_tree_invalid', `Marketplace tree contains a symbolic link: ${name}`);
      }
      if (status.isDirectory()) {
        pending.push(path);
      } else if (status.isFile()) {
        files.push(relative(root, path).split(sep).join('/'));
      } else {
        fail('marketplace_tree_invalid', `Marketplace tree contains a special file: ${name}`);
      }
    }
  }
  return files.sort();
}

function expectedManagedPaths() {
  return [...marketplaceOutputPaths].sort();
}

function actualManagedPaths(root) {
  return [
    ...readTreeFiles(root, dirname(marketplaceCatalogPath).split(sep).join('/')),
    ...readTreeFiles(root, marketplacePluginRoot),
  ].sort();
}

function assertMarketplaceTree(root, plan) {
  const actualPaths = actualManagedPaths(root);
  const expectedPaths = expectedManagedPaths();
  if (JSON.stringify(actualPaths) !== JSON.stringify(expectedPaths)) {
    fail(
      'marketplace_tree_invalid',
      `Marketplace tree must contain exactly: ${expectedPaths.join(', ')}`,
    );
  }
  for (const file of plan.files) {
    const target = resolveManagedPath(root, file.path);
    const status = lstatSync(target);
    if (!status.isFile() || status.isSymbolicLink()) {
      fail('marketplace_tree_invalid', `Marketplace file is unsafe: ${file.path}`);
    }
    if (!readFileSync(target).equals(file.bytes)) {
      fail('marketplace_bytes_mismatch', `Marketplace file differs from Release: ${file.path}`);
    }
  }
}

function readReleasePlan(releaseDirectory) {
  const releaseRoot = resolve(releaseDirectory);
  const manifest = readJson(resolve(releaseRoot, 'RELEASE.json'), 'Release manifest');
  const version = manifest?.release?.version;
  const pluginArtifacts = Array.isArray(manifest?.artifacts)
    ? manifest.artifacts.filter(
        (artifact) => artifact?.id === 'konclave-agent-plugin' && artifact?.kind === 'plugin',
      )
    : [];
  if (
    typeof version !== 'string' ||
    pluginArtifacts.length !== 1 ||
    pluginArtifacts[0].fileName !== `konclave-${version}.zip`
  ) {
    fail('release_contract_invalid', 'Release manifest has no exact Konclave Agent Plugin.');
  }

  const artifactFileName = pluginArtifacts[0].fileName;
  const archivePath = resolveManagedPath(releaseRoot, artifactFileName);
  if (!existsSync(archivePath) || lstatSync(archivePath).isSymbolicLink()) {
    fail('release_contract_invalid', 'Release Agent Plugin archive is missing or unsafe.');
  }
  const archive = readFileSync(archivePath);
  if (archive.byteLength === 0 || archive.byteLength > maximumArchiveBytes) {
    fail('release_contract_invalid', 'Release Agent Plugin archive exceeds its size contract.');
  }

  let checksumText;
  try {
    checksumText = readFileSync(resolve(releaseRoot, 'SHA256SUMS'), 'utf8');
  } catch {
    fail('release_contract_invalid', 'Release checksum manifest is missing.');
  }
  const checksumLines = checksumText.split(/\r?\n/).filter((line) => line.length > 0);
  const matchingChecksums = checksumLines.filter((line) => line.endsWith(`  ${artifactFileName}`));
  if (matchingChecksums.length !== 1) {
    fail('release_contract_invalid', 'Release checksum manifest does not name the plugin once.');
  }
  const expectedDigest = matchingChecksums[0].slice(0, 64);
  if (!/^[0-9a-f]{64}$/.test(expectedDigest)) {
    fail('release_contract_invalid', 'Release Agent Plugin checksum is invalid.');
  }
  const actualDigest = createHash('sha256').update(archive).digest('hex');
  if (actualDigest !== expectedDigest) {
    fail('release_checksum_mismatch', 'Release Agent Plugin checksum does not match.');
  }

  let provenance;
  try {
    const statements = readFileSync(
      resolve(releaseRoot, `${artifactFileName}.intoto.jsonl`),
      'utf8',
    )
      .split(/\r?\n/)
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line));
    if (statements.length !== 1) {
      fail('release_provenance_invalid', 'Release Agent Plugin provenance is not singular.');
    }
    [provenance] = statements;
  } catch (error) {
    if (error instanceof MarketplaceContractError) {
      throw error;
    }
    fail('release_provenance_invalid', 'Release Agent Plugin provenance is missing or invalid.');
  }
  const externalParameters = provenance?.predicate?.buildDefinition?.externalParameters;
  const sourceCommits = (
    provenance?.predicate?.buildDefinition?.resolvedDependencies ?? []
  ).flatMap((dependency) => {
    const commit = dependency?.digest?.gitCommit;
    return typeof commit === 'string' && /^[0-9a-f]{40}$/.test(commit) ? [commit] : [];
  });
  if (
    provenance?._type !== 'https://in-toto.io/Statement/v1' ||
    provenance?.predicateType !== 'https://slsa.dev/provenance/v1' ||
    provenance?.subject?.length !== 1 ||
    provenance.subject[0]?.name !== artifactFileName ||
    provenance.subject[0]?.digest?.sha256 !== actualDigest ||
    externalParameters?.artifactId !== 'konclave-agent-plugin' ||
    externalParameters?.buildKind !== 'plugin' ||
    externalParameters?.target !== 'portable' ||
    externalParameters?.version !== version ||
    sourceCommits.length !== 1
  ) {
    fail('release_provenance_invalid', 'Release Agent Plugin provenance does not match.');
  }

  let entries;
  try {
    entries = unzipSync(new Uint8Array(archive));
  } catch {
    fail('release_archive_invalid', 'Release Agent Plugin archive cannot be decoded.');
  }
  const plan = createMarketplacePlan({
    releaseVersion: version,
    artifactFileName,
    entries,
  });
  return {
    ...plan,
    sourceCommit: sourceCommits[0],
  };
}

export function materializeMarketplace({ releaseDirectory, outputRoot, checkOnly = false }) {
  const root = resolve(outputRoot);
  const plan = readReleasePlan(releaseDirectory);
  if (checkOnly) {
    assertMarketplaceTree(root, plan);
    return plan;
  }

  const existingPaths = actualManagedPaths(root);
  const unexpected = existingPaths.filter((path) => !marketplaceOutputPaths.includes(path));
  if (unexpected.length > 0) {
    fail(
      'marketplace_tree_invalid',
      `Marketplace tree contains unexpected files: ${unexpected.join(', ')}`,
    );
  }
  for (const file of plan.files) {
    const target = resolveManagedPath(root, file.path);
    mkdirSync(dirname(target), { recursive: true });
    if (existsSync(target) && (lstatSync(target).isSymbolicLink() || !lstatSync(target).isFile())) {
      fail('marketplace_tree_invalid', `Marketplace target is unsafe: ${file.path}`);
    }
    const temporary = `${target}.tmp`;
    rmSync(temporary, { force: true });
    try {
      writeFileSync(temporary, file.bytes, { mode: 0o644 });
      if (process.platform === 'win32' && existsSync(target)) {
        rmSync(target);
      }
      renameSync(temporary, target);
    } finally {
      rmSync(temporary, { force: true });
    }
    if (process.platform !== 'win32') {
      chmodSync(target, 0o644);
    }
  }
  assertMarketplaceTree(root, plan);
  return plan;
}

function option(name) {
  const index = process.argv.indexOf(name);
  const value = index >= 0 ? process.argv[index + 1] : null;
  if (!value) {
    fail('argument_invalid', `${name} is required.`);
  }
  return value;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const plan = materializeMarketplace({
    releaseDirectory: option('--release-directory'),
    outputRoot: option('--output-root'),
    checkOnly: process.argv.includes('--check'),
  });
  console.log(
    `${process.argv.includes('--check') ? 'Verified' : 'Materialized'} marketplace ${plan.version}.`,
  );
}
