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
import { agentPluginExtensionEntryPath } from './package-contract.mjs';

const maximumArchiveBytes = 2 * 1024 * 1024;
const maximumReleaseContractBytes = 1024 * 1024;

function fail(code, message) {
  throw new MarketplaceContractError(code, message);
}

function readBoundedFile(path, maximumBytes, description) {
  try {
    const status = lstatSync(path);
    if (
      status.isSymbolicLink() ||
      !status.isFile() ||
      status.size === 0 ||
      status.size > maximumBytes
    ) {
      fail('release_contract_invalid', `${description} is unsafe or oversized.`);
    }
    return readFileSync(path);
  } catch (error) {
    if (error instanceof MarketplaceContractError) {
      throw error;
    }
    fail('release_contract_invalid', `${description} is missing or unsafe.`);
  }
}

function readJson(path, description) {
  try {
    return JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(
        readBoundedFile(path, maximumReleaseContractBytes, description),
      ),
    );
  } catch (error) {
    if (error instanceof MarketplaceContractError) {
      throw error;
    }
    fail('release_contract_invalid', `${description} is invalid JSON.`);
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
  const archive = readBoundedFile(archivePath, maximumArchiveBytes, 'Release Agent Plugin archive');

  let checksumText;
  try {
    checksumText = new TextDecoder('utf-8', { fatal: true }).decode(
      readBoundedFile(
        resolve(releaseRoot, 'SHA256SUMS'),
        maximumReleaseContractBytes,
        'Release checksum manifest',
      ),
    );
  } catch (error) {
    if (error instanceof MarketplaceContractError) {
      throw error;
    }
    fail('release_contract_invalid', 'Release checksum manifest is invalid UTF-8.');
  }
  const checksumLines = checksumText.split(/\r?\n/).filter((line) => line.length > 0);
  const matchingChecksums = checksumLines.flatMap((line) => {
    const match = /^([0-9a-f]{64}) {2}([^\r\n]+)$/.exec(line);
    return match?.[2] === artifactFileName ? [match[1]] : [];
  });
  if (matchingChecksums.length !== 1) {
    fail('release_contract_invalid', 'Release checksum manifest does not name the plugin once.');
  }
  const [expectedDigest] = matchingChecksums;
  const actualDigest = createHash('sha256').update(archive).digest('hex');
  if (actualDigest !== expectedDigest) {
    fail('release_checksum_mismatch', 'Release Agent Plugin checksum does not match.');
  }

  let provenance;
  try {
    const statements = new TextDecoder('utf-8', { fatal: true })
      .decode(
        readBoundedFile(
          resolve(releaseRoot, `${artifactFileName}.intoto.jsonl`),
          maximumReleaseContractBytes,
          'Release Agent Plugin provenance',
        ),
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
  let archiveContractError = null;
  const expectedArchivePaths = new Set(
    marketplaceOutputPaths.slice(1).map((path) => {
      return path.slice(`${marketplacePluginRoot}/`.length);
    }),
  );
  const seenArchivePaths = new Set();
  let expandedBytes = 0;
  try {
    entries = unzipSync(new Uint8Array(archive), {
      filter(file) {
        const maximumBytes =
          file.name === agentPluginExtensionEntryPath ? 1024 * 1024 : maximumReleaseContractBytes;
        if (
          !expectedArchivePaths.has(file.name) ||
          seenArchivePaths.has(file.name) ||
          file.originalSize <= 0 ||
          file.originalSize > maximumBytes
        ) {
          archiveContractError = new MarketplaceContractError(
            'archive_layout_mismatch',
            `Release archive entry is unexpected, duplicated, or oversized: ${file.name}`,
          );
          return false;
        }
        seenArchivePaths.add(file.name);
        expandedBytes += file.originalSize;
        if (expandedBytes > 1024 * 1024 + 2 * maximumReleaseContractBytes) {
          archiveContractError = new MarketplaceContractError(
            'archive_layout_mismatch',
            'Release archive expanded size exceeds its contract.',
          );
          return false;
        }
        return true;
      },
    });
  } catch {
    fail('release_archive_invalid', 'Release Agent Plugin archive cannot be decoded.');
  }
  if (archiveContractError) {
    throw archiveContractError;
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

export function materializeMarketplace({
  releaseDirectory,
  outputRoot,
  expectedSourceCommit,
  checkOnly = false,
}) {
  const root = resolve(outputRoot);
  const plan = readReleasePlan(releaseDirectory);
  if (
    typeof expectedSourceCommit !== 'string' ||
    !/^[0-9a-f]{40}$/.test(expectedSourceCommit) ||
    plan.sourceCommit !== expectedSourceCommit
  ) {
    fail(
      'release_source_mismatch',
      'Release provenance does not match the expected source commit.',
    );
  }
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
    expectedSourceCommit: option('--source-commit'),
    checkOnly: process.argv.includes('--check'),
  });
  console.log(
    `${process.argv.includes('--check') ? 'Verified' : 'Materialized'} marketplace ${plan.version}.`,
  );
}
