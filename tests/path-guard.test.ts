import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  getDefaultAllowedDirs,
  isSensitivePath,
  PathGuardError,
  resolveAllowedDirs,
  validateAllowedPath,
} from '../src/security/path-guard.js';

describe('path-guard', () => {
  let tempRoot: string;
  let allowedDir: string;
  let outsideDir: string;
  let originalEnv: string | undefined;

  beforeEach(() => {
    originalEnv = process.env.PC_ALLOWED_DIRS;
    delete process.env.PC_ALLOWED_DIRS;

    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-pc-control-guard-'));
    allowedDir = path.join(tempRoot, 'allowed');
    outsideDir = path.join(tempRoot, 'outside');
    fs.mkdirSync(allowedDir, { recursive: true });
    fs.mkdirSync(outsideDir, { recursive: true });
  });

  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env.PC_ALLOWED_DIRS;
    } else {
      process.env.PC_ALLOWED_DIRS = originalEnv;
    }
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  it('uses Documents and Downloads under homedir when PC_ALLOWED_DIRS is unset', () => {
    const defaults = getDefaultAllowedDirs();
    expect(defaults).toEqual([
      path.join(os.homedir(), 'Documents'),
      path.join(os.homedir(), 'Downloads'),
    ]);
    const resolved = resolveAllowedDirs();
    expect(resolved.length).toBe(2);
  });

  it('reads allowed directories from PC_ALLOWED_DIRS', () => {
    process.env.PC_ALLOWED_DIRS = [allowedDir, outsideDir].join(path.delimiter);
    const resolved = resolveAllowedDirs();
    expect(resolved).toEqual([fs.realpathSync(allowedDir), fs.realpathSync(outsideDir)]);
  });

  it('allows valid existing and non-existent paths inside allowed directories', () => {
    const existingFile = path.join(allowedDir, 'notes.txt');
    fs.writeFileSync(existingFile, 'hello', 'utf8');

    const resolvedExisting = validateAllowedPath(existingFile, [allowedDir]);
    expect(resolvedExisting).toBe(fs.realpathSync(existingFile));

    const nonExistent = path.join(allowedDir, 'nested', 'new-file.txt');
    const resolvedNonExistent = validateAllowedPath(nonExistent, [allowedDir]);
    expect(resolvedNonExistent).toBe(path.join(fs.realpathSync(allowedDir), 'nested', 'new-file.txt'));
  });

  it('allows legitimate filenames starting with double dots like ..foo inside allowed dirs', () => {
    const weirdFile = path.join(allowedDir, '..foo');
    const resolved = validateAllowedPath(weirdFile, [allowedDir]);
    expect(resolved).toBe(path.join(fs.realpathSync(allowedDir), '..foo'));
  });

  it('blocks path traversal attempts and sibling prefix bypasses', () => {
    const traversal = path.join(allowedDir, '..', 'outside', 'secret.txt');
    expect(() => validateAllowedPath(traversal, [allowedDir])).toThrowError(PathGuardError);

    const siblingDir = path.join(tempRoot, 'allowed-evil');
    fs.mkdirSync(siblingDir, { recursive: true });
    expect(() =>
      validateAllowedPath(path.join(siblingDir, 'payload.txt'), [allowedDir]),
    ).toThrowError(PathGuardError);
  });

  it('blocks symlinks or junctions pointing outside allowed directories', () => {
    const outsideSecret = path.join(outsideDir, 'secret.txt');
    fs.writeFileSync(outsideSecret, 'top-secret', 'utf8');

    const linkDir = path.join(allowedDir, 'escape-link');
    const linkType = process.platform === 'win32' ? 'junction' : 'dir';
    fs.symlinkSync(outsideDir, linkDir, linkType);

    expect(() => validateAllowedPath(linkDir, [allowedDir])).toThrowError(PathGuardError);
    expect(() =>
      validateAllowedPath(path.join(linkDir, 'secret.txt'), [allowedDir]),
    ).toThrowError(PathGuardError);
    expect(() =>
      validateAllowedPath(path.join(linkDir, 'future', 'new.txt'), [allowedDir]),
    ).toThrowError(PathGuardError);
  });

  it('blocks all sensitive file patterns even inside allowed directories', () => {
    const sensitiveCases = [
      path.join(allowedDir, '.env'),
      path.join(allowedDir, '.env.production'),
      path.join(allowedDir, 'repo', '.git', 'config'),
      path.join(allowedDir, 'certs', 'server.pem'),
      path.join(allowedDir, 'certs', 'private.key'),
      path.join(allowedDir, '.ssh', 'id_rsa'),
      path.join(allowedDir, '.ssh', 'id_rsa.pub'),
      path.join(allowedDir, 'Steam', 'config', 'loginusers.vdf'),
      path.join(allowedDir, 'Steam', 'ssfn1234567890'),
    ];

    for (const candidate of sensitiveCases) {
      expect(isSensitivePath(candidate)).toBe(true);
      expect(() => validateAllowedPath(candidate, [allowedDir])).toThrowError(PathGuardError);
    }
  });

  it('rejects empty strings, null bytes, and Windows ADS colons', () => {
    expect(() => validateAllowedPath('', [allowedDir])).toThrowError(PathGuardError);
    expect(() => validateAllowedPath('   ', [allowedDir])).toThrowError(PathGuardError);
    expect(() =>
      validateAllowedPath(path.join(allowedDir, 'bad\0.txt'), [allowedDir]),
    ).toThrowError(PathGuardError);

    if (process.platform === 'win32') {
      expect(() =>
        validateAllowedPath(`${path.join(allowedDir, 'file.txt')}:Zone.Identifier`, [allowedDir]),
      ).toThrowError(PathGuardError);
    }
  });
});
