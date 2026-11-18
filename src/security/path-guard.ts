import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export type PathGuardErrorCode =
  | 'INVALID_PATH'
  | 'SENSITIVE_PATH'
  | 'OUTSIDE_ALLOWED_DIRS'
  | 'SYMLINK_ERROR';

export class PathGuardError extends Error {
  readonly code: PathGuardErrorCode;

  constructor(code: PathGuardErrorCode, message: string) {
    super(message);
    this.name = 'PathGuardError';
    this.code = code;
  }
}

const MAX_SYMLINK_DEPTH = 32;

const SENSITIVE_SEGMENT_PATTERNS: readonly RegExp[] = [
  /^\.env(\..+)?$/i,
  /\.pem$/i,
  /\.key$/i,
  /^id_rsa(\..+)?$/i,
  /^loginusers\.vdf$/i,
  /^ssfn/i,
];

/**
 * Returns the default allowed directories when PC_ALLOWED_DIRS is not configured.
 */
export function getDefaultAllowedDirs(): string[] {
  const home = os.homedir();
  return [path.join(home, 'Documents'), path.join(home, 'Downloads')];
}

function splitAllowedDirsEnv(rawValue: string): string[] {
  if (rawValue.includes(path.delimiter)) {
    return rawValue.split(path.delimiter);
  }
  if (process.platform === 'win32' && rawValue.includes(',')) {
    return rawValue.split(',');
  }
  return [rawValue];
}

function hasWindowsAlternateDataStream(candidatePath: string): boolean {
  if (process.platform !== 'win32') {
    return false;
  }
  // Strip standard or extended-length drive prefix (e.g. "C:" or "\\?\C:") before checking for ":" ADS markers.
  const withoutDrive = candidatePath.replace(/^(?:\\\\\?\\)?[A-Za-z]:/, '');
  return withoutDrive.includes(':');
}

function resolveCanonicalPath(inputPath: string, depth = 0): string {
  if (depth > MAX_SYMLINK_DEPTH) {
    throw new PathGuardError('SYMLINK_ERROR', 'Too many symbolic link levels encountered');
  }

  let current = path.resolve(inputPath);
  const trailingSegments: string[] = [];

  while (true) {
    try {
      fs.lstatSync(current);
      break;
    } catch (error) {
      const errCode = (error as NodeJS.ErrnoException).code;
      if (errCode !== 'ENOENT' && errCode !== 'ENOTDIR') {
        throw error;
      }
      const parent = path.dirname(current);
      if (parent === current) {
        return path.resolve(inputPath);
      }
      trailingSegments.unshift(path.basename(current));
      current = parent;
    }
  }

  let canonicalBase: string;
  try {
    canonicalBase = fs.realpathSync(current);
  } catch (error) {
    const errCode = (error as NodeJS.ErrnoException).code;
    if (errCode === 'ENOENT') {
      // Dangling symlink: resolve its link target recursively so traversal through broken links is still caught.
      const stat = fs.lstatSync(current);
      if (stat.isSymbolicLink()) {
        const linkTarget = fs.readlinkSync(current);
        const resolvedLinkTarget = path.resolve(path.dirname(current), linkTarget);
        canonicalBase = resolveCanonicalPath(resolvedLinkTarget, depth + 1);
      } else {
        canonicalBase = current;
      }
    } else if (errCode === 'ELOOP') {
      throw new PathGuardError('SYMLINK_ERROR', `Symbolic link loop detected at "${current}"`);
    } else {
      throw error;
    }
  }

  return trailingSegments.length > 0
    ? path.join(canonicalBase, ...trailingSegments)
    : canonicalBase;
}

function isPathWithinBase(candidatePath: string, baseDir: string): boolean {
  const comparableCandidate =
    process.platform === 'win32' ? candidatePath.toLowerCase() : candidatePath;
  const comparableBase = process.platform === 'win32' ? baseDir.toLowerCase() : baseDir;

  const relative = path.relative(comparableBase, comparableCandidate);
  return (
    relative === '' ||
    (relative !== '..' &&
      !relative.startsWith(`..${path.sep}`) &&
      !relative.startsWith('../') &&
      !path.isAbsolute(relative))
  );
}

/**
 * Checks whether a path references a blocked sensitive file or pattern
 * (.env, .git/config, *.pem, *.key, id_rsa, loginusers.vdf, ssfn*).
 */
export function isSensitivePath(targetPath: string): boolean {
  const normalized = targetPath.replace(/\\/g, '/');
  const segments = normalized.split('/').filter((segment) => segment.length > 0);

  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i];
    if (SENSITIVE_SEGMENT_PATTERNS.some((pattern) => pattern.test(segment))) {
      return true;
    }
    if (
      segment.toLowerCase() === '.git' &&
      i + 1 < segments.length &&
      segments[i + 1].toLowerCase() === 'config'
    ) {
      return true;
    }
  }

  return false;
}

/**
 * Resolves the effective list of canonical allowed directories from explicit override,
 * PC_ALLOWED_DIRS environment variable, or OS defaults.
 */
export function resolveAllowedDirs(allowedDirs?: readonly string[]): string[] {
  let rawDirs: string[];

  if (allowedDirs !== undefined) {
    rawDirs = [...allowedDirs];
  } else {
    const envValue = process.env.PC_ALLOWED_DIRS?.trim();
    rawDirs = envValue ? splitAllowedDirsEnv(envValue) : getDefaultAllowedDirs();
  }

  return rawDirs
    .map((dir) => dir.trim())
    .filter((dir) => dir.length > 0)
    .map((dir) => resolveCanonicalPath(dir));
}

/**
 * Validates that targetPath resolves inside one of the allowed directories
 * and does not target a blocked sensitive file or malicious symlink.
 * Returns the canonical resolved path when valid, or throws PathGuardError.
 */
export function validateAllowedPath(
  targetPath: string,
  allowedDirs?: readonly string[],
): string {
  if (typeof targetPath !== 'string' || targetPath.trim().length === 0) {
    throw new PathGuardError('INVALID_PATH', 'Target path must be a non-empty string');
  }

  if (targetPath.includes('\0')) {
    throw new PathGuardError('INVALID_PATH', 'Target path contains invalid null bytes');
  }

  if (hasWindowsAlternateDataStream(targetPath)) {
    throw new PathGuardError(
      'INVALID_PATH',
      'Target path contains disallowed NTFS alternate data stream syntax',
    );
  }

  const resolvedAllowedDirs = resolveAllowedDirs(allowedDirs);
  if (resolvedAllowedDirs.length === 0) {
    throw new PathGuardError('OUTSIDE_ALLOWED_DIRS', 'No allowed directories are configured');
  }

  const resolvedInput = path.resolve(targetPath);
  const canonicalTarget = resolveCanonicalPath(resolvedInput);

  if (hasWindowsAlternateDataStream(canonicalTarget)) {
    throw new PathGuardError(
      'INVALID_PATH',
      'Resolved path contains disallowed NTFS alternate data stream syntax',
    );
  }

  if (isSensitivePath(targetPath) || isSensitivePath(canonicalTarget)) {
    throw new PathGuardError(
      'SENSITIVE_PATH',
      `Access denied: "${targetPath}" matches a blocked sensitive file pattern`,
    );
  }

  const isAllowed = resolvedAllowedDirs.some((allowedDir) =>
    isPathWithinBase(canonicalTarget, allowedDir),
  );

  if (!isAllowed) {
    throw new PathGuardError(
      'OUTSIDE_ALLOWED_DIRS',
      `Access denied: "${targetPath}" is outside the allowed directories`,
    );
  }

  return canonicalTarget;
}
