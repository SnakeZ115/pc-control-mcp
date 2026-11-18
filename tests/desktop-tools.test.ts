import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PathGuardError, validateAllowedPath } from '../src/security/path-guard.js';
import {
  clipboardGet,
  clipboardSet,
  type DesktopToolsDeps,
  listAllowedFiles,
  mediaVolume,
  systemPower,
  takeScreenshot,
} from '../src/tools/desktop-tools.js';

describe('desktop-tools', () => {
  let tempRoot: string;
  let allowedDir: string;
  let outsideDir: string;

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-pc-control-desktop-'));
    allowedDir = path.join(tempRoot, 'allowed');
    outsideDir = path.join(tempRoot, 'outside');
    fs.mkdirSync(allowedDir, { recursive: true });
    fs.mkdirSync(outsideDir, { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  function createMockDesktopDeps(
    overrides: Partial<DesktopToolsDeps> = {},
  ): DesktopToolsDeps {
    return {
      execFile: vi.fn(async () => ({ stdout: '', stderr: '' })),
      platform: 'win32',
      validatePath: (target, dirs) => validateAllowedPath(target, dirs ?? [allowedDir]),
      getAllowedDirs: () => [fs.realpathSync(allowedDir)],
      ...overrides,
    };
  }

  it('captures screenshot using fixed powershell script without user interpolation', async () => {
    const fakePngBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=';
    const execMock = vi.fn(async () => ({ stdout: `${fakePngBase64}\r\n`, stderr: '' }));
    const deps = createMockDesktopDeps({ execFile: execMock });

    const result = await takeScreenshot(deps);
    expect(result).toEqual({
      mimeType: 'image/png',
      data: fakePngBase64,
    });

    expect(execMock).toHaveBeenCalledTimes(1);
    const [cmd, args] = execMock.mock.calls[0];
    expect(cmd).toBe('powershell.exe');
    expect(args.slice(0, 3)).toEqual(['-NoProfile', '-NonInteractive', '-Command']);
    expect(args[3]).toContain('System.Windows.Forms.Screen');

    await expect(
      takeScreenshot(createMockDesktopDeps({ platform: 'linux' })),
    ).rejects.toThrow(/only supported on Windows/i);

    await expect(
      takeScreenshot(
        createMockDesktopDeps({
          execFile: vi.fn(async () => ({ stdout: 'not valid base64!!!', stderr: '' })),
        }),
      ),
    ).rejects.toThrow(/invalid or empty Base64/i);
  });

  it('reads and writes clipboard safely via stdin without command injection', async () => {
    const execMock = vi.fn(async (_file: string, args: readonly string[]) => {
      if (args[3]?.includes('Get-Clipboard')) {
        return { stdout: 'hello clipboard', stderr: '' };
      }
      return { stdout: '', stderr: '' };
    });
    const deps = createMockDesktopDeps({ execFile: execMock });

    const got = await clipboardGet(deps);
    expect(got).toEqual({ text: 'hello clipboard', length: 15 });

    const payload = 'unsafe $(calc.exe) | rm -rf / & "quotes" \n line2';
    const setResult = await clipboardSet({ text: payload }, deps);
    expect(setResult).toEqual({ updated: true, length: payload.length });

    const [, setArgs, setOpts] = execMock.mock.calls[1];
    expect(setArgs.slice(0, 3)).toEqual(['-NoProfile', '-NonInteractive', '-Command']);
    expect(setArgs[3]).toContain('Set-Clipboard');
    expect(setArgs[3]).not.toContain('calc.exe');
    expect(setOpts?.input).toBe(payload);
  });

  it('controls media and volume using fixed script and stdin JSON payload', async () => {
    const execMock = vi.fn(async (_file, _args, opts) => {
      const req = JSON.parse(opts?.input ?? '{}') as { action: string; level: number | null };
      return {
        stdout: JSON.stringify({
          action: req.action,
          volumePercent: req.level ?? 55,
          muted: req.action === 'mute',
        }),
        stderr: '',
      };
    });
    const deps = createMockDesktopDeps({ execFile: execMock });

    const setRes = await mediaVolume({ action: 'set', level: 42 }, deps);
    expect(setRes).toEqual({ action: 'set', volumePercent: 42, muted: false });

    const muteRes = await mediaVolume({ action: 'mute' }, deps);
    expect(muteRes).toEqual({ action: 'mute', volumePercent: 55, muted: true });

    const upRes = await mediaVolume({ action: 'volume_up', steps: 4 }, deps);
    expect(upRes.action).toBe('volume_up');
    expect(JSON.parse(execMock.mock.calls[2][2]?.input ?? '{}')).toEqual({
      action: 'volume_up',
      level: null,
      muted: null,
      steps: 4,
    });

    const playRes = await mediaVolume({ action: 'play_pause' }, deps);
    expect(playRes.action).toBe('play_pause');

    await expect(mediaVolume({}, deps)).rejects.toThrow();
    await expect(mediaVolume({ action: 'set' }, deps)).rejects.toThrow();
    await expect(mediaVolume({ level: 101 }, deps)).rejects.toThrow();
  });

  it('resolves and executes system_power actions safely with dryRun support', async () => {
    const execMock = vi.fn(async () => ({ stdout: '', stderr: '' }));
    const deps = createMockDesktopDeps({ execFile: execMock });

    const dryShutdown = await systemPower(
      { action: 'shutdown', delaySeconds: 45, dryRun: true },
      deps,
    );
    expect(dryShutdown).toEqual({
      executed: false,
      dryRun: true,
      action: 'shutdown',
      command: 'shutdown.exe',
      args: ['/s', '/t', '45'],
      delaySeconds: 45,
    });
    expect(execMock).not.toHaveBeenCalled();

    const dryLock = await systemPower({ action: 'lock', dryRun: true }, deps);
    expect(dryLock).toEqual({
      executed: false,
      dryRun: true,
      action: 'lock',
      command: 'rundll32.exe',
      args: ['user32.dll,LockWorkStation'],
    });

    const dryCancel = await systemPower(
      { action: 'cancel_shutdown', dryRun: true },
      deps,
    );
    expect(dryCancel.args).toEqual(['/a']);

    const execRestart = await systemPower(
      { action: 'restart', delaySeconds: 15, dryRun: false },
      deps,
    );
    expect(execRestart.executed).toBe(true);
    expect(execMock).toHaveBeenCalledWith('shutdown.exe', ['/r', '/t', '15']);

    await expect(
      systemPower({ action: 'shutdown', delaySeconds: 4000, dryRun: true }, deps),
    ).rejects.toThrow();
  });

  it('lists allowed files while hiding sensitive patterns and external symlinks', async () => {
    fs.mkdirSync(path.join(allowedDir, 'projects'), { recursive: true });
    fs.writeFileSync(path.join(allowedDir, 'readme.txt'), 'hello', 'utf8');
    fs.writeFileSync(path.join(allowedDir, '.env'), 'SECRET=123', 'utf8');
    fs.writeFileSync(path.join(allowedDir, '.hidden-note'), 'hidden', 'utf8');
    fs.writeFileSync(path.join(allowedDir, 'cert.pem'), 'pem', 'utf8');
    fs.writeFileSync(path.join(allowedDir, 'ssfn998877'), 'steam', 'utf8');
    fs.writeFileSync(path.join(allowedDir, 'loginusers.vdf'), 'steam', 'utf8');
    fs.writeFileSync(path.join(allowedDir, 'id_rsa'), 'ssh', 'utf8');

    const escapeLink = path.join(allowedDir, 'outside-link');
    const linkType = process.platform === 'win32' ? 'junction' : 'dir';
    fs.symlinkSync(outsideDir, escapeLink, linkType);

    const deps = createMockDesktopDeps();

    const rootsResult = await listAllowedFiles({}, deps);
    expect(rootsResult.mode).toBe('roots');
    expect(rootsResult.allowedDirs).toEqual([fs.realpathSync(allowedDir)]);

    const listedDefault = await listAllowedFiles({ directory: allowedDir }, deps);
    expect(listedDefault.entries.map((e) => e.name)).toEqual(['projects', 'readme.txt']);

    const listedWithHidden = await listAllowedFiles(
      { directory: allowedDir, includeHidden: true },
      deps,
    );
    expect(listedWithHidden.entries.map((e) => e.name)).toEqual([
      'projects',
      '.hidden-note',
      'readme.txt',
    ]);

    await expect(
      listAllowedFiles({ directory: outsideDir }, deps),
    ).rejects.toThrowError(PathGuardError);
  });
});
