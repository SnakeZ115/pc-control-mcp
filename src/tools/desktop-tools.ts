import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import {
  isSensitivePath,
  resolveAllowedDirs,
  validateAllowedPath,
} from '../security/path-guard.js';

const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_BUFFER_BYTES = 10 * 1024 * 1024;
const SCREENSHOT_MAX_BUFFER_BYTES = 50 * 1024 * 1024;
const MAX_CLIPBOARD_BYTES = 1_000_000;

const SCREENSHOT_PS_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  'Add-Type -AssemblyName System.Windows.Forms,System.Drawing',
  '$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds',
  '$bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height',
  '$graphics = [System.Drawing.Graphics]::FromImage($bitmap)',
  'try {',
  '  $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)',
  '  $ms = New-Object System.IO.MemoryStream',
  '  try {',
  '    $bitmap.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)',
  '    [Convert]::ToBase64String($ms.ToArray())',
  '  } finally {',
  '    $ms.Dispose()',
  '  }',
  '} finally {',
  '  $graphics.Dispose()',
  '  $bitmap.Dispose()',
  '}',
].join('; ');

const CLIPBOARD_GET_PS_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8',
  '$text = Get-Clipboard -Raw',
  'if ($null -ne $text) { [Console]::Write($text) }',
].join('; ');

const CLIPBOARD_SET_PS_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  '[Console]::InputEncoding = [System.Text.Encoding]::UTF8',
  '$text = [Console]::In.ReadToEnd()',
  'if ([string]::IsNullOrEmpty($text)) {',
  '  Add-Type -AssemblyName System.Windows.Forms',
  '  [System.Windows.Forms.Clipboard]::Clear()',
  '} else {',
  '  Set-Clipboard -Value $text',
  '}',
].join('; ');

const MEDIA_VOLUME_PS_SCRIPT = `
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$rawInput = [Console]::In.ReadToEnd()
$payload = $rawInput | ConvertFrom-Json

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class McpAudioControl {
    [DllImport("user32.dll")]
    private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

    private const uint KEYEVENTF_KEYUP = 0x0002;

    [ComImport]
    [Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")]
    private class MMDeviceEnumerator {}

    [Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IMMDeviceEnumerator {
        [PreserveSig] int NotImpl1();
        [PreserveSig] int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice ppDevice);
    }

    [Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IMMDevice {
        [PreserveSig] int Activate(ref Guid iid, int dwClsCtx, IntPtr pActivationParams, [MarshalAs(UnmanagedType.IUnknown)] out object ppInterface);
    }

    [Guid("5CDF2C82-841E-4546-9722-0CF74078229A"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IAudioEndpointVolume {
        [PreserveSig] int RegisterControlChangeNotify(IntPtr pNotify);
        [PreserveSig] int UnregisterControlChangeNotify(IntPtr pNotify);
        [PreserveSig] int GetChannelCount(out uint pnChannelCount);
        [PreserveSig] int SetMasterVolumeLevel(float fLevelDB, ref Guid pguidEventContext);
        [PreserveSig] int SetMasterVolumeLevelScalar(float fLevel, ref Guid pguidEventContext);
        [PreserveSig] int GetMasterVolumeLevel(out float pfLevelDB);
        [PreserveSig] int GetMasterVolumeLevelScalar(out float pfLevel);
        [PreserveSig] int SetChannelVolumeLevel(uint nChannel, float fLevelDB, ref Guid pguidEventContext);
        [PreserveSig] int SetChannelVolumeLevelScalar(uint nChannel, float fLevel, ref Guid pguidEventContext);
        [PreserveSig] int GetChannelVolumeLevel(uint nChannel, out float pfLevelDB);
        [PreserveSig] int GetChannelVolumeLevelScalar(uint nChannel, out float pfLevel);
        [PreserveSig] int SetMute([MarshalAs(UnmanagedType.Bool)] bool bMute, ref Guid pguidEventContext);
        [PreserveSig] int GetMute([MarshalAs(UnmanagedType.Bool)] out bool pbMute);
    }

    private static IAudioEndpointVolume GetEndpoint() {
        var enumerator = (IMMDeviceEnumerator)(new MMDeviceEnumerator());
        IMMDevice device;
        Marshal.ThrowExceptionForHR(enumerator.GetDefaultAudioEndpoint(0, 1, out device));
        var iid = typeof(IAudioEndpointVolume).GUID;
        object obj;
        Marshal.ThrowExceptionForHR(device.Activate(ref iid, 1, IntPtr.Zero, out obj));
        return (IAudioEndpointVolume)obj;
    }

    public static void SendMediaKey(byte vk, int count) {
        int clamped = Math.Max(1, Math.Min(50, count));
        for (int i = 0; i < clamped; i++) {
            keybd_event(vk, 0, 0, UIntPtr.Zero);
            keybd_event(vk, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
        }
    }

    public static void SetVolumePercent(int percent) {
        float scalar = Math.Max(0, Math.Min(100, percent)) / 100.0f;
        var ctx = Guid.Empty;
        Marshal.ThrowExceptionForHR(GetEndpoint().SetMasterVolumeLevelScalar(scalar, ref ctx));
    }

    public static void SetMuteState(bool muted) {
        var ctx = Guid.Empty;
        Marshal.ThrowExceptionForHR(GetEndpoint().SetMute(muted, ref ctx));
    }

    public static int GetVolumePercent() {
        float level;
        Marshal.ThrowExceptionForHR(GetEndpoint().GetMasterVolumeLevelScalar(out level));
        return (int)Math.Round(level * 100.0);
    }

    public static bool GetMuteState() {
        bool muted;
        Marshal.ThrowExceptionForHR(GetEndpoint().GetMute(out muted));
        return muted;
    }
}
"@

$steps = if ($null -ne $payload.steps) { [int]$payload.steps } else { 1 }
switch ($payload.action) {
  'get' { }
  'set' {
    [McpAudioControl]::SetVolumePercent([int]$payload.level)
    if ($null -ne $payload.muted) {
      [McpAudioControl]::SetMuteState([bool]$payload.muted)
    }
  }
  'mute' { [McpAudioControl]::SetMuteState($true) }
  'unmute' { [McpAudioControl]::SetMuteState($false) }
  'toggle_mute' { [McpAudioControl]::SendMediaKey(0xAD, 1) }
  'volume_up' { [McpAudioControl]::SendMediaKey(0xAF, $steps) }
  'volume_down' { [McpAudioControl]::SendMediaKey(0xAE, $steps) }
  'play_pause' { [McpAudioControl]::SendMediaKey(0xB3, 1) }
  default { throw "Unsupported media action: $($payload.action)" }
}

$vol = $null
$mutedState = $null
try {
  $vol = [McpAudioControl]::GetVolumePercent()
  $mutedState = [McpAudioControl]::GetMuteState()
} catch {
  if ($payload.action -in @('get', 'set', 'mute', 'unmute')) {
    throw
  }
}

[Console]::Write((@{
  action = $payload.action
  volumePercent = $vol
  muted = $mutedState
} | ConvertTo-Json -Compress))
`.trim();

export const takeScreenshotInputSchema = z.object({});

export const clipboardGetInputSchema = z.object({});

export const clipboardSetInputSchema = z.object({
  text: z
    .string()
    .max(MAX_CLIPBOARD_BYTES)
    .describe('Text content to place into the Windows clipboard'),
});

export const mediaVolumeInputSchema = z
  .object({
    action: z
      .enum([
        'get',
        'set',
        'mute',
        'unmute',
        'toggle_mute',
        'volume_up',
        'volume_down',
        'play_pause',
      ])
      .optional()
      .describe('Audio or media control action to execute'),
    level: z
      .number()
      .int()
      .min(0)
      .max(100)
      .optional()
      .describe('Target master volume percentage (0-100)'),
    muted: z
      .boolean()
      .optional()
      .describe('Explicit mute state (true to mute, false to unmute)'),
    steps: z
      .number()
      .int()
      .min(1)
      .max(50)
      .default(1)
      .describe('Number of steps for volume_up or volume_down'),
  })
  .refine(
    (data) =>
      data.action !== undefined ||
      data.level !== undefined ||
      data.muted !== undefined,
    { message: 'At least one of action, level, or muted must be provided' },
  )
  .refine((data) => data.action !== 'set' || data.level !== undefined, {
    message: 'level (0-100) is required when action is "set"',
  });

export const systemPowerInputSchema = z.object({
  action: z
    .enum(['lock', 'sleep', 'shutdown', 'restart', 'cancel_shutdown'])
    .describe('Windows power or session action to execute'),
  delaySeconds: z
    .number()
    .int()
    .min(0)
    .max(3600)
    .default(10)
    .describe('Delay in seconds before shutdown or restart (0-3600)'),
  dryRun: z
    .boolean()
    .default(false)
    .describe('When true, resolves the command without executing it'),
});

export const listAllowedFilesInputSchema = z.object({
  directory: z
    .string()
    .trim()
    .min(1)
    .optional()
    .describe('Directory inside allowed paths to list; defaults to allowed root directories'),
  includeHidden: z
    .boolean()
    .default(false)
    .describe('Include dotfiles other than blocked sensitive files'),
  limit: z
    .number()
    .int()
    .min(1)
    .max(500)
    .default(100)
    .describe('Maximum number of directory entries to return (1-500)'),
});

export interface ExecResult {
  stdout: string;
  stderr: string;
}

export interface ExecFileOptions {
  input?: string;
  timeoutMs?: number;
  maxBufferBytes?: number;
}

export type ExecFileRunner = (
  file: string,
  args: readonly string[],
  options?: ExecFileOptions,
) => Promise<ExecResult>;

export interface DesktopToolsDeps {
  execFile: ExecFileRunner;
  platform: NodeJS.Platform;
  validatePath: (targetPath: string, allowedDirs?: readonly string[]) => string;
  getAllowedDirs: (allowedDirs?: readonly string[]) => string[];
}

export interface ScreenshotResult {
  mimeType: 'image/png';
  data: string;
}

export interface ClipboardGetResult {
  text: string;
  length: number;
}

export interface ClipboardSetResult {
  updated: boolean;
  length: number;
}

export interface MediaVolumeResult {
  action: string;
  volumePercent: number | null;
  muted: boolean | null;
}

export interface SystemPowerResult {
  executed: boolean;
  dryRun: boolean;
  action: 'lock' | 'sleep' | 'shutdown' | 'restart' | 'cancel_shutdown';
  command: string;
  args: string[];
  delaySeconds?: number;
}

export interface AllowedFileEntry {
  name: string;
  path: string;
  type: 'directory' | 'file' | 'other';
  exists?: boolean;
  sizeBytes: number | null;
  modifiedAt: string | null;
}

export interface ListAllowedFilesResult {
  mode: 'roots' | 'directory';
  directory: string | null;
  allowedDirs: string[];
  totalEntries: number;
  truncated: boolean;
  entries: AllowedFileEntry[];
}

export const defaultExecFileRunner: ExecFileRunner = (
  file,
  args,
  options = {},
): Promise<ExecResult> =>
  new Promise((resolve, reject) => {
    const child = execFile(
      file,
      [...args],
      {
        shell: false,
        windowsHide: true,
        encoding: 'utf8',
        timeout: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
        maxBuffer: options.maxBufferBytes ?? DEFAULT_MAX_BUFFER_BYTES,
      },
      (error, stdout, stderr) => {
        if (error) {
          const detail = stderr?.trim() || error.message;
          reject(new Error(`Command "${file}" failed: ${detail}`));
          return;
        }
        resolve({ stdout: stdout ?? '', stderr: stderr ?? '' });
      },
    );

    if (options.input !== undefined && child.stdin) {
      child.stdin.on('error', () => {
        // Ignore EPIPE when child exits before consuming all stdin.
      });
      child.stdin.end(options.input, 'utf8');
    }
  });

const defaultDeps: DesktopToolsDeps = {
  execFile: defaultExecFileRunner,
  platform: process.platform,
  validatePath: validateAllowedPath,
  getAllowedDirs: resolveAllowedDirs,
};

function assertWindowsPlatform(platform: NodeJS.Platform, feature: string): void {
  if (platform !== 'win32') {
    throw new Error(`${feature} is only supported on Windows (win32); current platform is ${platform}`);
  }
}

export async function takeScreenshot(
  deps: DesktopToolsDeps = defaultDeps,
): Promise<ScreenshotResult> {
  assertWindowsPlatform(deps.platform, 'take_screenshot');

  const { stdout } = await deps.execFile(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-Command', SCREENSHOT_PS_SCRIPT],
    {
      maxBufferBytes: SCREENSHOT_MAX_BUFFER_BYTES,
      timeoutMs: DEFAULT_TIMEOUT_MS,
    },
  );

  const base64 = stdout.trim();
  if (!base64 || !/^[A-Za-z0-9+/]+={0,2}$/.test(base64)) {
    throw new Error('Screenshot capture returned invalid or empty Base64 PNG output');
  }

  return {
    mimeType: 'image/png',
    data: base64,
  };
}

export async function clipboardGet(
  deps: DesktopToolsDeps = defaultDeps,
): Promise<ClipboardGetResult> {
  assertWindowsPlatform(deps.platform, 'clipboard_get');

  const { stdout } = await deps.execFile('powershell.exe', [
    '-NoProfile',
    '-NonInteractive',
    '-Command',
    CLIPBOARD_GET_PS_SCRIPT,
  ]);

  return {
    text: stdout,
    length: stdout.length,
  };
}

export async function clipboardSet(
  rawInput: z.input<typeof clipboardSetInputSchema>,
  deps: DesktopToolsDeps = defaultDeps,
): Promise<ClipboardSetResult> {
  assertWindowsPlatform(deps.platform, 'clipboard_set');

  const { text } = clipboardSetInputSchema.parse(rawInput);

  await deps.execFile(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-Command', CLIPBOARD_SET_PS_SCRIPT],
    { input: text },
  );

  return {
    updated: true,
    length: text.length,
  };
}

export async function mediaVolume(
  rawInput: z.input<typeof mediaVolumeInputSchema>,
  deps: DesktopToolsDeps = defaultDeps,
): Promise<MediaVolumeResult> {
  assertWindowsPlatform(deps.platform, 'media_volume');

  const parsed = mediaVolumeInputSchema.parse(rawInput);
  const resolvedAction =
    parsed.action ??
    (parsed.level !== undefined
      ? 'set'
      : parsed.muted
        ? 'mute'
        : 'unmute');

  if (resolvedAction === 'set' && parsed.level === undefined) {
    throw new Error('level (0-100) is required when action is "set"');
  }

  const commandPayload = JSON.stringify({
    action: resolvedAction,
    level: parsed.level ?? null,
    muted: parsed.muted ?? null,
    steps: parsed.steps,
  });

  const { stdout } = await deps.execFile(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-Command', MEDIA_VOLUME_PS_SCRIPT],
    { input: commandPayload },
  );

  const trimmed = stdout.trim();
  if (!trimmed) {
    return {
      action: resolvedAction,
      volumePercent: null,
      muted: null,
    };
  }

  try {
    const result = JSON.parse(trimmed) as {
      action?: string;
      volumePercent?: number | null;
      muted?: boolean | null;
    };
    return {
      action: result.action ?? resolvedAction,
      volumePercent: result.volumePercent ?? null,
      muted: result.muted ?? null,
    };
  } catch {
    throw new Error(`Unexpected response from media_volume script: ${trimmed}`);
  }
}

export function resolveSystemPowerCommand(
  input: z.infer<typeof systemPowerInputSchema>,
): { command: string; args: string[] } {
  switch (input.action) {
    case 'lock':
      return {
        command: 'rundll32.exe',
        args: ['user32.dll,LockWorkStation'],
      };
    case 'sleep':
      return {
        command: 'rundll32.exe',
        args: ['powrprof.dll,SetSuspendState', '0,1,0'],
      };
    case 'shutdown':
      return {
        command: 'shutdown.exe',
        args: ['/s', '/t', String(input.delaySeconds)],
      };
    case 'restart':
      return {
        command: 'shutdown.exe',
        args: ['/r', '/t', String(input.delaySeconds)],
      };
    case 'cancel_shutdown':
      return {
        command: 'shutdown.exe',
        args: ['/a'],
      };
  }
}

export async function systemPower(
  rawInput: z.input<typeof systemPowerInputSchema>,
  deps: DesktopToolsDeps = defaultDeps,
): Promise<SystemPowerResult> {
  const input = systemPowerInputSchema.parse(rawInput);
  const { command, args } = resolveSystemPowerCommand(input);
  const includeDelay = input.action === 'shutdown' || input.action === 'restart';

  if (input.dryRun) {
    return {
      executed: false,
      dryRun: true,
      action: input.action,
      command,
      args,
      ...(includeDelay ? { delaySeconds: input.delaySeconds } : {}),
    };
  }

  assertWindowsPlatform(deps.platform, 'system_power');
  await deps.execFile(command, args);

  return {
    executed: true,
    dryRun: false,
    action: input.action,
    command,
    args,
    ...(includeDelay ? { delaySeconds: input.delaySeconds } : {}),
  };
}

export async function listAllowedFiles(
  rawInput: z.input<typeof listAllowedFilesInputSchema>,
  deps: DesktopToolsDeps = defaultDeps,
): Promise<ListAllowedFilesResult> {
  const input = listAllowedFilesInputSchema.parse(rawInput);
  const allowedDirs = deps.getAllowedDirs();

  if (!input.directory) {
    const rootEntries: AllowedFileEntry[] = allowedDirs.map((dir) => {
      let exists = false;
      let modifiedAt: string | null = null;
      try {
        const stat = fs.statSync(dir);
        exists = stat.isDirectory();
        modifiedAt = stat.mtime.toISOString();
      } catch {
        exists = false;
      }
      return {
        name: path.basename(dir) || dir,
        path: dir,
        type: 'directory',
        exists,
        sizeBytes: null,
        modifiedAt,
      };
    });

    const limitedRoots = rootEntries.slice(0, input.limit);
    return {
      mode: 'roots',
      directory: null,
      allowedDirs,
      totalEntries: rootEntries.length,
      truncated: rootEntries.length > input.limit,
      entries: limitedRoots,
    };
  }

  const safeDir = deps.validatePath(input.directory, allowedDirs);
  const dirStat = await fs.promises.stat(safeDir);
  if (!dirStat.isDirectory()) {
    throw new Error(`Target path "${safeDir}" is not a directory`);
  }

  const dirents = await fs.promises.readdir(safeDir, { withFileTypes: true });
  const visibleEntries: AllowedFileEntry[] = [];

  for (const dirent of dirents) {
    if (!input.includeHidden && dirent.name.startsWith('.')) {
      continue;
    }

    const entryPath = path.join(safeDir, dirent.name);
    if (isSensitivePath(entryPath)) {
      continue;
    }

    let resolvedEntryPath = entryPath;
    if (dirent.isSymbolicLink()) {
      try {
        resolvedEntryPath = deps.validatePath(entryPath, allowedDirs);
      } catch {
        // Never follow or expose symlinks escaping allowed directories or pointing to sensitive files.
        continue;
      }
    }

    let entryType: 'directory' | 'file' | 'other' = 'other';
    let sizeBytes: number | null = null;
    let modifiedAt: string | null = null;

    try {
      const stat = await fs.promises.stat(resolvedEntryPath);
      if (stat.isDirectory()) {
        entryType = 'directory';
      } else if (stat.isFile()) {
        entryType = 'file';
        sizeBytes = stat.size;
      }
      modifiedAt = stat.mtime.toISOString();
    } catch {
      if (dirent.isDirectory()) {
        entryType = 'directory';
      } else if (dirent.isFile()) {
        entryType = 'file';
      }
    }

    visibleEntries.push({
      name: dirent.name,
      path: entryPath,
      type: entryType,
      sizeBytes,
      modifiedAt,
    });
  }

  visibleEntries.sort((a, b) => {
    if (a.type === 'directory' && b.type !== 'directory') return -1;
    if (a.type !== 'directory' && b.type === 'directory') return 1;
    return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
  });

  const truncated = visibleEntries.length > input.limit;
  return {
    mode: 'directory',
    directory: safeDir,
    allowedDirs,
    totalEntries: visibleEntries.length,
    truncated,
    entries: visibleEntries.slice(0, input.limit),
  };
}
