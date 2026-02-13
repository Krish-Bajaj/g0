import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import { execSync } from 'node:child_process';

export interface RemoteTarget {
  url: string;
  branch?: string;
  host: string;
  owner: string;
  repo: string;
}

export interface CloneResult {
  tempDir: string;
  cleanup: () => void;
}

const REMOTE_PATTERNS = [
  /^https?:\/\/(github|gitlab|bitbucket)\.\w+\//,
  /^git@[\w.-]+:/,
  /^ssh:\/\//,
  /^https?:\/\/[\w.-]+\/[\w.-]+\/[\w.-]+(?:\.git)?$/,
];

export function isRemoteUrl(input: string): boolean {
  return REMOTE_PATTERNS.some(p => p.test(input));
}

export function parseTarget(input: string): RemoteTarget {
  let url = input;
  let branch: string | undefined;

  // Extract #branch suffix
  const hashIdx = url.indexOf('#');
  if (hashIdx !== -1) {
    branch = url.substring(hashIdx + 1);
    url = url.substring(0, hashIdx);
  }

  // Remove trailing .git
  const cleanUrl = url.replace(/\.git$/, '');

  // Parse host/owner/repo
  let host = '';
  let owner = '';
  let repo = '';

  if (url.startsWith('git@')) {
    // git@github.com:owner/repo.git
    const match = url.match(/^git@([\w.-]+):([\w.-]+)\/([\w.-]+?)(?:\.git)?$/);
    if (match) {
      host = match[1];
      owner = match[2];
      repo = match[3];
    }
  } else if (url.startsWith('ssh://')) {
    const match = url.match(/^ssh:\/\/(?:[\w]+@)?([\w.-]+)(?:\/|:)([\w.-]+)\/([\w.-]+?)(?:\.git)?$/);
    if (match) {
      host = match[1];
      owner = match[2];
      repo = match[3];
    }
  } else {
    // https://github.com/owner/repo
    try {
      const parsed = new URL(cleanUrl);
      host = parsed.hostname;
      const parts = parsed.pathname.split('/').filter(Boolean);
      if (parts.length >= 2) {
        owner = parts[0];
        repo = parts[1];
      }
    } catch {
      // Not a valid URL, fall through
    }
  }

  return { url, branch, host, owner, repo };
}

export async function cloneRepo(target: RemoteTarget): Promise<CloneResult> {
  const tempDir = path.join(os.tmpdir(), `g0-scan-${crypto.randomUUID()}`);
  fs.mkdirSync(tempDir, { recursive: true });

  const args = ['clone', '--depth', '1', '--single-branch'];
  if (target.branch) {
    args.push('--branch', target.branch);
  }
  args.push(target.url, tempDir);

  try {
    execSync(`git ${args.join(' ')}`, {
      timeout: 60_000,
      stdio: 'pipe',
      encoding: 'utf-8',
    });
  } catch (err: unknown) {
    // Clean up on failure
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }

    const message = err instanceof Error ? err.message : String(err);
    if (/Authentication|Permission|fatal: Could not read from remote/i.test(message)) {
      throw new Error(
        `Authentication failed for ${target.url}. Ensure you have access to this repository and valid credentials configured.`,
      );
    }
    throw new Error(`Failed to clone ${target.url}: ${message}`);
  }

  const cleanup = (): void => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  };

  return { tempDir, cleanup };
}
