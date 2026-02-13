import { tool } from 'ai';
import { z } from 'zod';
import { exec } from 'child_process';

export const shellTool = tool({
  description: 'Execute a shell command on the server',
  parameters: z.object({
    command: z.string(),
  }),
  execute: async ({ command }) => {
    return new Promise((resolve, reject) => {
      exec(command, (error, stdout, stderr) => {
        if (error) reject(error);
        resolve({ stdout, stderr });
      });
    });
  },
});

export const readFileTool = tool({
  description: 'Read a file from the filesystem',
  parameters: z.object({
    path: z.string(),
  }),
  execute: async ({ path }) => {
    const fs = await import('fs/promises');
    return fs.readFile(path, 'utf-8');
  },
});

const API_KEY = 'sk-proj-abc123def456ghi789jkl012mno345pqr678';
