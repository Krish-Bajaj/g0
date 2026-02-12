import * as fs from 'node:fs';
import * as path from 'node:path';
import YAML from 'yaml';
import type { G0Config } from '../types/config.js';

const CONFIG_FILENAMES = ['.g0.yaml', '.g0.yml', 'g0.yaml', 'g0.yml'];

export function loadConfig(rootPath: string, configPath?: string): G0Config | null {
  if (configPath) {
    const resolved = path.resolve(configPath);
    if (!fs.existsSync(resolved)) {
      throw new Error(`Config file not found: ${resolved}`);
    }
    return parseConfigFile(resolved);
  }

  for (const name of CONFIG_FILENAMES) {
    const filePath = path.join(rootPath, name);
    if (fs.existsSync(filePath)) {
      return parseConfigFile(filePath);
    }
  }

  return null;
}

function parseConfigFile(filePath: string): G0Config {
  const content = fs.readFileSync(filePath, 'utf-8');
  const raw = YAML.parse(content);

  if (!raw || typeof raw !== 'object') {
    return {};
  }

  const config: G0Config = {};

  if (typeof raw.min_score === 'number') {
    config.min_score = Math.max(0, Math.min(100, raw.min_score));
  }
  if (typeof raw.min_grade === 'string' && ['A', 'B', 'C', 'D', 'F'].includes(raw.min_grade.toUpperCase())) {
    config.min_grade = raw.min_grade.toUpperCase() as G0Config['min_grade'];
  }
  if (typeof raw.fail_on === 'string' && ['critical', 'high', 'medium', 'low', 'info'].includes(raw.fail_on)) {
    config.fail_on = raw.fail_on as G0Config['fail_on'];
  }
  if (Array.isArray(raw.exclude_rules)) {
    config.exclude_rules = raw.exclude_rules.filter((r: unknown) => typeof r === 'string');
  }
  if (Array.isArray(raw.exclude_paths)) {
    config.exclude_paths = raw.exclude_paths.filter((p: unknown) => typeof p === 'string');
  }
  if (typeof raw.include_beta === 'boolean') {
    config.include_beta = raw.include_beta;
  }

  return config;
}
