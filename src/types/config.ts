import type { Grade, Severity } from './common.js';

export interface G0Config {
  min_score?: number;
  min_grade?: Grade;
  fail_on?: Severity;
  exclude_rules?: string[];
  exclude_paths?: string[];
  include_beta?: boolean;
  rules_dir?: string;
}
