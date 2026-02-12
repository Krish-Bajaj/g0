import * as fs from 'node:fs';
import type { ScanResult } from '../types/score.js';
import type { Finding } from '../types/finding.js';
import type { Severity } from '../types/common.js';
import { getAllRules } from '../analyzers/rules/index.js';

interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
  invocations: SarifInvocation[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  defaultConfiguration: { level: string };
  properties: {
    tags: string[];
    security_severity: string;
  };
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: string;
  message: { text: string };
  locations: SarifLocation[];
  fixes?: { description: { text: string } }[];
  properties?: Record<string, unknown>;
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string };
    region: { startLine: number; startColumn?: number; snippet?: { text: string } };
  };
}

interface SarifInvocation {
  executionSuccessful: boolean;
  endTimeUtc: string;
  properties: Record<string, unknown>;
}

function severityToLevel(severity: Severity): string {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
      return 'note';
  }
}

function severityToScore(severity: Severity): string {
  switch (severity) {
    case 'critical': return '9.0';
    case 'high': return '7.0';
    case 'medium': return '4.0';
    case 'low': return '2.0';
    case 'info': return '1.0';
  }
}

export function reportSarif(result: ScanResult, outputPath?: string): string {
  const allRules = getAllRules();
  const ruleIndexMap = new Map<string, number>();
  const sarifRules: SarifRule[] = allRules.map((rule, i) => {
    ruleIndexMap.set(rule.id, i);
    return {
      id: rule.id,
      name: rule.name.replace(/\s+/g, ''),
      shortDescription: { text: rule.name },
      fullDescription: { text: rule.description },
      defaultConfiguration: { level: severityToLevel(rule.severity) },
      properties: {
        tags: ['security', rule.domain, ...rule.owaspAgentic],
        security_severity: severityToScore(rule.severity),
      },
    };
  });

  const sarifResults: SarifResult[] = result.findings.map((finding: Finding) => {
    const ruleIndex = ruleIndexMap.get(finding.ruleId) ?? 0;
    const sarifResult: SarifResult = {
      ruleId: finding.ruleId,
      ruleIndex,
      level: severityToLevel(finding.severity),
      message: { text: `${finding.title}: ${finding.description}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: finding.location.file },
            region: {
              startLine: finding.location.line,
              ...(finding.location.column ? { startColumn: finding.location.column } : {}),
              ...(finding.location.snippet ? { snippet: { text: finding.location.snippet } } : {}),
            },
          },
        },
      ],
    };

    if (finding.remediation) {
      sarifResult.fixes = [{ description: { text: finding.remediation } }];
    }

    if (finding.standards) {
      sarifResult.properties = { standards: finding.standards };
    }

    return sarifResult;
  });

  const sarifLog: SarifLog = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'g0',
            version: '0.1.0',
            informationUri: 'https://github.com/guard0-ai/g0',
            rules: sarifRules,
          },
        },
        results: sarifResults,
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: result.timestamp,
            properties: {
              score: result.score.overall,
              grade: result.score.grade,
              duration: result.duration,
              target: result.graph.rootPath,
              framework: result.graph.primaryFramework,
            },
          },
        ],
      },
    ],
  };

  const json = JSON.stringify(sarifLog, null, 2);

  if (outputPath) {
    fs.writeFileSync(outputPath, json, 'utf-8');
  }

  return json;
}
