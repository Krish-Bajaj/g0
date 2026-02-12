# g0 — AI Agent Security Scanner

The open-source CLI that scans AI agent projects for security vulnerabilities. Think "Snyk for AI agents."

```
npx g0 scan ./my-agent
```

## Quickstart

```bash
# Scan a project
npx g0 scan ./my-agent

# JSON output for CI/CD
npx g0 scan ./my-agent --json

# HTML report
npx g0 scan ./my-agent --html report.html

# CI/CD gate (exit code 1 if score < 80)
npx g0 gate ./my-agent --min-score 80
```

## What It Does

g0 statically analyzes AI agent codebases to find security issues across 7 domains:

| Domain | Rules | Key Checks |
|--------|-------|------------|
| Goal Integrity (AA-GI) | 8 | Prompt injection, scope boundaries, instruction guarding |
| Tool Safety (AA-TS) | 10 | Shell execution, raw SQL, filesystem access, input validation |
| Identity & Access (AA-IA) | 8 | Hardcoded API keys, secrets in config, missing auth |
| Supply Chain (AA-SC) | 5 | Unpinned deps, unverified MCP servers, npx -y |
| Code Execution (AA-CE) | 6 | eval/exec, subprocess, unsandboxed code execution |
| Memory & Context (AA-MP) | 4 | Unbounded memory, no session isolation, no TTL |
| Data Leakage (AA-DL) | 5 | verbose=True, raw errors exposed, PII in prompts |

**46 rules** total, all mapped to [OWASP Agentic Top 10](https://owasp.org/www-project-agentic-ai/) (ASI01–ASI10).

## Supported Frameworks

- **LangChain / LangGraph** — agents, tools, prompts, memory
- **CrewAI** — crews, agents, tasks, YAML configs
- **MCP** — server tools, config files, client configs
- **OpenAI Agents SDK** — assistants, function tools, responses API
- **Generic** — any Python/TypeScript project with agent patterns

## Scoring

Each domain starts at 100 and is deducted based on finding severity:

| Severity | Deduction |
|----------|-----------|
| Critical | -25 |
| High | -15 |
| Medium | -8 |
| Low | -3 |

Domain scores are weighted and averaged into an overall score (0–100) with a letter grade:

| Grade | Score |
|-------|-------|
| A | >= 90 |
| B | >= 80 |
| C | >= 70 |
| D | >= 60 |
| F | < 60 |

## CLI Commands

### `g0 scan [path]`

Scan an AI agent project for security issues.

```bash
g0 scan ./my-agent              # Terminal output
g0 scan ./my-agent --json       # JSON to stdout
g0 scan ./my-agent -o report.json  # JSON to file
g0 scan ./my-agent --html report.html  # HTML report
g0 scan ./my-agent -q --json    # Quiet mode + JSON
```

### `g0 gate [path]`

CI/CD gate that exits with code 1 if the scan fails thresholds.

```bash
g0 gate ./my-agent --min-score 80
g0 gate ./my-agent --no-critical
g0 gate ./my-agent --min-grade B
```

### `g0 init`

Generate a `.g0.yaml` configuration file.

```bash
g0 init
g0 init --path ./my-agent
```

## Programmatic API

```typescript
import { runScan } from 'g0';

const result = await runScan({ targetPath: './my-agent' });
console.log(result.score.grade);     // 'B'
console.log(result.findings.length); // 12
```

## Development

```bash
git clone https://github.com/guard0-ai/g0.git
cd g0
npm install
npm test
npm run build
```

## License

MIT
