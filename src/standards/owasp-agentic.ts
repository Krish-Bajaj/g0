export interface OwaspAgenticEntry {
  id: string;
  name: string;
  description: string;
}

export const OWASP_AGENTIC_TOP_10: OwaspAgenticEntry[] = [
  {
    id: 'ASI01',
    name: 'Prompt Injection',
    description: 'Manipulating agent behavior through crafted inputs that override system instructions.',
  },
  {
    id: 'ASI02',
    name: 'Excessive Tool Access',
    description: 'Agents granted broader tool access than necessary, enabling misuse.',
  },
  {
    id: 'ASI03',
    name: 'Privilege Escalation',
    description: 'Agents or users gaining unauthorized access through improper identity/access controls.',
  },
  {
    id: 'ASI04',
    name: 'Supply Chain Vulnerabilities',
    description: 'Compromised dependencies, plugins, or MCP servers introducing security risks.',
  },
  {
    id: 'ASI05',
    name: 'Unsafe Code Execution',
    description: 'Agents generating or executing code without proper sandboxing or validation.',
  },
  {
    id: 'ASI06',
    name: 'Memory Poisoning',
    description: 'Persistent memory manipulation to influence future agent behavior.',
  },
  {
    id: 'ASI07',
    name: 'Multi-Agent Manipulation',
    description: 'Exploiting trust between agents in multi-agent systems.',
  },
  {
    id: 'ASI08',
    name: 'Cascading Failures',
    description: 'Failures in one component propagating across the agent system.',
  },
  {
    id: 'ASI09',
    name: 'Insufficient Human Oversight',
    description: 'High-impact actions taken without human approval or audit trails.',
  },
  {
    id: 'ASI10',
    name: 'Rogue Agent Behavior',
    description: 'Agents acting outside defined parameters without detection or containment.',
  },
];
