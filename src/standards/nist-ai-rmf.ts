export interface NISTAiRmfEntry {
  id: string;
  name: string;
  description: string;
}

export const NIST_AI_RMF_FUNCTIONS: NISTAiRmfEntry[] = [
  { id: 'GOVERN-1.1', name: 'Legal & Regulatory Compliance', description: 'Ensure AI systems comply with relevant legal and regulatory requirements.' },
  { id: 'GOVERN-1.2', name: 'Trustworthy AI Policies', description: 'Establish policies for trustworthy AI development and deployment.' },
  { id: 'GOVERN-2.1', name: 'Roles & Responsibilities', description: 'Define roles and responsibilities for AI risk management.' },
  { id: 'MAP-1.1', name: 'Intended Purpose', description: 'Document the intended purpose and context of AI systems.' },
  { id: 'MAP-1.5', name: 'AI Risk Identification', description: 'Identify risks specific to AI system deployment context.' },
  { id: 'MAP-2.1', name: 'Threat Modeling', description: 'Model threats specific to AI system components and interfaces.' },
  { id: 'MAP-2.3', name: 'Attack Surface Analysis', description: 'Analyze and minimize AI system attack surfaces.' },
  { id: 'MAP-3.1', name: 'Third-Party Risk', description: 'Assess risks from third-party AI components and data.' },
  { id: 'MEASURE-1.1', name: 'Security Testing', description: 'Test AI systems for security vulnerabilities and weaknesses.' },
  { id: 'MEASURE-2.1', name: 'Privacy Assessment', description: 'Assess privacy risks in AI system data handling.' },
  { id: 'MEASURE-2.6', name: 'Robustness Testing', description: 'Test AI system robustness against adversarial inputs.' },
  { id: 'MANAGE-1.1', name: 'Risk Prioritization', description: 'Prioritize identified AI risks for mitigation.' },
  { id: 'MANAGE-2.1', name: 'Risk Mitigation', description: 'Implement controls to mitigate identified AI risks.' },
  { id: 'MANAGE-2.4', name: 'Incident Management', description: 'Manage AI-related security incidents and events.' },
  { id: 'MANAGE-3.1', name: 'Continuous Monitoring', description: 'Continuously monitor AI system risks and controls.' },
];
