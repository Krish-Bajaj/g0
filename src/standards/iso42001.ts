export interface ISO42001Entry {
  id: string;
  name: string;
  description: string;
}

export const ISO42001_CONTROLS: ISO42001Entry[] = [
  { id: 'A.5.2', name: 'AI Policy', description: 'Establish and maintain policies for AI system development and deployment.' },
  { id: 'A.5.3', name: 'AI Risk Assessment', description: 'Assess risks associated with AI system components.' },
  { id: 'A.5.4', name: 'AI System Lifecycle', description: 'Manage AI system lifecycle from development to decommissioning.' },
  { id: 'A.6.2', name: 'Access Control', description: 'Implement access controls for AI systems and data.' },
  { id: 'A.6.3', name: 'Data Security', description: 'Protect data used in AI system training and operation.' },
  { id: 'A.6.4', name: 'Security Monitoring', description: 'Monitor AI system security events and incidents.' },
  { id: 'A.7.2', name: 'Third-Party Management', description: 'Manage security of third-party AI components and services.' },
  { id: 'A.7.3', name: 'Supply Chain Security', description: 'Ensure security of AI supply chain components.' },
  { id: 'A.8.2', name: 'AI Transparency', description: 'Ensure transparency in AI system decisions and operations.' },
  { id: 'A.8.3', name: 'AI Accountability', description: 'Establish accountability for AI system actions.' },
  { id: 'A.9.2', name: 'Performance Monitoring', description: 'Monitor AI system performance and behavior.' },
  { id: 'A.9.3', name: 'Incident Response', description: 'Respond to AI system security incidents.' },
  { id: 'A.10.2', name: 'Bias & Fairness', description: 'Address bias and fairness in AI systems.' },
];
