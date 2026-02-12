export interface AIUC1Entry {
  id: string;
  name: string;
  description: string;
}

export const AIUC1_CONTROLS: AIUC1Entry[] = [
  { id: 'A001', name: 'Prompt Injection Prevention', description: 'Controls to prevent prompt injection attacks on AI agents.' },
  { id: 'A002', name: 'Input Validation', description: 'Validate and sanitize all inputs to AI systems.' },
  { id: 'A003', name: 'Output Filtering', description: 'Filter and validate AI model outputs before use.' },
  { id: 'B001', name: 'Authentication & Authorization', description: 'Enforce authentication and authorization for AI agent access.' },
  { id: 'B002', name: 'Credential Management', description: 'Secure storage and rotation of credentials used by AI agents.' },
  { id: 'B003', name: 'Least Privilege', description: 'Apply least privilege principle to AI agent permissions.' },
  { id: 'C001', name: 'Dependency Management', description: 'Manage and verify AI system dependencies.' },
  { id: 'C002', name: 'Supply Chain Integrity', description: 'Ensure integrity of AI model and plugin supply chains.' },
  { id: 'D001', name: 'Code Execution Safety', description: 'Sandbox and restrict code execution capabilities.' },
  { id: 'D002', name: 'Injection Prevention', description: 'Prevent SQL, command, and template injection attacks.' },
  { id: 'E001', name: 'Data Protection', description: 'Protect sensitive data in AI agent pipelines.' },
  { id: 'E002', name: 'Privacy Controls', description: 'Implement privacy controls for PII and user data.' },
  { id: 'E003', name: 'Logging & Monitoring', description: 'Secure logging without exposing sensitive information.' },
  { id: 'F001', name: 'Memory Safety', description: 'Secure memory storage and access controls for AI agents.' },
  { id: 'F002', name: 'Context Isolation', description: 'Isolate context and memory across users and sessions.' },
];
