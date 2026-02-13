import { describe, it, expect } from 'vitest';
import { isRemoteUrl, parseTarget } from '../../src/remote/clone.js';

describe('Remote scan utilities', () => {
  describe('isRemoteUrl', () => {
    it('should detect HTTPS GitHub URLs', () => {
      expect(isRemoteUrl('https://github.com/org/repo')).toBe(true);
    });

    it('should detect HTTPS GitLab URLs', () => {
      expect(isRemoteUrl('https://gitlab.com/org/repo')).toBe(true);
    });

    it('should detect SSH git URLs', () => {
      expect(isRemoteUrl('git@github.com:org/repo.git')).toBe(true);
    });

    it('should detect SSH protocol URLs', () => {
      expect(isRemoteUrl('ssh://git@github.com/org/repo')).toBe(true);
    });

    it('should reject local paths', () => {
      expect(isRemoteUrl('.')).toBe(false);
      expect(isRemoteUrl('/home/user/project')).toBe(false);
      expect(isRemoteUrl('./relative/path')).toBe(false);
    });

    it('should reject non-repo URLs', () => {
      expect(isRemoteUrl('https://example.com')).toBe(false);
    });
  });

  describe('parseTarget', () => {
    it('should parse HTTPS GitHub URL', () => {
      const target = parseTarget('https://github.com/langchain-ai/langchain');
      expect(target.host).toBe('github.com');
      expect(target.owner).toBe('langchain-ai');
      expect(target.repo).toBe('langchain');
      expect(target.branch).toBeUndefined();
    });

    it('should parse URL with branch suffix', () => {
      const target = parseTarget('https://github.com/org/repo#main');
      expect(target.owner).toBe('org');
      expect(target.repo).toBe('repo');
      expect(target.branch).toBe('main');
    });

    it('should parse SSH URL', () => {
      const target = parseTarget('git@github.com:org/repo.git');
      expect(target.host).toBe('github.com');
      expect(target.owner).toBe('org');
      expect(target.repo).toBe('repo');
    });

    it('should strip .git suffix', () => {
      const target = parseTarget('https://github.com/org/repo.git');
      expect(target.repo).toBe('repo');
    });
  });
});
