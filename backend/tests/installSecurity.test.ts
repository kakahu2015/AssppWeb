import { describe, it, expect } from 'vitest';
import {
  createInstallSignature,
  verifyInstallSignature,
} from '../src/routes/install.js';

describe('install URL signature helpers', () => {
  it('verifies a valid signature', () => {
    const id = 'task-123';
    const expires = String(Date.now() + 60_000);
    const secret = 'test-secret';
    const signature = createInstallSignature(id, expires, secret);

    expect(verifyInstallSignature(id, expires, signature, secret)).toBe(true);
  });

  it('rejects an invalid signature', () => {
    const id = 'task-123';
    const expires = String(Date.now() + 60_000);
    const secret = 'test-secret';

    expect(verifyInstallSignature(id, expires, 'invalid-signature', secret)).toBe(
      false,
    );
  });

  it('rejects a signature from a different payload', () => {
    const secret = 'test-secret';
    const signature = createInstallSignature('task-abc', '123456', secret);

    expect(
      verifyInstallSignature('task-def', '123456', signature, secret),
    ).toBe(false);
  });
});
