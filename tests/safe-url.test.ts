import { describe, it, expect, vi, beforeEach } from 'vitest';
import { isSafeExternalUrl, safeOpenWindow } from '../src/shared/safe-url';

describe('safe-url utilities', () => {
  describe('isSafeExternalUrl', () => {
    it('accepts standard https and http URLs', () => {
      expect(isSafeExternalUrl('https://youtube.com/watch?v=dQw4w9WgXcQ')).toBe(true);
      expect(isSafeExternalUrl('http://jellyfin.local:8096/web/index.html')).toBe(true);
      expect(isSafeExternalUrl('https://app.jellyfin.org/#/details?id=123')).toBe(true);
    });

    it('accepts valid vnd.youtube intent URIs', () => {
      expect(isSafeExternalUrl('vnd.youtube:dQw4w9WgXcQ')).toBe(true);
      expect(isSafeExternalUrl('vnd.youtube:abc_12-XY')).toBe(true);
    });

    it('rejects unsafe protocols and XSS payloads', () => {
      expect(isSafeExternalUrl('javascript:alert(document.cookie)')).toBe(false);
      expect(isSafeExternalUrl('JAVASCRIPT:alert(1)')).toBe(false);
      expect(isSafeExternalUrl('data:text/html,<script>alert(1)</script>')).toBe(false);
      expect(isSafeExternalUrl('vbscript:msgbox("hello")')).toBe(false);
      expect(isSafeExternalUrl('file:///etc/passwd')).toBe(false);
      expect(isSafeExternalUrl('blob:https://example.com/uuid')).toBe(false);
    });

    it('rejects empty, non-string, or malformed inputs', () => {
      expect(isSafeExternalUrl('')).toBe(false);
      expect(isSafeExternalUrl('   ')).toBe(false);
      expect(isSafeExternalUrl(null)).toBe(false);
      expect(isSafeExternalUrl(undefined)).toBe(false);
      expect(isSafeExternalUrl('not-a-valid-url')).toBe(false);
      expect(isSafeExternalUrl('vnd.youtube:invalid payload with spaces')).toBe(false);
    });
  });

  describe('safeOpenWindow', () => {
    beforeEach(() => {
      vi.restoreAllMocks();
      if (typeof (globalThis as any).window === 'undefined') {
        (globalThis as any).window = { open: vi.fn() };
      }
    });

    it('calls window.open with noopener,noreferrer for safe URLs', () => {
      const openSpy = vi.spyOn(window, 'open').mockReturnValue({} as Window);
      const res = safeOpenWindow('https://www.youtube.com/watch?v=test', '_blank');

      expect(openSpy).toHaveBeenCalledWith(
        'https://www.youtube.com/watch?v=test',
        '_blank',
        'noopener,noreferrer'
      );
      expect(res).not.toBeNull();
    });

    it('refuses to open unsafe URLs and returns null', () => {
      const openSpy = vi.spyOn(window, 'open');
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      const res = safeOpenWindow('javascript:alert(1)', '_blank');
      expect(openSpy).not.toHaveBeenCalled();
      expect(warnSpy).toHaveBeenCalledWith('Blocked opening unsafe URL:', 'javascript:alert(1)');
      expect(res).toBeNull();
    });
  });
});
