/**
 * Utility for verifying and safely opening external URLs.
 * Prevents JavaScript execution (XSS) via javascript:, data:, or malformed URI schemes,
 * and ensures tab isolation by always applying noopener,noreferrer.
 */

export function isSafeExternalUrl(url: string | null | undefined): boolean {
  if (!url || typeof url !== 'string') return false;
  const trimmed = url.trim();
  if (/^vnd\.youtube:[a-zA-Z0-9_-]{5,20}$/i.test(trimmed)) {
    return true;
  }
  try {
    const parsed = new URL(trimmed);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch {
    return false;
  }
}

export function safeOpenWindow(url: string | null | undefined, target = '_blank'): Window | null {
  if (!isSafeExternalUrl(url)) {
    console.warn('Blocked opening unsafe URL:', url);
    return null;
  }
  if (typeof window === 'undefined' || typeof window.open !== 'function') {
    return null;
  }
  return window.open(url!.trim(), target, 'noopener,noreferrer');
}
