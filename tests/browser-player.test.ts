import { describe, it, expect, vi, beforeEach } from 'vitest';

// Provide basic browser globals for Lit if running in Node environment
if (typeof window === 'undefined') {
    (global as any).window = {
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
    };
    (global as any).document = {
        createElement: vi.fn(() => ({
            appendChild: vi.fn(),
            remove: vi.fn(),
            querySelector: vi.fn(),
        })),
        body: {
            appendChild: vi.fn(),
            contains: vi.fn(() => false),
        },
    };
    (global as any).customElements = {
        define: vi.fn(),
        get: vi.fn(),
    };
}

import { JellyHABrowserPlayer } from '../src/components/jellyha-browser-player';

describe('JellyHABrowserPlayer HLS & Lifecycle', () => {
    let player: JellyHABrowserPlayer;
    let callWS: any;
    let mockHass: any;

    beforeEach(() => {
        callWS = vi.fn();
        mockHass = {
            callWS,
            states: {
                'sensor.jellyha_server': {
                    entity_id: 'sensor.jellyha_server',
                    state: 'online',
                    attributes: { config_entry_id: 'entry_123' },
                },
            },
        };
        player = new JellyHABrowserPlayer();
        player.hass = mockHass;
    });

    it('resolves stream via jellyha/resolve_playback and handles DirectPlay', async () => {
        callWS.mockResolvedValueOnce({
            play_method: 'DirectPlay',
            url: '/api/jellyha/stream/entry_123/item_1?authSig=valid',
            mime_type: 'video/mp4',
        });

        const res = await (player as any)._resolveStream({
            hass: mockHass,
            item: { id: 'item_1', name: 'Movie 1', type: 'Movie' } as any,
            configEntryId: 'entry_123',
        });

        expect(callWS).toHaveBeenCalledWith({
            type: 'jellyha/resolve_playback',
            item_id: 'item_1',
            config_entry_id: 'entry_123',
        });
        expect(res.url).toBe('/api/jellyha/stream/entry_123/item_1?authSig=valid');
        expect(res.mimeType).toBe('video/mp4');
        expect((player as any)._playMethod).toBe('DirectPlay');
    });

    it('resolves stream via jellyha/resolve_playback and handles Transcode with HLS token', async () => {
        callWS.mockResolvedValueOnce({
            play_method: 'Transcode',
            url: '/api/jellyha/hls/tok_abc/master.m3u8?MediaSourceId=ms_1&PlaySessionId=ps_99',
            mime_type: 'application/x-mpegURL',
            play_session_id: 'ps_99',
            token: 'tok_abc',
        });

        const res = await (player as any)._resolveStream({
            hass: mockHass,
            item: { id: 'item_2', name: 'Movie AVI', type: 'Movie' } as any,
            configEntryId: 'entry_123',
        });

        expect(callWS).toHaveBeenCalledWith({
            type: 'jellyha/resolve_playback',
            item_id: 'item_2',
            config_entry_id: 'entry_123',
        });
        expect(res.url).toContain('/api/jellyha/hls/tok_abc/master.m3u8');
        expect(res.mimeType).toBe('application/x-mpegURL');
        expect((player as any)._playMethod).toBe('Transcode');
        expect((player as any)._playSessionId).toBe('ps_99');
        expect((player as any)._hlsToken).toBe('tok_abc');
    });

    it('terminates active transcode on close() and destroys hls instance', async () => {
        (player as any)._playMethod = 'Transcode';
        (player as any)._hlsToken = 'tok_abc';
        (player as any)._playSessionId = 'ps_99';
        const mockDestroy = vi.fn();
        (player as any)._hlsInstance = { destroy: mockDestroy };

        player.close();

        expect(mockDestroy).toHaveBeenCalled();
        expect(callWS).toHaveBeenCalledWith({
            type: 'jellyha/stop_playback',
            token: 'tok_abc',
            play_session_id: 'ps_99',
        });
        expect((player as any)._hlsInstance).toBeUndefined();
        expect((player as any)._hlsToken).toBeUndefined();
        expect((player as any)._playSessionId).toBeUndefined();
    });
});
