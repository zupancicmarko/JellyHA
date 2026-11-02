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

    it('resolves audio tracks from item media_streams and marks default track', () => {
        const item = {
            id: 'item_multi',
            name: 'Multi Audio Movie',
            type: 'Movie',
            media_streams: [
                { Type: 'Video', Index: 0, Codec: 'h264', Width: 1920, Height: 1080 },
                { Type: 'Audio', Index: 1, Language: 'jpn', Codec: 'eac3', Channels: 6, IsDefault: false },
                { Type: 'Audio', Index: 2, Language: 'eng', Codec: 'ac3', Channels: 6, IsDefault: true },
                { Type: 'Audio', Index: 3, Language: 'slv', Codec: 'aac', Channels: 2, IsDefault: false },
                { Type: 'Subtitle', Index: 4, Language: 'eng', Codec: 'srt' },
            ],
        } as any;

        const tracks = (player as any)._resolveAudioTracks(item);
        expect(tracks).toHaveLength(3);
        expect(tracks[0]).toMatchObject({
            index: 1,
            label: 'Japanese',
            shortLang: 'JPN',
            details: '5.1 • EAC3',
            isDefault: false,
        });
        expect(tracks[1]).toMatchObject({
            index: 2,
            label: 'English',
            shortLang: 'ENG',
            details: '5.1 • AC3',
            isDefault: true,
        });
        expect(tracks[2]).toMatchObject({
            index: 3,
            label: 'Slovenian',
            shortLang: 'SLV',
            details: 'Stereo • AAC',
            isDefault: false,
        });
    });

    it('passes audio_stream_index to jellyha/resolve_playback when switching audio tracks', async () => {
        callWS.mockResolvedValueOnce({
            play_method: 'Transcode',
            url: '/api/jellyha/hls/tok_new/master.m3u8?AudioStreamIndex=3',
            mime_type: 'application/x-mpegURL',
            play_session_id: 'ps_new',
            token: 'tok_new',
        });

        const res = await (player as any)._resolveStream({
            hass: mockHass,
            item: { id: 'item_1', name: 'Movie 1', type: 'Movie' } as any,
            configEntryId: 'entry_123',
            audioStreamIndex: 3,
        });

        expect(callWS).toHaveBeenCalledWith({
            type: 'jellyha/resolve_playback',
            item_id: 'item_1',
            config_entry_id: 'entry_123',
            audio_stream_index: 3,
        });
        expect(res.url).toContain('AudioStreamIndex=3');
    });

    it('switches audio track via _selectAudioTrack and preserves playback timestamp', async () => {
        (player as any)._open = true;
        (player as any)._item = {
            id: 'item_1',
            name: 'Movie 1',
            type: 'Movie',
            config_entry_id: 'entry_123',
        };
        (player as any)._selectedAudioIndex = 1;
        (player as any)._hlsToken = 'old_tok';
        (player as any)._playSessionId = 'old_ps';

        const mockVideo = {
            currentTime: 142.5,
            paused: false,
            play: vi.fn(() => Promise.resolve()),
            pause: vi.fn(),
            load: vi.fn(),
        };
        (player as any)._portalContainer = {
            querySelector: vi.fn((sel: string) => (sel === 'video' ? mockVideo : null)),
            remove: vi.fn(),
        };
        vi.spyOn(player as any, '_renderPortal').mockImplementation(() => {});
        const attachSpy = vi.spyOn(player as any, '_attachVideoMedia').mockResolvedValue(undefined);

        // First callWS is stop_playback for old session, second is resolve_playback for new audio stream
        callWS.mockImplementation((msg: any) => {
            if (msg.type === 'jellyha/stop_playback') {
                return Promise.resolve({ success: true });
            }
            if (msg.type === 'jellyha/resolve_playback') {
                return Promise.resolve({
                    play_method: 'Transcode',
                    url: '/api/jellyha/hls/new_tok/master.m3u8?AudioStreamIndex=2',
                    mime_type: 'application/x-mpegURL',
                    play_session_id: 'new_ps',
                    token: 'new_tok',
                });
            }
            return Promise.resolve({});
        });

        await (player as any)._selectAudioTrack(2);

        expect((player as any)._selectedAudioIndex).toBe(2);
        expect(callWS).toHaveBeenCalledWith({
            type: 'jellyha/stop_playback',
            token: 'old_tok',
            play_session_id: 'old_ps',
        });
        expect(callWS).toHaveBeenCalledWith({
            type: 'jellyha/resolve_playback',
            item_id: 'item_1',
            config_entry_id: 'entry_123',
            audio_stream_index: 2,
        });
        expect(attachSpy).toHaveBeenCalledWith(142.5, false);
    });
});
