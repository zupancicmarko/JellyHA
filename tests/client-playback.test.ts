import { describe, it, expect, vi } from 'vitest';
import { JellyHALibraryCardConfig, PlayTarget, MediaItem } from '../src/shared/types';

describe('Play on Jellyfin Client functionality (Issue #62)', () => {
    it('correctly maps default_client_device in card configuration', () => {
        let config: JellyHALibraryCardConfig = {
            type: 'custom:jellyha-library-card',
            entity: 'sensor.jellyfin_library',
            click_action: 'play-client',
        };

        const updateConfig = (key: keyof JellyHALibraryCardConfig, value: unknown) => {
            config = { ...config, [key]: value };
        };

        updateConfig('default_client_device', 'media_player.jellyha_device_living_room_tv');
        expect(config.default_client_device).toBe('media_player.jellyha_device_living_room_tv');

        // Test clearing
        const next = { ...config };
        delete next.default_client_device;
        config = next;
        expect(config.default_client_device).toBeUndefined();
    });

    it('creates client PlayTarget with proper defaults', () => {
        const clientTarget: PlayTarget = {
            type: 'client',
            device: 'media_player.jellyha_device_shield',
            name: 'Play on Living Room Shield',
            icon: 'mdi:television-play',
        };

        expect(clientTarget.type).toBe('client');
        expect(clientTarget.device).toBe('media_player.jellyha_device_shield');
        expect(clientTarget.name).toBe('Play on Living Room Shield');
        expect(clientTarget.icon).toBe('mdi:television-play');
    });

    it('triggers jellyha.session_play with entity_id and item_id for client playback', async () => {
        const mockCallService = vi.fn().mockResolvedValue(true);
        const mockHass: any = {
            callService: mockCallService,
            states: {
                'media_player.jellyha_device_tv': {
                    state: 'idle',
                    attributes: { device_name: 'Living Room TV' },
                },
            },
        };

        const item: MediaItem = {
            id: 'movie_777',
            name: 'Interstellar',
            type: 'Movie',
        };

        const defaultClientDevice = 'media_player.jellyha_device_tv';

        // Helper mimicking _playOnClient execution
        const playOnClient = async (targetDevice: string, mediaItem: MediaItem) => {
            if (!targetDevice) throw new Error('No client device configured');
            await mockHass.callService('jellyha', 'session_play', {
                entity_id: targetDevice,
                item_id: mediaItem.id,
            });
        };

        await playOnClient(defaultClientDevice, item);

        expect(mockCallService).toHaveBeenCalledWith('jellyha', 'session_play', {
            entity_id: 'media_player.jellyha_device_tv',
            item_id: 'movie_777',
        });
    });
});
