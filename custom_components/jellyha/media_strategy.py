"""Media strategy logic for JellyHA."""
from __future__ import annotations

import logging
import uuid
from typing import Any

_LOGGER = logging.getLogger(__name__)

class MediaStrategy:
    """Strategy for determining playback method and URL."""

    @staticmethod
    def analyze_media(item: dict[str, Any]) -> dict[str, Any]:
        """Analyze media item to extract codec and dimension info."""
        media_streams = item.get("MediaStreams", [])
        info = {
            "container": (item.get("Container") or "unknown").lower(),
            "video_codec": "unknown",
            "video_height": 0,
            "bit_depth": 8,
            "audio_codec": "unknown",
            "audio_channels": 2,
        }

        for stream in media_streams:
            if stream.get("Type") == "Video":
                info["video_codec"] = (stream.get("Codec") or "unknown").lower()
                info["video_height"] = int(stream.get("Height") or 0)
                info["bit_depth"] = int(stream.get("BitDepth") or 8)
            elif stream.get("Type") == "Audio" and stream.get("Index") == 1:
                # Assuming first audio track is main
                info["audio_codec"] = (stream.get("Codec") or "unknown").lower()
                info["audio_channels"] = int(stream.get("Channels") or 2)
        
        if info["audio_codec"] == "unknown":
             for stream in media_streams:
                if stream.get("Type") == "Audio":
                    info["audio_codec"] = (stream.get("Codec") or "unknown").lower()
                    info["audio_channels"] = int(stream.get("Channels") or 2)
                    break
        
        return info

    TEXT_SUBTITLE_CODECS = {
        "subrip", "srt", "vtt", "webvtt", "mov_text", "ass", "ssa", "text", "ttml"
    }

    @staticmethod
    def match_language(stream_lang: str | None, stream_title: str | None, target_lang: str) -> bool:
        """Check if a subtitle stream language matches a target language code or name."""
        if not target_lang:
            return False
        
        target = target_lang.strip().lower()
        if not target:
            return False

        base_groups = [
            {"sl", "slv", "slovenian", "slovenski"},
            {"en", "eng", "english"},
            {"de", "ger", "deu", "german", "deutsch"},
            {"fr", "fre", "fra", "french", "francais", "français"},
            {"es", "spa", "spanish", "espanol", "español"},
            {"it", "ita", "italian", "italiano"},
            {"nl", "dut", "nld", "dutch", "nederlands"},
            {"hr", "hrv", "croatian", "hrvatski"},
            {"sr", "srp", "serbian", "srpski"},
            {"bs", "bos", "bosnian", "bosanski"},
            {"ru", "rus", "russian"},
            {"pl", "pol", "polish", "polski"},
            {"cs", "cze", "ces", "czech"},
            {"hu", "hun", "hungarian", "magyar"},
            {"ja", "jpn", "japanese"},
            {"zh", "zho", "chi", "chinese", "zhs", "zht"},
        ]

        s_lang = (stream_lang or "").strip().lower()
        s_title = (stream_title or "").strip().lower()

        target_set = {target}
        for group in base_groups:
            if target in group:
                target_set = group
                break

        if s_lang in target_set:
            return True

        if s_lang and len(target) >= 2 and s_lang.startswith(target):
            return True

        if s_title:
            import re
            title_words = {w.lower() for w in re.findall(r'[a-zA-Z]+', s_title)}
            if any(t in title_words for t in target_set):
                return True

        return False

    @classmethod
    def is_text_subtitle(cls, stream: dict[str, Any]) -> bool:
        """Return True if subtitle stream is text-based (can be served as WebVTT)."""
        codec = (stream.get("Codec") or "").lower()
        return codec in cls.TEXT_SUBTITLE_CODECS or stream.get("IsExternal") is True

    @staticmethod
    def resolve_subtitle_stream(
        item: dict[str, Any],
        subtitle_mode: str = "auto",
        subtitle_language: str | None = None,
        user_config: dict[str, Any] | None = None,
        subtitle_index: int | None = None,
    ) -> dict[str, Any] | None:
        """Resolve the appropriate subtitle stream from an item based on strategy and user configuration."""
        streams = item.get("MediaStreams") or []
        if not streams and "MediaSources" in item and item["MediaSources"]:
            streams = item["MediaSources"][0].get("MediaStreams", [])

        sub_streams = [s for s in streams if s.get("Type") == "Subtitle"]
        if not sub_streams:
            return None

        # 1. Direct stream index override
        if subtitle_index is not None:
            for s in sub_streams:
                if s.get("Index") == subtitle_index:
                    return s
            _LOGGER.warning("Specified subtitle_index %s not found in item %s", subtitle_index, item.get("Id"))
            return None

        mode = (subtitle_mode or "auto").lower()

        # 2. None / Disabled
        if mode == "none":
            return None

        def find_by_lang(lang_code: str, forced_only: bool = False) -> dict[str, Any] | None:
            for s in sub_streams:
                if forced_only and not s.get("IsForced"):
                    continue
                if MediaStrategy.match_language(s.get("Language"), s.get("DisplayTitle"), lang_code):
                    return s
            return None

        # 3. Forced Only
        if mode == "forced_only":
            if subtitle_language:
                langs = [l.strip() for l in subtitle_language.split(",") if l.strip()]
                for l in langs:
                    found = find_by_lang(l, forced_only=True)
                    if found:
                        return found
            for s in sub_streams:
                if s.get("IsForced"):
                    return s
            return None

        # 4. Custom Prioritized Languages (e.g. "sl, en" or "slv, eng")
        if mode == "custom":
            if not subtitle_language:
                for s in sub_streams:
                    if s.get("IsDefault"):
                        return s
                return sub_streams[0] if sub_streams else None

            langs = [l.strip().lower() for l in subtitle_language.split(",") if l.strip()]
            for l in langs:
                found = find_by_lang(l)
                if found:
                    return found
            for s in sub_streams:
                if s.get("IsDefault"):
                    return s
            return None

        # 5. Auto (Jellyfin User Profile)
        # Rule: On auto, if user has no default language set in Jellyfin, fallback to English
        cfg = user_config or {}
        jf_sub_mode = cfg.get("SubtitleMode", "Default")
        jf_pref_lang = cfg.get("SubtitleLanguagePreference")
        jf_pref_audio = cfg.get("AudioLanguagePreference")

        if not jf_pref_lang:
            jf_pref_lang = "eng"

        if jf_sub_mode == "None":
            return None

        if jf_sub_mode == "OnlyForced":
            found = find_by_lang(jf_pref_lang, forced_only=True)
            if found:
                return found
            for s in sub_streams:
                if s.get("IsForced"):
                    return s
            return None

        if jf_sub_mode == "Smart":
            audio_stream = next((s for s in streams if s.get("Type") == "Audio"), None)
            audio_lang = (audio_stream.get("Language") or "").lower() if audio_stream else ""
            
            if jf_pref_audio and MediaStrategy.match_language(audio_lang, None, jf_pref_audio):
                return find_by_lang(jf_pref_lang, forced_only=True)
            if jf_pref_lang and MediaStrategy.match_language(audio_lang, None, jf_pref_lang):
                return find_by_lang(jf_pref_lang, forced_only=True)

            found = find_by_lang(jf_pref_lang)
            if found:
                return found

        # Default or Always:
        found = find_by_lang(jf_pref_lang)
        if found:
            return found

        # Fallback to English if pref_lang wasn't English
        if jf_pref_lang not in ["eng", "en"]:
            found_en = find_by_lang("eng")
            if found_en:
                return found_en

        for s in sub_streams:
            if s.get("IsDefault"):
                return s

        if jf_sub_mode == "Always" and sub_streams:
            return sub_streams[0]

        return None

    @staticmethod
    def extract_video_stream_attributes(item: dict[str, Any] | None) -> dict[str, Any]:
        """Extract dynamic range, HDR profile, and video stream metadata from a Jellyfin item."""
        empty_attrs = {
            "dynamic_range": None,
            "video_range": None,
            "video_range_type": None,
            "video_codec": None,
            "video_bit_depth": None,
            "dv_profile": None,
            "color_transfer": None,
            "color_primaries": None,
            "width": None,
            "height": None,
            "aspect_ratio": None,
            "resolution": None,
        }

        if not item:
            return empty_attrs

        streams = item.get("MediaStreams") or []
        if not streams and "MediaSources" in item and item["MediaSources"]:
            streams = item["MediaSources"][0].get("MediaStreams", [])

        video_stream = None
        for s in streams:
            if s.get("Type") == "Video":
                video_stream = s
                break

        if not video_stream:
            return empty_attrs

        raw_range = video_stream.get("VideoRange")
        raw_range_type = video_stream.get("VideoRangeType")
        color_transfer = video_stream.get("ColorTransfer")
        color_primaries = video_stream.get("ColorPrimaries")
        dv_profile = video_stream.get("DvProfile")
        codec = video_stream.get("Codec")
        bit_depth = video_stream.get("BitDepth")
        width = video_stream.get("Width")
        height = video_stream.get("Height")
        aspect_ratio = video_stream.get("AspectRatio")

        resolution = None
        if width or height:
            try:
                w = int(width or 0)
                h = int(height or 0)
                if w >= 3800 or h >= 2000:
                    resolution = "4K"
                elif w >= 1900 or h >= 1000:
                    resolution = "1080p"
                elif w >= 1200 or h >= 700:
                    resolution = "720p"
                elif h >= 480 or w >= 640:
                    resolution = "480p"
                else:
                    resolution = "SD"
            except (ValueError, TypeError):
                pass

        dynamic_range = "SDR"
        range_type_str = str(raw_range_type or "").upper()
        range_str = str(raw_range or "").upper()
        transfer_str = str(color_transfer or "").lower()

        if range_type_str.startswith("DOVI") or dv_profile is not None:
            dynamic_range = "Dolby Vision"
        elif range_type_str in ("HDR10PLUS", "HDR10+"):
            dynamic_range = "HDR10+"
        elif range_type_str == "HDR10" or transfer_str == "smpte2084":
            dynamic_range = "HDR10"
        elif range_type_str == "HLG" or transfer_str == "arib-std-b67":
            dynamic_range = "HLG"
        elif range_str == "HDR":
            dynamic_range = "HDR"
        elif range_str == "SDR" or transfer_str == "bt709":
            dynamic_range = "SDR"

        return {
            "dynamic_range": dynamic_range,
            "video_range": raw_range or ("HDR" if dynamic_range != "SDR" else "SDR"),
            "video_range_type": raw_range_type or dynamic_range,
            "video_codec": codec.lower() if codec else None,
            "video_bit_depth": bit_depth,
            "dv_profile": dv_profile,
            "color_transfer": color_transfer,
            "color_primaries": color_primaries,
            "width": width,
            "height": height,
            "aspect_ratio": aspect_ratio,
            "resolution": resolution,
        }

    @staticmethod
    def discover_chromecast_model(
        hass: Any, entity_id: str, zc: Any = None
    ) -> tuple[str, bool]:
        """Discover Chromecast model and determining legacy status via pychromecast.
        
        This method must be run in an executor (it blocks).
        """
        model_name = "Unknown"
        is_legacy = False
        
        try:
            # We are running in an executor (thread), so we can make blocking calls.
            # Accessing hass.states.get() from a thread is generally safe for reading.
            entity_state = hass.states.get(entity_id)
            if entity_state:
                friendly_name = entity_state.attributes.get("friendly_name")
                if friendly_name:
                    import pychromecast
                    kwargs: dict[str, Any] = {"discovery_timeout": 5.0}
                    if zc is not None:
                        kwargs["zeroconf_instance"] = zc
                    chromecasts, browser = pychromecast.get_listed_chromecasts(
                        [friendly_name],
                        **kwargs,
                    )
                    
                    if chromecasts:
                        cast_device = chromecasts[0]
                        model_name = cast_device.model_name
                        # Gen 1, 2, 3 are "Chromecast". Ultra/TV are different.
                        if model_name == "Chromecast":
                            is_legacy = True
                    if browser:
                        browser.stop_discovery()
        except Exception as e:
            _LOGGER.warning("Could not detect Chromecast model: %s", e)
            
        return model_name, is_legacy

    @staticmethod
    def get_playback_info(
        server_url: str,
        api_key: str,
        item_id: str,
        media_info: dict[str, Any],
        device_model: str,
        item_type: str = "Video",
        selected_sub: dict[str, Any] | None = None,
        media_source_id: str | None = None,
    ) -> dict[str, Any]:
        """Determine playback strategy and return URL/Type."""
        
        is_legacy_device = device_model == "Chromecast"
        
        video_codec = media_info["video_codec"]
        video_height = media_info["video_height"]
        bit_depth = media_info["bit_depth"]
        audio_codec = media_info["audio_codec"]
        audio_channels = media_info["audio_channels"]
        container = media_info.get("container", "unknown")

        if item_type == "Audio":
            # Audio-specific compatibility matrix
            is_format_standard = audio_codec in ["mp3", "aac", "ac3", "wav"]
            should_direct_play = False
            
            if is_legacy_device:
                # LEGACY: No FLAC, ALAC natively
                if is_format_standard and audio_channels <= 2 and container not in ["flac", "alac"]:
                    should_direct_play = True
            else:
                # MODERN: FLAC is supported
                should_direct_play = True
                
            if should_direct_play:
                content_type = "audio/mpeg"
                if container == "flac":
                    content_type = "audio/flac"
                elif container in ["m4a", "aac"]:
                    content_type = "audio/mp4"
                elif container in ["ogg", "oga"]:
                    content_type = "audio/ogg"
                elif container == "wav":
                    content_type = "audio/wav"
                    
                _LOGGER.info("Strategy Selected: DIRECT PLAY (Audio - %s)", content_type)
                return {
                    "media_url": f"{server_url}/Audio/{item_id}/stream?static=true&api_key={api_key}&ApiKey={api_key}",
                    "content_type": content_type
                }
            else:
                # Force an HLS transcode for incompatible audio limits
                _LOGGER.info("Strategy Selected: TRANSCODE (Legacy Audio HLS)")
                media_url = (
                    f"{server_url}/Audio/{item_id}/master.m3u8"
                    f"?api_key={api_key}&ApiKey={api_key}"
                    f"&DeviceId=JellyHA_Cast"
                    f"&MediaSourceId={item_id}"
                    f"&AudioCodec=mp3"
                    f"&AudioBitrate=320000"
                    f"&TranscodingContainer=ts"
                    f"&TranscodingProtocol=hls"
                )
                return {
                    "media_url": media_url,
                    "content_type": "application/x-mpegURL"
                }

        # Check Format Basics (Video)
        is_format_standard = (
            video_codec in ["h264", "avc"] and 
            bit_depth == 8 and
            audio_codec in ["aac", "mp3", "ac3"]
        )

        should_direct_play = False

        if is_legacy_device:
            # LEGACY: Strict limits (Max 720p, Max Stereo)
            if is_format_standard and video_height <= 720 and audio_channels <= 2:
                should_direct_play = True
        else:
            # MODERN: Standard limits (Max 1080p)
            if is_format_standard and video_height <= 1080:
                should_direct_play = True

        reason = (
            f"Codec={video_codec}/{audio_codec}, "
            f"H={video_height}p, Ch={audio_channels}, "
            f"Legacy={is_legacy_device}"
        )

        _LOGGER.info(
            "Media Analysis: %s | DirectPlay Decision: %s", 
            reason, should_direct_play
        )

        # Hybrid Subtitle Evaluation
        force_burn_in = False
        vtt_url = None
        sub_index = None
        sub_lang = "en"
        sub_title = "Subtitles"

        if selected_sub is not None:
            sub_index = selected_sub.get("Index")
            is_text = MediaStrategy.is_text_subtitle(selected_sub)
            sub_lang = selected_sub.get("Language") or "en"
            sub_title = selected_sub.get("DisplayTitle") or "Subtitles"

            if should_direct_play and is_text:
                # Text subtitle on direct-playable video: deliver WebVTT sidecar (0% server transcode CPU!)
                ms_id = media_source_id or item_id
                vtt_url = f"{server_url}/Videos/{item_id}/{ms_id}/Subtitles/{sub_index}/Stream.vtt?api_key={api_key}&ApiKey={api_key}"
            else:
                # Video requires transcode OR subtitle is bitmap (PGS/VobSub): force transcode with burn-in
                should_direct_play = False
                force_burn_in = True

        sub_params = "&EnableSubtitlesInManifest=false"
        if selected_sub is not None and (force_burn_in or not should_direct_play):
            sub_params = f"&SubtitleStreamIndex={sub_index}&SubtitleMethod=Encode"

        media_url = ""
        content_type = ""
        log_mode = ""

        if should_direct_play:
            # [A] DIRECT PLAY
            log_mode = "DIRECT (H.264)"
            if vtt_url:
                log_mode += f" + WebVTT Sidecar ({sub_lang})"
            media_url = (
                f"{server_url}/Videos/{item_id}/stream"
                f"?Static=true"
                f"&api_key={api_key}&ApiKey={api_key}"
                f"&VideoCodec=h264"
                f"&AudioCodec=aac"
            )
            content_type = "video/mp4"
            
        elif is_legacy_device:
            # [B] LEGACY TRANSCODE (Gen 1)
            log_mode = "TRANSCODE (Legacy Gen 1 - Force 720p/Stereo)"
            if force_burn_in:
                log_mode += f" + Burn-in Subtitles ({sub_lang})"
            
            play_session_id = uuid.uuid4().hex
            media_url = (
                f"{server_url}/Videos/{item_id}/master.m3u8"
                f"?api_key={api_key}&ApiKey={api_key}"
                f"&PlaySessionId={play_session_id}"
                f"&DeviceId=JellyHA_Cast"
                f"&MediaSourceId={item_id}"
                f"&Width=1280"
                f"&Height=720"
                f"&VideoBitrate=18000000"
                f"&MaxStreamingBitrate=18000000"
                f"&EncoderPreset=veryfast"
                f"&VideoCodec=h264"
                f"&h264-profile=high"
                f"&h264-level=41"
                f"&h264-videobitdepth=8"
                f"&AudioCodec=aac"
                f"&AudioBitrate=256000"
                f"&AudioSampleRate=48000"
                f"&TranscodingMaxAudioChannels=2" 
                f"&SegmentContainer=ts"
                f"&MinSegments=2"
                f"&BreakOnNonKeyFrames=False"
                f"&CopyTimestamps=true"
                f"{sub_params}"
            )
            content_type = "application/x-mpegURL"
            
        else:
            # [C] MODERN TRANSCODE (Tuned 2026 Settings)
            log_mode = "TRANSCODE (Modern HQ)"
            if force_burn_in:
                log_mode += f" + Burn-in Subtitles ({sub_lang})"
            
            play_session_id = uuid.uuid4().hex
            media_url = (
                f"{server_url}/Videos/{item_id}/master.m3u8"
                f"?api_key={api_key}&ApiKey={api_key}"
                f"&PlaySessionId={play_session_id}"
                f"&DeviceId=JellyHA_Cast"
                f"&MediaSourceId={item_id}"
                f"&Width=1920"
                f"&Height=1080"
                f"&VideoBitrate=20000000"
                f"&MaxStreamingBitrate=20000000"
                f"&EncoderPreset=medium"
                f"&VideoCodec=h264"
                f"&h264-profile=high"
                f"&h264-level=51"
                f"&h264-videobitdepth=8"
                f"&AudioCodec=aac"
                f"&AudioBitrate=320000"
                f"&TranscodingMaxAudioChannels=6"
                f"&SegmentContainer=ts"
                f"&MinSegments=2"
                f"&BreakOnNonKeyFrames=False"
                f"&CopyTimestamps=true"
                f"{sub_params}"
            )
            content_type = "application/x-mpegURL"

        # Log
        safe_url = media_url.replace(api_key, "REDACTED")
        _LOGGER.info("Strategy Selected: %s", log_mode)
        _LOGGER.debug("Target URL: %s", safe_url)

        result: dict[str, Any] = {
            "media_url": media_url,
            "content_type": content_type,
            "log_mode": log_mode,
        }
        if vtt_url:
            result["vtt_url"] = vtt_url
            result["subtitles_lang"] = sub_lang
            result["subtitles_title"] = sub_title
        if selected_sub is not None:
            result["subtitle_stream_index"] = sub_index

        return result
