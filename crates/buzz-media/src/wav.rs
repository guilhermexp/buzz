//! Canonical PCM WAV validation for voice notes.
//!
//! Audio is otherwise refused on the generic file path because Buzz has no
//! sanitizer for arbitrary audio containers. Voice notes are the exception:
//! Buzz clients record them as plain 16-bit PCM RIFF/WAVE files. This module
//! accepts exactly that shape and nothing else, as a structural allowlist like
//! the image metadata policy:
//!
//! - `RIFF` size equals the file length minus 8 — no trailing bytes;
//! - chunks in order `fmt ` → optional `fact` → `data`, each exactly once,
//!   with `data` last; any other chunk (`LIST`/`INFO`, `id3 `, `bext`, …)
//!   is metadata and rejected rather than stripped;
//! - PCM only (format tag 1, or `WAVE_FORMAT_EXTENSIBLE` with the PCM
//!   subformat), 1–2 channels, 8–48 kHz, 16 bits per sample, with consistent
//!   block align, byte rate and channel mask;
//! - a non-empty `data` chunk of whole frames, at most
//!   [`MAX_WAV_DURATION_SECS`] long.
//!
//! Accepted bytes are stored unmodified, so the Blossom `x` hash the client
//! signed remains the blob's address. Clients must remove metadata before
//! upload; the relay never rewrites audio.

use crate::error::MediaError;

/// Longest accepted voice note.
pub const MAX_WAV_DURATION_SECS: f64 = 300.0;

const WAVE_FORMAT_PCM: u16 = 0x0001;
const WAVE_FORMAT_EXTENSIBLE: u16 = 0xfffe;
/// `KSDATAFORMAT_SUBTYPE_PCM` as stored in a WAVE file (little-endian GUID).
const PCM_SUBFORMAT: [u8; 16] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71,
];

/// Properties of an accepted WAV voice note.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WavMeta {
    /// Channel count (1 or 2).
    pub channels: u16,
    /// Sample rate in Hz.
    pub sample_rate: u32,
    /// Duration in seconds.
    pub duration_secs: f64,
}

/// Validate `bytes` as a canonical 16-bit PCM WAV voice note.
///
/// Unknown chunks are [`MediaError::MetadataForbidden`], over-long audio is
/// [`MediaError::DurationTooLong`], everything else malformed or unsupported
/// is [`MediaError::InvalidAudio`].
pub fn validate_wav(bytes: &[u8]) -> Result<WavMeta, MediaError> {
    if bytes.len() < 12 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
        return Err(MediaError::InvalidAudio);
    }
    if (u32_le(bytes, 4) as usize).checked_add(8) != Some(bytes.len()) {
        return Err(MediaError::InvalidAudio);
    }

    let mut format: Option<Format> = None;
    let mut fact_frames: Option<u32> = None;
    let mut data_len: Option<usize> = None;
    let mut offset = 12;
    while offset < bytes.len() {
        // `data` is the last chunk; anything after it is trailing payload.
        if data_len.is_some() {
            return Err(MediaError::InvalidAudio);
        }
        if bytes.len() - offset < 8 {
            return Err(MediaError::InvalidAudio);
        }
        let id = &bytes[offset..offset + 4];
        let size = u32_le(bytes, offset + 4) as usize;
        let body_start = offset + 8;
        let body_end = body_start
            .checked_add(size)
            .ok_or(MediaError::InvalidAudio)?;
        let padded_end = body_end + (size & 1);
        if padded_end > bytes.len() || (size & 1 == 1 && bytes[body_end] != 0) {
            return Err(MediaError::InvalidAudio);
        }
        let body = &bytes[body_start..body_end];
        match id {
            b"fmt " => {
                if format.is_some() {
                    return Err(MediaError::InvalidAudio);
                }
                format = Some(parse_format(body)?);
            }
            b"fact" => {
                if format.is_none() || fact_frames.is_some() || body.len() != 4 {
                    return Err(MediaError::InvalidAudio);
                }
                fact_frames = Some(u32_le(body, 0));
            }
            b"data" => {
                if format.is_none() {
                    return Err(MediaError::InvalidAudio);
                }
                data_len = Some(body.len());
            }
            _ => return Err(MediaError::MetadataForbidden),
        }
        offset = padded_end;
    }

    let format = format.ok_or(MediaError::InvalidAudio)?;
    let data_len = data_len.ok_or(MediaError::InvalidAudio)?;
    let block_align = usize::from(format.channels) * 2;
    if data_len == 0 || data_len % block_align != 0 {
        return Err(MediaError::InvalidAudio);
    }
    let frames = data_len / block_align;
    if fact_frames.is_some_and(|declared| declared as usize != frames) {
        return Err(MediaError::InvalidAudio);
    }
    let duration_secs = frames as f64 / f64::from(format.sample_rate);
    if duration_secs > MAX_WAV_DURATION_SECS {
        return Err(MediaError::DurationTooLong);
    }
    Ok(WavMeta {
        channels: format.channels,
        sample_rate: format.sample_rate,
        duration_secs,
    })
}

struct Format {
    channels: u16,
    sample_rate: u32,
}

fn parse_format(body: &[u8]) -> Result<Format, MediaError> {
    if !matches!(body.len(), 16 | 18 | 40) {
        return Err(MediaError::InvalidAudio);
    }
    let tag = u16_le(body, 0);
    let channels = u16_le(body, 2);
    let sample_rate = u32_le(body, 4);
    let byte_rate = u32_le(body, 8);
    let block_align = u16_le(body, 12);
    let bits = u16_le(body, 14);

    let canonical_pcm = match body.len() {
        16 => tag == WAVE_FORMAT_PCM,
        18 => tag == WAVE_FORMAT_PCM && u16_le(body, 16) == 0,
        _ => {
            let channel_mask = u32_le(body, 20);
            tag == WAVE_FORMAT_EXTENSIBLE
                && u16_le(body, 16) == 22
                && u16_le(body, 18) == 16
                && (channel_mask == 0 || channel_mask.count_ones() == u32::from(channels))
                && body[24..40] == PCM_SUBFORMAT
        }
    };
    if !canonical_pcm
        || !(1..=2).contains(&channels)
        || !(8_000..=48_000).contains(&sample_rate)
        || bits != 16
        || block_align != channels * 2
        || byte_rate != sample_rate * u32::from(block_align)
    {
        return Err(MediaError::InvalidAudio);
    }
    Ok(Format {
        channels,
        sample_rate,
    })
}

fn u16_le(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_le(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(id: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut out = id.to_vec();
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(body);
        if body.len() % 2 == 1 {
            out.push(0);
        }
        out
    }

    fn pcm_fmt(channels: u16, rate: u32, bits: u16) -> Vec<u8> {
        let align = channels * bits / 8;
        let mut fmt = Vec::new();
        fmt.extend_from_slice(&WAVE_FORMAT_PCM.to_le_bytes());
        fmt.extend_from_slice(&channels.to_le_bytes());
        fmt.extend_from_slice(&rate.to_le_bytes());
        fmt.extend_from_slice(&(rate * u32::from(align)).to_le_bytes());
        fmt.extend_from_slice(&align.to_le_bytes());
        fmt.extend_from_slice(&bits.to_le_bytes());
        fmt
    }

    fn riff(chunks: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = chunks.concat();
        let mut out = b"RIFF".to_vec();
        out.extend_from_slice(&((body.len() + 4) as u32).to_le_bytes());
        out.extend_from_slice(b"WAVE");
        out.extend_from_slice(&body);
        out
    }

    /// Mono 16-bit 24 kHz, as the web and desktop recorders emit.
    fn voice_note(frames: usize) -> Vec<u8> {
        riff(&[
            chunk(b"fmt ", &pcm_fmt(1, 24_000, 16)),
            chunk(b"data", &vec![0x11; frames * 2]),
        ])
    }

    #[test]
    fn accepts_recorder_voice_note() {
        let meta = validate_wav(&voice_note(24_000)).expect("canonical voice note");
        assert_eq!(meta.channels, 1);
        assert_eq!(meta.sample_rate, 24_000);
        assert!((meta.duration_secs - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn accepts_stereo_fact_and_extensible_pcm() {
        let stereo = riff(&[
            chunk(b"fmt ", &pcm_fmt(2, 48_000, 16)),
            chunk(b"fact", &480u32.to_le_bytes()),
            chunk(b"data", &[0u8; 480 * 4]),
        ]);
        assert_eq!(validate_wav(&stereo).unwrap().channels, 2);

        let mut ext = pcm_fmt(1, 16_000, 16);
        ext[0..2].copy_from_slice(&WAVE_FORMAT_EXTENSIBLE.to_le_bytes());
        ext.extend_from_slice(&22u16.to_le_bytes());
        ext.extend_from_slice(&16u16.to_le_bytes());
        ext.extend_from_slice(&4u32.to_le_bytes()); // front center
        ext.extend_from_slice(&PCM_SUBFORMAT);
        let extensible = riff(&[chunk(b"fmt ", &ext), chunk(b"data", &[0u8; 320])]);
        assert_eq!(validate_wav(&extensible).unwrap().sample_rate, 16_000);
    }

    #[test]
    fn metadata_chunks_are_rejected_not_stripped() {
        let fmt = chunk(b"fmt ", &pcm_fmt(1, 24_000, 16));
        let data = chunk(b"data", &[0u8; 48]);
        for (id, body) in [
            (b"LIST", &b"INFOINAM\x05\x00\x00\x00home\x00\x00"[..]),
            (b"id3 ", &b"ID3\x04\x00\x00\x00\x00\x00\x00"[..]),
            (b"bext", &[0u8; 10][..]),
            (b"JUNK", &[0u8; 4][..]),
        ] {
            let before_data = riff(&[fmt.clone(), chunk(id, body), data.clone()]);
            assert!(
                matches!(
                    validate_wav(&before_data),
                    Err(MediaError::MetadataForbidden)
                ),
                "{:?} before data",
                std::str::from_utf8(id)
            );
        }
        // Even an allowed chunk after `data` is trailing payload.
        let after_data = riff(&[
            fmt.clone(),
            data.clone(),
            chunk(b"fact", &24u32.to_le_bytes()),
        ]);
        assert!(matches!(
            validate_wav(&after_data),
            Err(MediaError::InvalidAudio)
        ));
    }

    #[test]
    fn malformed_sizes_are_rejected() {
        let good = voice_note(100);

        let mut trailing = good.clone();
        trailing.extend_from_slice(b"junk");
        assert!(matches!(
            validate_wav(&trailing),
            Err(MediaError::InvalidAudio)
        ));

        let mut riff_too_big = good.clone();
        riff_too_big[4..8].copy_from_slice(&(good.len() as u32).to_le_bytes());
        assert!(matches!(
            validate_wav(&riff_too_big),
            Err(MediaError::InvalidAudio)
        ));

        let mut data_overruns = good.clone();
        let data_size_at = 12 + 8 + 16 + 4;
        data_overruns[data_size_at..data_size_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            validate_wav(&data_overruns),
            Err(MediaError::InvalidAudio)
        ));

        let partial_frame = riff(&[
            chunk(b"fmt ", &pcm_fmt(2, 24_000, 16)),
            chunk(b"data", &[0u8; 6]),
        ]);
        assert!(matches!(
            validate_wav(&partial_frame),
            Err(MediaError::InvalidAudio)
        ));

        let empty = voice_note(0);
        assert!(matches!(
            validate_wav(&empty),
            Err(MediaError::InvalidAudio)
        ));

        let wrong_fact = riff(&[
            chunk(b"fmt ", &pcm_fmt(1, 24_000, 16)),
            chunk(b"fact", &99u32.to_le_bytes()),
            chunk(b"data", &[0u8; 200]),
        ]);
        assert!(matches!(
            validate_wav(&wrong_fact),
            Err(MediaError::InvalidAudio)
        ));

        let no_fmt = riff(&[chunk(b"data", &[0u8; 4])]);
        assert!(matches!(
            validate_wav(&no_fmt),
            Err(MediaError::InvalidAudio)
        ));

        let truncated = &good[..good.len() - 1];
        assert!(validate_wav(truncated).is_err());
    }

    #[test]
    fn non_pcm_or_unsupported_formats_are_rejected() {
        let data = chunk(b"data", &[0u8; 96]);
        let cases = [
            pcm_fmt(1, 24_000, 8),
            pcm_fmt(1, 24_000, 24),
            pcm_fmt(3, 24_000, 16),
            pcm_fmt(1, 96_000, 16),
            pcm_fmt(1, 4_000, 16),
            {
                let mut float = pcm_fmt(1, 24_000, 16);
                float[0..2].copy_from_slice(&3u16.to_le_bytes()); // IEEE float
                float
            },
            {
                let mut bad_rate = pcm_fmt(1, 24_000, 16);
                bad_rate[8..12].copy_from_slice(&1u32.to_le_bytes());
                bad_rate
            },
            {
                let mut ext = pcm_fmt(1, 24_000, 16);
                ext[0..2].copy_from_slice(&WAVE_FORMAT_EXTENSIBLE.to_le_bytes());
                ext.extend_from_slice(&22u16.to_le_bytes());
                ext.extend_from_slice(&16u16.to_le_bytes());
                ext.extend_from_slice(&0u32.to_le_bytes());
                let mut float_guid = PCM_SUBFORMAT;
                float_guid[0] = 0x03;
                ext.extend_from_slice(&float_guid);
                ext
            },
        ];
        for fmt in cases {
            let wav = riff(&[chunk(b"fmt ", &fmt), data.clone()]);
            assert!(
                matches!(validate_wav(&wav), Err(MediaError::InvalidAudio)),
                "{fmt:?}"
            );
        }
    }

    #[test]
    fn over_five_minutes_is_rejected() {
        let at_limit = voice_note(24_000 * 300);
        assert!(validate_wav(&at_limit).is_ok());
        let over = voice_note(24_000 * 300 + 1);
        assert!(matches!(
            validate_wav(&over),
            Err(MediaError::DurationTooLong)
        ));
    }
}
