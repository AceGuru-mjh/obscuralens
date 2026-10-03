"""
LSB steganography and anomaly analysis for images (EXPERIMENTAL).

Pure-standard-library implementation of the classic spatial-domain
steganalysis toolkit:

* PNG  - full chunk walk, IDAT re-inflation and a correct scanline
  unfilter (None/Sub/Up/Average/Paeth) followed by per-channel LSB bit
  plane statistics for planes 0-3 (run lengths, chi-square pair tests,
  entropy) and a weighted 0-100 suspicion score per plane.
* BMP  - 24/32-bit bottom-up pixel walk honoring the 4-byte row padding,
  same statistics.
* GIF  - a complete LZW decoder (clear-code aware) so palette index LSBs
  can be analyzed per frame.
* Every format - byte entropy profiling (Shannon histogram + 64 sliding
  windows + high-entropy blob detection) and signature carving for
  embedded ZIP / RAR / 7z / PDF / JPEG / PNG / gzip / ELF / PE / SQLite /
  RIFF blobs plus trailing-data-after-IEND/EOI detection.

Privacy framing: all analysis runs locally, nothing leaves your machine.
Steganography detection is exactly the kind of task people otherwise paste
into random online "stego detector" sites - which is a great way to leak
the very evidence you are investigating. This module never touches the
network and returns plain dicts for the caller to render.

Robustness contract: these functions NEVER raise on malformed or truncated
user-supplied bytes; corrupt containers yield ``{'error': ...}`` plus
partial results. Only programming errors raise.

JPEG note: DCT-domain stego (jsteg / F5 / outguess class) is out of scope;
for JPEG this module still runs entropy, carving and trailing-data checks.
"""

import binascii
import math
import os
import re
import struct
import zlib
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    'analyze_png',
    'analyze_bmp',
    'analyze_gif',
    'entropy_profile',
    'embedded_files_scan',
    'analyze',
    'SUSPICION_WEIGHTS',
]

# ---------------------------------------------------------------------------
# Scoring rubric (exported so the verdict is auditable / tweakable)
# ---------------------------------------------------------------------------

SUSPICION_WEIGHTS: Dict[str, Any] = {
    # Per-bit-plane rubric (0-100 before the confidence ramp):
    'chi_square_nonuniform': 35.0,
    'run_length_anomaly': 25.0,
    'entropy_deviation': 20.0,
    'plane_randomness_mismatch': 10.0,
    'flat_plane_score': 5.0,
    'confidence_ramp_bits': 65536,
    # Overall verdict thresholds on the 0-100 suspicion score:
    'verdict_clean_below': 35,
    'verdict_suspicious_below': 65,
    # One-shot analyze() bonuses (added to the LSB score, capped at 100):
    'trailing_data_bonus': 40,
    'embedded_file_bonus': 50,
    'high_entropy_region_bonus': 20,
}

_MAX_STREAM_BYTES = 300000       # per-channel cap for plane statistics
_MAX_UNFILTER_BYTES = 4000000    # cap on PNG scanline reconstruction
_MAX_GIF_INDICES = 900000        # cap on decoded GIF palette indices
_HIGH_ENTROPY_THRESHOLD = 7.2    # bits/byte for embedded-blob detection
_ASCII_STRING_RE = re.compile(rb'[\x20-\x7e]{8,}')

_PNG_CHANNELS: Dict[int, int] = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
_CHANNEL_NAMES: Dict[int, List[str]] = {1: ['gray'], 2: ['gray', 'alpha'],
                                        3: ['r', 'g', 'b'],
                                        4: ['r', 'g', 'b', 'a']}


# ---------------------------------------------------------------------------
# Math helpers (chi-square survival function without scipy)
# ---------------------------------------------------------------------------

def _clamp(value: float, low: float, high: float) -> float:
    """Clamp ``value`` into [low, high]."""
    return max(low, min(high, value))


def _binary_entropy(ratio: float) -> float:
    """Shannon entropy (bits) of a binary source with ones-ratio ``ratio``."""
    if ratio <= 0.0 or ratio >= 1.0:
        return 0.0
    return -(ratio * math.log2(ratio) + (1.0 - ratio) * math.log2(1.0 - ratio))


def _shannon_entropy(counts: List[int], total: int) -> float:
    """Shannon entropy (bits/byte, 0..8) of a 256-bin histogram."""
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / total
            entropy -= probability * math.log2(probability)
    return entropy


def _gamma_p_series(a: float, x: float) -> float:
    """Regularized lower incomplete gamma P(a, x) via the power series."""
    ap = a
    total = 1.0 / a
    delta = total
    for _ in range(512):
        ap += 1.0
        delta *= x / ap
        total += delta
        if abs(delta) < abs(total) * 1e-15:
            break
    return total * math.exp(-x + a * math.log(x) - math.lgamma(a))


def _gamma_q_contfrac(a: float, x: float) -> float:
    """Regularized upper incomplete gamma Q(a, x) via Lentz's continued fraction."""
    tiny = 1e-300
    b = x + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for i in range(1, 512):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-15:
            break
    return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h


def _gamma_q(a: float, x: float) -> float:
    """Regularized upper incomplete gamma Q(a, x) = Gamma(a, x) / Gamma(a)."""
    if a <= 0.0 or x < 0.0:
        return 1.0
    if x == 0.0:
        return 1.0
    if x < a + 1.0:
        return 1.0 - _gamma_p_series(a, x)
    return _gamma_q_contfrac(a, x)


def _chi2_sf(statistic: float, df: int) -> float:
    """Chi-square survival function P(X >= statistic) with ``df`` degrees of freedom."""
    if df <= 0 or statistic <= 0.0:
        return 1.0
    return _clamp(_gamma_q(df / 2.0, statistic / 2.0), 0.0, 1.0)


# ---------------------------------------------------------------------------
# Core bit-plane statistics
# ---------------------------------------------------------------------------

def _pair_stats(hist: List[int]) -> Dict[str, Any]:
    """
    Chi-square uniformity test over the 256 plane-pair byte patterns.

    Each group of 4 consecutive samples contributes one pattern byte whose
    low nibble packs plane-p bits and whose high nibble packs plane-(p+1)
    bits - the classic Westfeld/Pfitzmann-style pair statistic marker for
    sequential LSB embedding.
    """
    total = sum(hist)
    if total < 64:
        return {'samples': total, 'chi2': 0.0, 'p_value': 1.0, 'entropy_bits': 0.0,
                'note': 'too few samples for a chi-square test'}
    expected = total / 256.0
    statistic = 0.0
    for count in hist:
        statistic += (count - expected) ** 2 / expected
    p_value = _chi2_sf(statistic, 255)
    return {
        'samples': total,
        'chi2': round(statistic, 2),
        'p_value': round(p_value, 6),
        'entropy_bits': round(_shannon_entropy(hist, total), 4),
        'note': ('pattern distribution close to uniform (noise-like)'
                 if p_value > 0.05 else 'pattern distribution deviates from uniform'),
    }


def _bit_plane_pass(stream: bytes,
                    max_bytes: int = _MAX_STREAM_BYTES) -> Dict[str, Any]:
    """
    One pass over a byte stream collecting bit plane 0..3 statistics.

    Per plane: ones ratio, entropy, run lengths. Also accumulates the raw
    256-bin pattern histograms for plane pairs (0,1) and (2,3) so callers
    can pool several channels before the chi-square test.
    """
    limit = min(len(stream), max_bytes)
    ones = [0, 0, 0, 0]
    max_run = [0, 0, 0, 0]
    cur_run = [0, 0, 0, 0]
    cur_bit = [-1, -1, -1, -1]
    run_starts = [0, 0, 0, 0]
    pair_hists = ([0] * 256, [0] * 256)
    acc_lo = [0, 0]
    acc_hi = [0, 0]
    quad = 0
    for value in stream[:limit]:
        for k in range(4):
            bit = (value >> k) & 1
            ones[k] += bit
            if bit != cur_bit[k]:
                if cur_run[k] > max_run[k]:
                    max_run[k] = cur_run[k]
                cur_bit[k] = bit
                cur_run[k] = 1
                run_starts[k] += 1
            else:
                cur_run[k] += 1
        acc_lo[0] |= (value & 1) << quad
        acc_hi[0] |= ((value >> 1) & 1) << quad
        acc_lo[1] |= ((value >> 2) & 1) << quad
        acc_hi[1] |= ((value >> 3) & 1) << quad
        quad += 1
        if quad == 4:
            pair_hists[0][acc_lo[0] | (acc_hi[0] << 4)] += 1
            pair_hists[1][acc_lo[1] | (acc_hi[1] << 4)] += 1
            acc_lo[0] = 0
            acc_hi[0] = 0
            acc_lo[1] = 0
            acc_hi[1] = 0
            quad = 0
    for k in range(4):
        if cur_run[k] > max_run[k]:
            max_run[k] = cur_run[k]
    planes: Dict[int, Dict[str, Any]] = {}
    for k in range(4):
        if limit == 0:
            planes[k] = {'bits': 0, 'ones_ratio': 0.0, 'entropy_bits': 0.0,
                         'mean_run_length': 0.0, 'max_run_length': 0, 'flat': True}
            continue
        ratio = ones[k] / limit
        planes[k] = {
            'bits': limit,
            'ones_ratio': round(ratio, 4),
            'entropy_bits': round(_binary_entropy(ratio), 4),
            'mean_run_length': round(limit / max(run_starts[k], 1), 2),
            'max_run_length': max_run[k],
            'flat': ones[k] == 0 or ones[k] == limit,
        }
    return {'planes': planes, 'pair_hists': pair_hists, 'analyzed_bytes': limit,
            'truncated': len(stream) > max_bytes}


def _plane_suspicion(entropy: float, max_run: int, bits: int, pair: Dict[str, Any],
                     flat: bool, mismatch: float) -> Tuple[float, str]:
    """
    Weighted 0-100 suspicion score for one bit plane (see SUSPICION_WEIGHTS).

    Low chi-square p-value (structured pair patterns), long runs of
    identical bits, entropy deviating from 1.0 bit and LSB planes that are
    flatter than the upper planes all add suspicion. Essentially constant
    planes score low: no LSB payload can fit in a plane that never changes.
    """
    if flat:
        return (SUSPICION_WEIGHTS['flat_plane_score'],
                'flat bit plane (constant value) - no LSB payload can hide here; '
                'typical of synthetic or solid-color images')
    log_n = math.log2(max(bits, 2))
    run_ratio = max_run / max(log_n, 1.0)
    run_anomaly = _clamp((run_ratio - 2.0) / 8.0, 0.0, 1.0)
    chi_term = SUSPICION_WEIGHTS['chi_square_nonuniform'] * (1.0 - pair['p_value'])
    entropy_term = SUSPICION_WEIGHTS['entropy_deviation'] * abs(entropy - 1.0)
    run_term = SUSPICION_WEIGHTS['run_length_anomaly'] * run_anomaly
    mismatch_term = SUSPICION_WEIGHTS['plane_randomness_mismatch'] * _clamp(mismatch, 0.0, 1.0)
    confidence = _clamp(bits / SUSPICION_WEIGHTS['confidence_ramp_bits'], 0.0, 1.0)
    score = _clamp(chi_term + entropy_term + run_term + mismatch_term, 0.0, 100.0) * confidence
    character = 'noise-like' if entropy >= 0.9 and run_anomaly < 0.25 else 'structured'
    note = (f'{character}: entropy {entropy:.2f} bits, max run {max_run} '
            f'(random expectation ~{log_n:.0f}), pair chi-square p={pair["p_value"]:.3g}')
    if confidence < 0.5:
        note += '; few samples - statistics unreliable'
    return score, note


def _lsb_analysis(streams: Dict[str, bytes], mode: str) -> Dict[str, Any]:
    """
    Aggregate per-channel bit-plane statistics into the shared report shape.

    ``streams`` maps channel names ('r'/'g'/'b'/'a'/'gray'/'palette') to
    their sample byte streams. Returns per-plane aggregates with per-channel
    detail, pooled chi-square pair tests, per-plane suspicion scores, an
    overall suspicion value, a verdict and human-readable reasons.
    """
    per_channel: Dict[str, Dict[str, Any]] = {}
    pooled = ([0] * 256, [0] * 256)
    for name, stream in streams.items():
        stats = _bit_plane_pass(stream)
        per_channel[name] = stats
        for p in range(2):
            hist = stats['pair_hists'][p]
            for index in range(256):
                pooled[p][index] += hist[index]
    channel_names = list(per_channel.keys())
    planes_out: Dict[str, Dict[str, Any]] = {}
    reasons: List[str] = []
    entropies = [0.0, 0.0, 0.0, 0.0]
    aggregates: List[Dict[str, Any]] = []
    for k in range(4):
        entries = [per_channel[name]['planes'][k] for name in channel_names]
        total_bits = sum(entry['bits'] for entry in entries)
        if total_bits == 0:
            continue
        ratio = sum(entry['ones_ratio'] * entry['bits'] for entry in entries) / total_bits
        entropy = sum(entry['entropy_bits'] * entry['bits'] for entry in entries) / total_bits
        mean_run = sum(entry['mean_run_length'] for entry in entries) / len(entries)
        max_run = max(entry['max_run_length'] for entry in entries)
        flat = all(entry['flat'] for entry in entries)
        entropies[k] = entropy
        aggregates.append({'plane': k, 'bits': total_bits, 'ones_ratio': ratio,
                           'entropy': entropy, 'mean_run': mean_run, 'max_run': max_run,
                           'flat': flat})
    # LSB planes should be at least as random as bit-2/3 planes in a photo.
    high_entropy = max(entropies[2], entropies[3])
    low_entropy = min(entropies[0], entropies[1])
    mismatch = high_entropy - low_entropy if aggregates else 0.0
    for agg in aggregates:
        k = agg['plane']
        pair = _pair_stats(pooled[0] if k <= 1 else pooled[1])
        score, note = _plane_suspicion(agg['entropy'], agg['max_run'], agg['bits'],
                                       pair, agg['flat'],
                                       mismatch if k <= 1 else 0.0)
        detail: Dict[str, Any] = {}
        for name in channel_names:
            entry = per_channel[name]['planes'][k]
            channel_pair = _pair_stats(per_channel[name]['pair_hists'][0] if k <= 1
                                       else per_channel[name]['pair_hists'][1])
            channel_score, _note = _plane_suspicion(
                entry['entropy_bits'], entry['max_run_length'], entry['bits'],
                channel_pair, entry['flat'], 0.0)
            detail[name] = {'suspicion': round(channel_score, 1),
                            'entropy_bits': entry['entropy_bits'],
                            'max_run_length': entry['max_run_length']}
        planes_out[str(k)] = {
            'bits': agg['bits'],
            'ones_ratio': round(agg['ones_ratio'], 4),
            'entropy_bits': round(agg['entropy'], 4),
            'mean_run_length': round(agg['mean_run'], 2),
            'max_run_length': agg['max_run'],
            'flat': agg['flat'],
            'suspicion': round(score, 1),
            'note': note,
            'per_channel': detail,
        }
        if score >= 20 or agg['flat']:
            reasons.append(f'plane {k}: {note}')
    overall = max((plane['suspicion'] for plane in planes_out.values()), default=0.0)
    if overall < SUSPICION_WEIGHTS['verdict_clean_below']:
        verdict = 'clean'
    elif overall < SUSPICION_WEIGHTS['verdict_suspicious_below']:
        verdict = 'suspicious'
    else:
        verdict = 'highly suspicious'
    if not reasons:
        reasons.append('all bit planes look noise-like; no LSB anomalies detected')
    if mismatch > 0.15:
        reasons.append(f'plane randomness mismatch: LSB planes (H={low_entropy:.2f}) are '
                       f'flatter than bit-2/3 planes (H={high_entropy:.2f})')
    return {
        'analysis_mode': mode,
        'channels': channel_names,
        'planes': planes_out,
        'chi_square': {'pair_0_1': _pair_stats(pooled[0]),
                       'pair_2_3': _pair_stats(pooled[1])},
        'suspicion': round(overall, 1),
        'verdict': verdict,
        'reasons': reasons,
    }


# ---------------------------------------------------------------------------
# PNG: chunk walk + scanline reconstruction
# ---------------------------------------------------------------------------

def _png_chunk_walk(data: bytes) -> Tuple[List[Tuple[str, bytes]], int, List[str]]:
    """
    Walk PNG chunks (independent of exif_reader; modules stay decoupled).

    Returns (chunks, trailing_bytes_after_IEND, notes). Malformed length
    fields stop the walk gracefully.
    """
    chunks: List[Tuple[str, bytes]] = []
    notes: List[str] = []
    pos = 8
    while pos + 8 <= len(data):
        length = struct.unpack_from('>I', data, pos)[0]
        ctype = data[pos + 4:pos + 8]
        if pos + 12 + length > len(data):
            notes.append(f'chunk {ctype!r} at offset {pos} truncated')
            break
        chunks.append((ctype.decode('latin-1', errors='replace'),
                       data[pos + 8:pos + 8 + length]))
        pos += 12 + length
        if ctype == b'IEND':
            if pos < len(data):
                notes.append(f'{len(data) - pos} bytes after IEND')
            return chunks, len(data) - pos, notes
    notes.append('IEND chunk not found')
    return chunks, 0, notes


def _paeth_predictor(a: int, b: int, c: int) -> int:
    """PNG spec Paeth predictor (ties prefer a, then b, then c)."""
    p = a + b - c
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def _unfilter_png(raw: bytes, width: int, height: int, channels: int,
                  bit_depth: int) -> Tuple[Optional[bytes], List[str]]:
    """
    Reverse PNG scanline filtering (types 0-4) per the PNG specification.

    ``bpp`` (filter unit) is ceil(bit_depth * channels / 8) with a floor of
    one byte, exactly as the spec demands for sub-byte depths. Returns
    (pixels, notes); None pixels means reconstruction was impossible.
    """
    notes: List[str] = []
    bpp = max(1, channels * (bit_depth // 8)) if bit_depth >= 8 else 1
    stride = (width * channels * bit_depth + 7) // 8
    if stride <= 0:
        return None, ['degenerate image dimensions']
    expected = height * (stride + 1)
    if len(raw) < expected:
        height = len(raw) // (stride + 1)
        notes.append(f'short IDAT stream: expected {expected} bytes, got {len(raw)}; '
                     f'reconstructing {height} of the declared rows')
    if height <= 0:
        return None, ['no complete scanline in the decompressed data']
    if height * stride > _MAX_UNFILTER_BYTES:
        capped_rows = _MAX_UNFILTER_BYTES // stride
        notes.append(f'reconstruction capped to the first {capped_rows} of {height} rows')
        height = capped_rows
    pixels = bytearray(height * stride)
    prev_start = 0
    pos = 0
    for row in range(height):
        filter_type = raw[pos]
        pos += 1
        row_start = row * stride
        if filter_type == 0:  # None: raw copy
            pixels[row_start:row_start + stride] = raw[pos:pos + stride]
            pos += stride
        elif filter_type <= 4:
            for i in range(stride):
                value = raw[pos]
                pos += 1
                left = pixels[row_start + i - bpp] if i >= bpp else 0
                up = pixels[prev_start + i] if row else 0
                up_left = pixels[prev_start + i - bpp] if row and i >= bpp else 0
                if filter_type == 1:  # Sub
                    recon = value + left
                elif filter_type == 2:  # Up
                    recon = value + up
                elif filter_type == 3:  # Average
                    recon = value + ((left + up) >> 1)
                else:  # Paeth
                    recon = value + _paeth_predictor(left, up, up_left)
                pixels[row_start + i] = recon & 0xFF
        else:
            notes.append(f'unknown filter type {filter_type} in row {row}')
            return None, notes
        prev_start = row_start
    return bytes(pixels), notes


def analyze_png(data: bytes) -> Dict[str, Any]:
    """
    Full LSB-plane analysis of a PNG image (pure stdlib, runs locally).

    Walks chunks, re-inflates IDAT, reconstructs scanlines for all five
    filter types, then scores bit planes 0-3 per channel. Palette images
    analyze palette-index LSBs (noted in the output); 16-bit images analyze
    the high byte of each sample (noted); interlaced images fall back to
    raw decompressed bytes with a caveat note.
    """
    result: Dict[str, Any] = {'format': 'png'}
    if not isinstance(data, (bytes, bytearray)) or len(data) < 16 \
            or data[:8] != b'\x89PNG\r\n\x1a\n':
        return {'format': 'png', 'error': 'not a PNG image', 'parsed': result}
    chunks, trailing, notes = _png_chunk_walk(data)
    result['chunk_count'] = len(chunks)
    if trailing:
        result['trailing_after_iend'] = trailing
    ihdr = next((payload for ctype, payload in chunks if ctype == 'IHDR'), None)
    if ihdr is None or len(ihdr) < 13:
        result['error'] = 'missing or truncated IHDR chunk'
        result['notes'] = notes
        return result
    width, height, depth, color, _compression, _filter, interlace = \
        struct.unpack('>IIBBBBB', ihdr[:13])
    result.update({'width': width, 'height': height, 'bit_depth': depth,
                   'color_type': color})
    idat = b''.join(payload for ctype, payload in chunks if ctype == 'IDAT')
    if not idat:
        result['error'] = 'no IDAT data'
        result['notes'] = notes
        return result
    try:
        raw = zlib.decompress(idat)
    except zlib.error as exc:
        result['error'] = f'IDAT decompression failed: {exc}'
        result['notes'] = notes
        return result
    result['idat_bytes'] = len(idat)
    result['decompressed_bytes'] = len(raw)
    channels = _PNG_CHANNELS.get(color, 1)
    result['channels'] = channels
    mode_notes: List[str] = list(notes)
    if interlace:
        mode_notes.append('Adam7-interlaced image: scanline reconstruction skipped; '
                          'analyzing raw decompressed bytes (filter bytes included)')
        pixels = raw
        expected = None
    else:
        pixels, unfilter_notes = _unfilter_png(raw, width, height, channels, depth)
        mode_notes.extend(unfilter_notes)
        expected = height * ((width * channels * depth + 7) // 8)
        if pixels is None:
            result['error'] = 'scanline reconstruction failed'
            result['notes'] = mode_notes
            return result
        result['pixel_bytes'] = len(pixels)
        if expected is not None:
            result['pixel_count_ok'] = len(pixels) == expected
            if not result['pixel_count_ok']:
                mode_notes.append(f'pixel bytes {len(pixels)} != expected {expected}')
    streams: Dict[str, bytes] = {}
    if depth == 16:
        mode_notes.append('16-bit image: analyzing the high byte of each sample')
        pixels = pixels[1::2]
    elif depth < 8:
        mode_notes.append(f'bit-packed {depth}-bit samples: analyzing packed bytes '
                          '(sub-byte boundaries are not expanded)')
    if color == 3:
        mode_notes.append('palette image: LSB of palette indices analyzed (index '
                          'swaps are what an embedding tool would flip)')
        streams['palette'] = pixels
    elif channels == 1:
        streams['gray'] = pixels
    else:
        names = _CHANNEL_NAMES.get(channels, [f'c{i}' for i in range(channels)])
        for index, name in enumerate(names):
            streams[name] = pixels[index::channels]
    mode = 'per-channel bit planes' if not interlace else 'raw interlaced bytes'
    if color == 3:
        mode = 'palette-index LSB'
    analysis = _lsb_analysis(streams, mode)
    result.update(analysis)
    result['notes'] = mode_notes
    return result


# ---------------------------------------------------------------------------
# BMP analysis
# ---------------------------------------------------------------------------

def analyze_bmp(data: bytes) -> Dict[str, Any]:
    """
    LSB analysis of 24/32-bit BMP pixel data (bottom-up rows, 4-byte padding).

    Row padding bytes are excluded from the channel statistics but their
    presence with non-zero content is reported - padding is a classic spot
    for smuggling raw payload bytes.
    """
    result: Dict[str, Any] = {'format': 'bmp'}
    if not isinstance(data, (bytes, bytearray)) or len(data) < 54 or data[:2] != b'BM':
        return {'format': 'bmp', 'error': 'not a BMP image', 'parsed': result}
    pixel_offset = struct.unpack_from('<I', data, 10)[0]
    width, height = struct.unpack_from('<ii', data, 18)
    bpp = struct.unpack_from('<H', data, 28)[0]
    compression = struct.unpack_from('<I', data, 30)[0] if len(data) >= 34 else 0
    if not (0 < abs(width) <= 50000 and 0 < abs(height) <= 50000):
        core_width, core_height = struct.unpack_from('<HH', data, 18)
        if 0 < core_width <= 50000 and 0 < core_height <= 50000:
            width, height = core_width, core_height
            result['notes'] = ['declared DIB size disagrees with the stored '
                               'dimensions (core-style u16) - salvaged']
    if not (0 < abs(width) <= 50000 and 0 < abs(height) <= 50000):
        return {'format': 'bmp', 'error': f'implausible dimensions {width}x{height}',
                'parsed': result}
    if compression not in (0, 3):
        return {'format': 'bmp',
                'error': f'compressed BMP (method {compression}) not supported',
                'parsed': result}
    result.update({'width': width, 'height': height, 'bpp': bpp,
                   'bottom_up': height > 0, 'compression': compression})
    if bpp not in (8, 24, 32):
        return {'format': 'bmp', 'error': f'{bpp}-bpp BMP not supported '
                f'(24/32-bit RGB and 8-bit palette supported)', 'parsed': result}
    row_size = ((abs(width) * bpp + 31) // 32) * 4
    pixel_bytes = row_size - abs(width) * (bpp // 8)
    rows = abs(height)
    result['row_size'] = row_size
    result['padding_bytes_per_row'] = pixel_bytes
    if pixel_offset + row_size * rows > len(data):
        rows = max(0, (len(data) - pixel_offset) // row_size)
        result['notes'] = result.get('notes', []) + [
            f'pixel data truncated: {rows} of {abs(height)} rows readable']
    if rows == 0:
        result.setdefault('notes', []).append('no pixel rows available')
        return result
    notes: List[str] = list(result.get('notes', []))
    if bpp == 8:
        # Palette indices: LSB of the index stream.
        indices = bytearray()
        for row in range(rows):
            start = pixel_offset + row * row_size
            indices += data[start:start + abs(width)]
        notes.append('8-bit palette BMP: LSB of palette indices analyzed')
        analysis = _lsb_analysis({'palette': bytes(indices[:_MAX_GIF_INDICES])},
                                 'palette-index LSB')
        result.update(analysis)
        result['notes'] = notes
        return result
    channels = bpp // 8
    streams: Dict[str, bytes] = {name: bytearray() for name in
                                 _CHANNEL_NAMES.get(channels, ['gray'])[:channels]}
    names = _CHANNEL_NAMES[channels]
    nonzero_padding = 0
    for row in range(rows):
        start = pixel_offset + row * row_size
        line = data[start:start + abs(width) * channels]
        for index, name in enumerate(names):
            streams[name] += line[index::channels]
        padding = data[start + abs(width) * channels:start + row_size]
        if padding.strip(b'\x00'):
            nonzero_padding += 1
    if nonzero_padding:
        notes.append(f'{nonzero_padding} row(s) have non-zero padding bytes - '
                     'possible payload smuggled in row padding')
    capped = {name: bytes(stream[:_MAX_STREAM_BYTES * 3]) for name, stream in streams.items()}
    analysis = _lsb_analysis(capped, 'per-channel bit planes (BGR(A) order)')
    result.update(analysis)
    result['notes'] = notes
    return result


# ---------------------------------------------------------------------------
# GIF: LZW decoder + frame analysis
# ---------------------------------------------------------------------------

def _gif_lzw_decode(min_code_size: int, payload: bytes,
                    max_output: int = _MAX_GIF_INDICES) -> Tuple[bytes, bool]:
    """
    GIF LZW decoder (variable code width, clear-code aware).

    Returns (indices, ok). ``ok`` is False when the stream hit an invalid
    code; the indices decoded up to that point are still returned so
    partial-frame analysis remains possible.
    """
    if not 2 <= min_code_size <= 11:
        return b'', False
    clear_code = 1 << min_code_size
    end_code = clear_code + 1
    table = [bytes([index]) for index in range(clear_code)] + [b'', b'']
    code_size = min_code_size + 1
    previous: Optional[bytes] = None
    out = bytearray()
    bit_buffer = 0
    bit_count = 0
    pos = 0
    ok = True
    while True:
        while bit_count < code_size and pos < len(payload):
            bit_buffer |= payload[pos] << bit_count
            bit_count += 8
            pos += 1
        if bit_count < code_size:
            break  # ran out of data: treat as end of stream
        code = bit_buffer & ((1 << code_size) - 1)
        bit_buffer >>= code_size
        bit_count -= code_size
        if code == clear_code:
            table = [bytes([index]) for index in range(clear_code)] + [b'', b'']
            code_size = min_code_size + 1
            previous = None
            continue
        if code == end_code:
            break
        if code < len(table) and table[code]:
            entry = table[code]
        elif code == len(table) and previous is not None:
            entry = previous + previous[:1]  # KwKwK case
        else:
            ok = False
            break
        out += entry
        if previous is not None and len(table) < 4096:
            table.append(previous + entry[:1])
            # The decoder table trails the encoder table by one entry, so the
            # code width must grow one code earlier than a naive count suggests.
            if len(table) == (1 << code_size) - 1 and code_size < 12:
                code_size += 1
        previous = entry
        if len(out) >= max_output:
            break
    return bytes(out), ok


def _gif_walk(data: bytes) -> Tuple[List[Tuple[int, bytes]], Dict[str, Any], List[str]]:
    """
    Walk GIF blocks collecting (min_code_size, lzw_payload) per frame.

    Returns (frames, screen_info, notes). Tolerates truncated streams.
    """
    info: Dict[str, Any] = {}
    notes: List[str] = []
    frames: List[Tuple[int, bytes]] = []
    if len(data) < 13:
        notes.append('truncated GIF header')
        return frames, info, notes
    width, height = struct.unpack_from('<HH', data, 6)
    packed = data[10]
    info.update({'width': width, 'height': height,
                 'global_color_table': bool(packed & 0x80),
                 'global_color_table_size': 3 * (2 ** ((packed & 0x07) + 1))
                 if packed & 0x80 else 0})
    pos = 13 + (info['global_color_table_size'] if packed & 0x80 else 0)
    while pos < len(data):
        block = data[pos]
        if block == 0x3B:
            pos += 1
            break
        if block == 0x21 and pos + 1 < len(data):
            label = data[pos + 1]
            pos += 2
            if label == 0xFF and pos < len(data):
                app_size = data[pos]
                app_id = data[pos + 1:pos + 1 + app_size]
                pos += 1 + app_size
                while pos < len(data) and data[pos]:
                    sub_len = data[pos]
                    if app_id[:11] == b'NETSCAPE2.0' and sub_len >= 3 and data[pos + 1] == 1:
                        info['loop_count'] = struct.unpack_from('<H', data, pos + 2)[0]
                    pos += 1 + sub_len
            else:
                while pos < len(data) and data[pos]:
                    pos += 1 + data[pos]
        elif block == 0x2C and pos + 10 <= len(data):
            image_packed = data[pos + 8]
            pos += 10
            if image_packed & 0x80:
                pos += 3 * (2 ** ((image_packed & 0x07) + 1))
            if pos >= len(data):
                notes.append('image descriptor truncated before LZW data')
                break
            min_code_size = data[pos]
            pos += 1
            payload = bytearray()
            while pos < len(data) and data[pos]:
                sub_len = data[pos]
                payload += data[pos + 1:pos + 1 + sub_len]
                pos += 1 + sub_len
            frames.append((min_code_size, bytes(payload)))
        else:
            notes.append(f'unexpected block byte 0x{block:02X} at offset {pos}')
            break
    if pos < len(data):
        info['trailing_after_trailer'] = len(data) - pos
    return frames, info, notes


def analyze_gif(data: bytes) -> Dict[str, Any]:
    """
    LSB analysis of GIF palette indices across all frames.

    A full LZW decoder recovers the index stream per frame; the LSBs of
    those indices are then scored exactly like PNG/BMP channels. If a frame
    fails to decode, the failure is noted and the remaining frames are
    still analyzed.
    """
    result: Dict[str, Any] = {'format': 'gif'}
    if not isinstance(data, (bytes, bytearray)) or len(data) < 13 \
            or data[:6] not in (b'GIF87a', b'GIF89a'):
        return {'format': 'gif', 'error': 'not a GIF image', 'parsed': result}
    frames, info, notes = _gif_walk(data)
    result.update(info)
    result['frame_count'] = len(frames)
    if not frames:
        result['error'] = 'no image frames found'
        result['notes'] = notes
        return result
    indices = bytearray()
    decoded_frames = 0
    for min_code_size, payload in frames:
        decoded, ok = _gif_lzw_decode(min_code_size, payload)
        if ok or decoded:
            decoded_frames += 1
        if not ok:
            notes.append('a frame failed LZW decode (invalid code); '
                         'partial indices retained')
        indices += decoded
        if len(indices) >= _MAX_GIF_INDICES:
            notes.append(f'index analysis capped at {_MAX_GIF_INDICES} bytes')
            break
    result['decoded_frames'] = decoded_frames
    result['index_bytes'] = len(indices)
    if not indices:
        result['error'] = 'LZW decoding produced no index data'
        result['notes'] = notes
        return result
    notes.append('palette image: LSB of palette indices analyzed per frame')
    analysis = _lsb_analysis({'palette': bytes(indices[:_MAX_GIF_INDICES])},
                             'palette-index LSB (all frames)')
    result.update(analysis)
    result['notes'] = notes
    return result


# ---------------------------------------------------------------------------
# Entropy profiling
# ---------------------------------------------------------------------------

def entropy_profile(data: bytes) -> Dict[str, Any]:
    """
    Byte-entropy profile: 256-bin Shannon histogram, 64 sliding windows and
    high-entropy region detection (> 7.2 bits/byte windows merged into
    regions - the signature of an embedded encrypted or compressed blob).
    """
    if not isinstance(data, (bytes, bytearray)) or not data:
        return {'error': 'no data'}
    buffer = bytes(data)
    capped = len(buffer) > 2097152
    sample = buffer[:2097152] if capped else buffer
    histogram = [0] * 256
    for value in sample:
        histogram[value] += 1
    overall = _shannon_entropy(histogram, len(sample))
    windows: List[Dict[str, Any]] = []
    window_count = 64
    step = max(1, len(sample) // window_count)
    window_size = max(64, step)
    for index in range(0, len(sample), step):
        window = sample[index:index + window_size]
        if not window:
            break
        counts = Counter(window)
        entropy = _shannon_entropy([counts.get(byte, 0) for byte in range(256)],
                                   len(window))
        windows.append({'offset': index, 'entropy_bits': round(entropy, 3)})
        if len(windows) >= window_count:
            break
    regions: List[Dict[str, Any]] = []
    run: List[Dict[str, Any]] = []
    for window in windows:
        if window['entropy_bits'] > _HIGH_ENTROPY_THRESHOLD:
            run.append(window)
        elif run:
            regions.append(run)
            run = []
    if run:
        regions.append(run)
    high_entropy = [{'offset_from': group[0]['offset'],
                     'offset_to': group[-1]['offset'] + window_size,
                     'mean_entropy': round(sum(w['entropy_bits'] for w in group) / len(group), 3),
                     'windows': len(group)} for group in regions]
    notes: List[str] = []
    if capped:
        notes.append('entropy computed over the first 2 MiB (file larger)')
    if overall < 1.0:
        notes.append('overall entropy is very low: mostly constant data '
                     '(solid-color or sparse image)')
    elif overall > 7.5:
        notes.append('overall entropy is near-maximal: compressed image payload '
                     'is expected, but combined with odd trailing data it can '
                     'also indicate encrypted content')
    if high_entropy:
        notes.append(f'{len(high_entropy)} high-entropy region(s) above '
                     f'{_HIGH_ENTROPY_THRESHOLD} bits/byte - possible embedded '
                     'encrypted/compressed blob (offsets listed)')
    return {
        'overall_entropy_bits': round(overall, 4),
        'sampled_bytes': len(sample),
        'windows': windows,
        'high_entropy_regions': high_entropy,
        'notes': notes,
    }


# ---------------------------------------------------------------------------
# Embedded file carving
# ---------------------------------------------------------------------------

def _preview(raw: bytes) -> str:
    """Hex + printable preview of the first bytes at a carve hit."""
    head = raw[:24]
    hex_part = binascii.hexlify(head).decode('ascii')
    text_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in head)
    return f'{hex_part} | {text_part}'


def _zip_inner_files(data: bytes, hit_offset: int) -> List[str]:
    """
    List inner ZIP filenames via the End Of Central Directory record.

    Tries the central directory both at its absolute offset and relative to
    the embedded archive start; returns [] when neither parses.
    """
    eocd = data.rfind(b'PK\x05\x06')
    if eocd == -1 or eocd < hit_offset:
        return []
    total_entries = struct.unpack_from('<H', data, eocd + 10)[0]
    cd_offset = struct.unpack_from('<I', data, eocd + 16)[0]
    for base in (cd_offset, hit_offset + cd_offset):
        names: List[str] = []
        pos = base
        for _ in range(min(total_entries, 50)):
            if pos + 46 > len(data) or data[pos:pos + 4] != b'PK\x01\x02':
                break
            name_len = struct.unpack_from('<H', data, pos + 28)[0]
            name = data[pos + 46:pos + 46 + name_len]
            names.append(name.decode('latin-1', errors='replace'))
            pos += 46 + name_len + struct.unpack_from('<H', data, pos + 30)[0] \
                + struct.unpack_from('<H', data, pos + 32)[0]
        if names:
            return names
    return []


def _gzip_probe(data: bytes, offset: int) -> Optional[str]:
    """Try to decompress an embedded gzip member; return a preview string."""
    try:
        output = zlib.decompressobj(31).decompress(data[offset:offset + 262144])
    except zlib.error:
        return None
    if not output:
        return None
    preview = _preview(output[:24])
    if output[257:262] == b'ustar':
        return f'{preview} (contains a tar archive)'
    return preview


def _trailing_data(data: bytes) -> Optional[Dict[str, Any]]:
    """Detect payload bytes appended after the PNG IEND / JPEG EOI marker."""
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        _chunks, trailing, _notes = _png_chunk_walk(data)
        if trailing > 0:
            return {'format': 'png', 'trailing_bytes': trailing,
                    'note': f'data after image end: {trailing} bytes - classic '
                            'payload smuggle (appended after IEND)'}
    elif data[:2] == b'\xff\xd8':
        eoi = data.rfind(b'\xff\xd9')
        if eoi != -1 and len(data) - eoi - 2 > 0:
            trailing = len(data) - eoi - 2
            return {'format': 'jpeg', 'trailing_bytes': trailing,
                    'note': f'data after image end: {trailing} bytes - classic '
                            'payload smuggle (appended after EOI)'}
    return None


def embedded_files_scan(data: bytes) -> Dict[str, Any]:
    """
    Carve known file signatures out of an image buffer.

    Looks for ZIP (with inner filename listing via the central directory),
    RAR, 7z, PDF, JPEG, PNG, gzip (decompressed preview), ELF, PE
    (validated via the PE\\0\\0 offset pointer), SQLite and RIFF headers.
    Signature hits at the very start of the file are skipped - they belong
    to the container itself, not to an embedded payload.
    """
    if not isinstance(data, (bytes, bytearray)) or not data:
        return {'error': 'no data', 'findings': [], 'notes': []}
    buffer = bytes(data)
    findings: List[Dict[str, Any]] = []
    notes: List[str] = []

    def add_hit(kind: str, offset: int, details: str = '') -> None:
        findings.append({'type': kind, 'offset': offset,
                         'preview': _preview(buffer[offset:]),
                         'details': details})

    for kind, signature in (('zip', b'PK\x03\x04'), ('rar', b'Rar!\x1a\x07'),
                            ('7z', b'7z\xbc\xaf\x27\x1c'), ('pdf', b'%PDF-'),
                            ('jpeg', b'\xff\xd8\xff'), ('png', b'\x89PNG\r\n\x1a\n'),
                            ('gzip', b'\x1f\x8b'), ('elf', b'\x7fELF'),
                            ('sqlite', b'SQLite format 3\x00'), ('riff', b'RIFF')):
        start = 0
        hits = 0
        while hits < 20:
            offset = buffer.find(signature, start)
            if offset == -1:
                break
            if offset >= 8 or (kind not in ('jpeg', 'png', 'riff')):
                if offset == 0:
                    notes.append(f'{kind} signature at offset 0 is the file header itself')
                else:
                    add_hit(kind, offset)
                    hits += 1
            start = offset + 1
    for hit in findings:
        if hit['type'] == 'zip':
            names = _zip_inner_files(buffer, hit['offset'])
            if names:
                hit['inner_files'] = names
                hit['details'] = f'{len(names)}+ inner file(s): ' + ', '.join(names[:10])
            else:
                hit['details'] = 'local file header; central directory not parseable'
        elif hit['type'] == 'gzip':
            probe = _gzip_probe(buffer, hit['offset'])
            if probe:
                hit['details'] = f'decompresses to: {probe}'
    # PE executables: 'MZ' + PE\0\0 at the e_lfanew offset.
    start = 0
    while True:
        offset = buffer.find(b'MZ', start)
        if offset == -1:
            break
        if offset + 64 <= len(buffer):
            lfanew = struct.unpack_from('<I', buffer, offset + 0x3C)[0]
            pe_at = offset + lfanew
            if 0 < lfanew < len(buffer) and buffer[pe_at:pe_at + 4] == b'PE\x00\x00':
                machine = struct.unpack_from('<H', buffer, pe_at + 4)[0]
                add_hit('pe', offset,
                        f'PE executable (machine 0x{machine:04X}, header at +{lfanew})')
        start = offset + 1
    trailing = _trailing_data(buffer)
    if trailing:
        notes.append(trailing['note'])
    return {'findings': findings, 'trailing_data': trailing, 'notes': notes}


# ---------------------------------------------------------------------------
# One-shot analysis
# ---------------------------------------------------------------------------

def _load_bytes(target: Any) -> Tuple[Optional[bytes], Optional[str]]:
    """Accept a filesystem path (str/Path) or raw bytes; return (data, error)."""
    if isinstance(target, (bytes, bytearray, memoryview)):
        return bytes(target), None
    if isinstance(target, (str, os.PathLike)):
        path = os.fspath(target)
        if not os.path.isfile(path):
            return None, f'file not found: {path}'
        try:
            with open(path, 'rb') as handle:
                return handle.read(), None
        except OSError as exc:
            return None, f'cannot read file {path}: {exc}'
    return None, f'unsupported input type: {type(target).__name__}'


def _strings_lite(data: bytes, limit: int = 60) -> List[Dict[str, Any]]:
    """Minimal ASCII string extraction (min length 8) for the one-shot report."""
    found: List[Dict[str, Any]] = []
    for match in _ASCII_STRING_RE.finditer(data):
        value = match.group().decode('ascii')
        if len(set(value)) <= 2 and len(value) > 10:
            continue  # pure-repetition noise
        found.append({'offset': match.start(), 'value': value})
        if len(found) >= limit:
            break
    return found


def analyze(path_or_bytes: Any) -> Dict[str, Any]:
    """
    One-shot local steganography triage for an image file or byte blob.

    Sniffs the format, runs the appropriate LSB analysis (PNG / BMP / GIF;
    JPEG gets entropy + carving only, with a note that DCT-domain stego is
    out of scope), then adds entropy profiling, embedded-file carving,
    trailing-data detection and a strings-lite pass. Returns
    ``{'format', 'summary': {'suspicion', 'verdict', 'findings'}, 'lsb',
    'entropy', 'embedded_files', 'strings', ...}``. Never raises on
    malformed input; nothing leaves the calling process.
    """
    data, load_error = _load_bytes(path_or_bytes)
    if load_error or not data:
        error = load_error or 'empty input'
        return {'error': error,
                'summary': {'suspicion': 0, 'verdict': 'clean',
                            'findings': [error]}}
    findings: List[str] = []
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        fmt = 'png'
        lsb = analyze_png(data)
    elif data[:2] == b'\xff\xd8':
        fmt = 'jpeg'
        lsb = {'format': 'jpeg',
               'note': 'JPEG carries no spatial LSB plane to decode: DCT-domain '
                       'steganography (jsteg/F5/outguess class) is out of scope for '
                       'this local analyzer - entropy, carving and trailing-data '
                       'checks still apply'}
        findings.append('DCT-domain steganography detection is out of scope for '
                        'JPEG; spatial analysis skipped (entropy + carving ran)')
    elif data[:6] in (b'GIF87a', b'GIF89a'):
        fmt = 'gif'
        lsb = analyze_gif(data)
    elif data[:2] == b'BM':
        fmt = 'bmp'
        lsb = analyze_bmp(data)
    else:
        fmt = 'unknown'
        lsb = {'format': 'unknown',
               'error': 'unsupported format for LSB analysis'}
        findings.append('unsupported format: only PNG, JPEG, GIF and BMP are analyzed')
    suspicion = 0.0
    if isinstance(lsb.get('suspicion'), (int, float)):
        suspicion = float(lsb['suspicion'])
    for reason in (lsb.get('reasons') or []):
        findings.append(f'LSB: {reason}')
    if lsb.get('error'):
        findings.append(f'LSB analysis incomplete: {lsb["error"]}')
    if lsb.get('note'):
        findings.append(lsb['note'])

    entropy = entropy_profile(data)
    embedded = embedded_files_scan(data)
    strings = _strings_lite(data)

    trailing = embedded.get('trailing_data')
    if trailing:
        suspicion += SUSPICION_WEIGHTS['trailing_data_bonus']
        findings.append(f'trailing data: {trailing["note"]}')
    if embedded.get('findings'):
        suspicion += SUSPICION_WEIGHTS['embedded_file_bonus']
        for hit in embedded['findings'][:10]:
            detail = f" ({hit['details']})" if hit.get('details') else ''
            findings.append(f"embedded {hit['type']} blob at offset {hit['offset']}{detail}")
    if entropy.get('high_entropy_regions'):
        suspicion += SUSPICION_WEIGHTS['high_entropy_region_bonus']
        for region in entropy['high_entropy_regions'][:5]:
            findings.append(f'high-entropy region at bytes {region["offset_from"]}-'
                            f'{region["offset_to"]} ({region["mean_entropy"]} bits/byte) '
                            '- possible embedded encrypted/compressed blob')
    for note in (entropy.get('notes') or []):
        if 'high-entropy region' not in note:
            findings.append(f'entropy: {note}')
    if strings:
        findings.append(f'{len(strings)} ASCII string(s) >= 8 chars in the raw bytes '
                         '(see "strings" list)')

    suspicion = _clamp(suspicion, 0.0, 100.0)
    if suspicion < SUSPICION_WEIGHTS['verdict_clean_below']:
        verdict = 'clean'
    elif suspicion < SUSPICION_WEIGHTS['verdict_suspicious_below']:
        verdict = 'suspicious'
    else:
        verdict = 'highly suspicious'
    return {
        'format': fmt,
        'summary': {'suspicion': round(suspicion, 1), 'verdict': verdict,
                    'findings': findings},
        'lsb': lsb,
        'entropy': entropy,
        'embedded_files': embedded,
        'strings': strings,
    }
