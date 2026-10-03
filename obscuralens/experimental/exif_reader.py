"""
Zero-dependency EXIF / metadata reader for images (EXPERIMENTAL).

Parses JPEG (APP0 JFIF, APP1 EXIF + XMP, APP2 ICC, APP13 Photoshop 8BIM,
COM comments), PNG (IHDR + tEXt/zTXt/iTXt/tIME/eXIf with CRC verification),
GIF, BMP and WebP containers straight from the byte stream using nothing
but the Python standard library - no Pillow, no exiftool, no network calls.

Privacy framing: this module is a core reason ObscuraLens can promise that
image triage "runs locally, nothing leaves your machine". EXIF blocks often
carry GPS coordinates, device serial numbers, owner names and editing
history - precisely the data you should never paste into a random online
EXIF-lookup site. Everything here is parsed in-process; the resulting dict
never leaves the caller's process unless the caller chooses to persist it.

Robustness contract: these functions NEVER raise on malformed or truncated
user-supplied bytes. Each parser returns a dict and, when a container is
corrupt, includes an ``'error'`` key alongside whatever partial fields were
recovered (``'parsed'`` style partials). Only programming errors raise.

Public API:
    read_metadata(path_or_bytes)   -> format-specific metadata dict
    strings_report(data, min_len)  -> embedded ASCII / UTF-16LE strings
    analyze(path_or_bytes)         -> one-shot OSINT-oriented report

Exported tag tables (documentation / reuse in other modules):
    EXIF_TAGS, GPS_TAGS, IFD0_TAGS
"""

import binascii
import hashlib
import os
import re
import struct
import zlib
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    'read_metadata',
    'strings_report',
    'analyze',
    'EXIF_TAGS',
    'GPS_TAGS',
    'IFD0_TAGS',
]

# ---------------------------------------------------------------------------
# Tag tables: id -> (friendly name, value kind used by _format_tag)
# ---------------------------------------------------------------------------

IFD0_TAGS: Dict[int, Tuple[str, str]] = {
    0x0100: ('ImageWidth', 'int'),
    0x0101: ('ImageLength', 'int'),
    0x0102: ('BitsPerSample', 'int'),
    0x0103: ('Compression', 'compression'),
    0x010D: ('DocumentName', 'ascii'),
    0x010E: ('ImageDescription', 'ascii'),
    0x010F: ('Make', 'ascii'),
    0x0110: ('Model', 'ascii'),
    0x0112: ('Orientation', 'orientation'),
    0x0115: ('SamplesPerPixel', 'int'),
    0x011A: ('XResolution', 'rational'),
    0x011B: ('YResolution', 'rational'),
    0x0128: ('ResolutionUnit', 'resolution_unit'),
    0x0131: ('Software', 'ascii'),
    0x0132: ('DateTime', 'ascii'),
    0x013B: ('Artist', 'ascii'),
    0x013C: ('HostComputer', 'ascii'),
    0x0201: ('JPEGInterchangeFormat', 'int'),
    0x0202: ('JPEGInterchangeFormatLength', 'int'),
    0x0213: ('YCbCrPositioning', 'ycbcr_position'),
    0x0214: ('ReferenceBlackWhite', 'rational_list'),
    0x8298: ('Copyright', 'ascii'),
    0x8769: ('ExifOffset', 'pointer'),
    0x8825: ('GPSInfo', 'pointer'),
    0xA005: ('InteropOffset', 'pointer'),
}

EXIF_TAGS: Dict[int, Tuple[str, str]] = {
    0x829A: ('ExposureTime', 'exposure'),
    0x829D: ('FNumber', 'fnumber'),
    0x8822: ('ExposureProgram', 'exposure_program'),
    0x8824: ('SpectralSensitivity', 'ascii'),
    0x8827: ('ISOSpeedRatings', 'int'),
    0x8830: ('SensitivityType', 'sensitivity_type'),
    0x8832: ('RecommendedExposureIndex', 'int'),
    0x9000: ('ExifVersion', 'version'),
    0x9101: ('ComponentsConfiguration', 'components'),
    0x9102: ('CompressedBitsPerPixel', 'rational'),
    0x9003: ('DateTimeOriginal', 'ascii'),
    0x9004: ('DateTimeDigitized', 'ascii'),
    0x9010: ('OffsetTime', 'ascii'),
    0x9011: ('OffsetTimeOriginal', 'ascii'),
    0x9012: ('OffsetTimeDigitized', 'ascii'),
    0x9201: ('ShutterSpeedValue', 'shutter_apex'),
    0x9202: ('ApertureValue', 'aperture_apex'),
    0x9203: ('BrightnessValue', 'rational_s'),
    0x9204: ('ExposureBiasValue', 'rational_s'),
    0x9205: ('MaxApertureValue', 'aperture_apex'),
    0x9206: ('SubjectDistance', 'distance'),
    0x9207: ('MeteringMode', 'metering'),
    0x9208: ('LightSource', 'light_source'),
    0x9209: ('Flash', 'flash'),
    0x920A: ('FocalLength', 'focal'),
    0x927C: ('MakerNote', 'makernote'),
    0x9286: ('UserComment', 'usercomment'),
    0x9290: ('SubSecTime', 'ascii'),
    0x9291: ('SubSecTimeOriginal', 'ascii'),
    0x9292: ('SubSecTimeDigitized', 'ascii'),
    0xA000: ('FlashpixVersion', 'version'),
    0xA001: ('ColorSpace', 'color_space'),
    0xA002: ('PixelXDimension', 'int'),
    0xA003: ('PixelYDimension', 'int'),
    0xA20B: ('FlashEnergy', 'rational'),
    0xA20E: ('FocalPlaneXResolution', 'rational'),
    0xA20F: ('FocalPlaneYResolution', 'rational'),
    0xA210: ('FocalPlaneResolutionUnit', 'focal_plane_unit'),
    0xA215: ('ExposureIndex', 'rational'),
    0xA217: ('SensingMethod', 'sensing_method'),
    0xA300: ('FileSource', 'file_source'),
    0xA301: ('SceneType', 'scene_type'),
    0xA302: ('CFAPattern', 'raw'),
    0xA401: ('CustomRendered', 'custom_rendered'),
    0xA402: ('ExposureMode', 'exposure_mode'),
    0xA403: ('WhiteBalance', 'white_balance'),
    0xA404: ('DigitalZoomRatio', 'zoom'),
    0xA405: ('FocalLengthIn35mmFilm', 'int'),
    0xA406: ('SceneCaptureType', 'scene_capture'),
    0xA407: ('GainControl', 'gain_control'),
    0xA408: ('Contrast', 'contrast'),
    0xA409: ('Saturation', 'saturation'),
    0xA40A: ('Sharpness', 'sharpness'),
    0xA40C: ('SubjectDistanceRange', 'distance_range'),
    0xA420: ('ImageUniqueID', 'ascii'),
    0xA430: ('CameraOwnerName', 'ascii'),
    0xA431: ('BodySerialNumber', 'ascii'),
    0xA433: ('LensMake', 'ascii'),
    0xA434: ('LensModel', 'ascii'),
    0xA435: ('LensSerialNumber', 'ascii'),
    0xA500: ('Gamma', 'rational'),
}

GPS_TAGS: Dict[int, Tuple[str, str]] = {
    0x0000: ('GPSVersionID', 'gps_version'),
    0x0001: ('GPSLatitudeRef', 'gps_latlon_ref'),
    0x0002: ('GPSLatitude', 'gps_coord'),
    0x0003: ('GPSLongitudeRef', 'gps_latlon_ref'),
    0x0004: ('GPSLongitude', 'gps_coord'),
    0x0005: ('GPSAltitudeRef', 'gps_altitude_ref'),
    0x0006: ('GPSAltitude', 'rational'),
    0x0007: ('GPSTimeStamp', 'gps_timestamp'),
    0x0008: ('GPSSatellites', 'ascii'),
    0x0009: ('GPSStatus', 'gps_status'),
    0x000A: ('GPSMeasureMode', 'gps_measure_mode'),
    0x000B: ('GPSDOP', 'rational'),
    0x000C: ('GPSSpeedRef', 'gps_speed_ref'),
    0x000D: ('GPSSpeed', 'rational'),
    0x000E: ('GPSTrackRef', 'ascii'),
    0x000F: ('GPSTrack', 'rational'),
    0x0010: ('GPSImgDirectionRef', 'ascii'),
    0x0011: ('GPSImgDirection', 'rational'),
    0x0012: ('GPSMapDatum', 'ascii'),
    0x0013: ('GPSDestLatitudeRef', 'gps_latlon_ref'),
    0x0014: ('GPSDestLatitude', 'gps_coord'),
    0x0015: ('GPSDestLongitudeRef', 'gps_latlon_ref'),
    0x0016: ('GPSDestLongitude', 'gps_coord'),
    0x0017: ('GPSDestBearingRef', 'ascii'),
    0x0018: ('GPSDestBearing', 'rational'),
    0x0019: ('GPSDestDistanceRef', 'ascii'),
    0x001A: ('GPSDestDistance', 'rational'),
    0x001B: ('GPSProcessingMethod', 'gps_comment'),
    0x001C: ('GPSAreaInformation', 'gps_comment'),
    0x001D: ('GPSDateStamp', 'ascii'),
    0x001E: ('GPSDifferential', 'gps_differential'),
    0x001F: ('GPSHPositioningError', 'rational'),
}

# TIFF field type sizes (1 BYTE, 2 ASCII, 3 SHORT, 4 LONG, 5 RATIONAL,
# 6 SBYTE, 7 UNDEFINED, 8 SSHORT, 9 SLONG, 10 SRATIONAL, 11 FLOAT, 12 DOUBLE).
_TYPE_SIZES: Dict[int, int] = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1,
                               7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}

_ORIENTATION: Dict[int, str] = {
    1: 'Horizontal (normal)', 2: 'Mirror horizontal', 3: 'Rotate 180',
    4: 'Mirror vertical', 5: 'Mirror horizontal and rotate 270 CW',
    6: 'Rotate 90 CW', 7: 'Mirror horizontal and rotate 90 CW',
    8: 'Rotate 270 CW',
}
_METERING: Dict[int, str] = {0: 'Unknown', 1: 'Average', 2: 'CenterWeightedAverage',
                             3: 'Spot', 4: 'MultiSpot', 5: 'Pattern', 6: 'Partial',
                             255: 'Other'}
_EXPOSURE_PROGRAM: Dict[int, str] = {0: 'Not defined', 1: 'Manual', 2: 'Normal program',
                                     3: 'Aperture priority', 4: 'Shutter priority',
                                     5: 'Creative program', 6: 'Action program',
                                     7: 'Portrait mode', 8: 'Landscape mode',
                                     9: 'Bulb'}
_LIGHT_SOURCE: Dict[int, str] = {
    0: 'Unknown', 1: 'Daylight', 2: 'Fluorescent', 3: 'Tungsten (incandescent)',
    4: 'Flash', 9: 'Fine weather', 10: 'Cloudy weather', 11: 'Shade',
    12: 'Daylight fluorescent (D 5700 - 7100K)', 13: 'Day white fluorescent (N 4600 - 5400K)',
    14: 'Cool white fluorescent (W 3900 - 4500K)', 15: 'White fluorescent (WW 3200 - 3700K)',
    17: 'Standard light A', 18: 'Standard light B', 19: 'Standard light C',
    20: 'D55', 21: 'D65', 22: 'D75', 23: 'D50', 24: 'ISO studio tungsten', 255: 'Other',
}
_COLOR_SPACE: Dict[int, str] = {1: 'sRGB', 0xFFFF: 'Uncalibrated'}
_EXPOSURE_MODE: Dict[int, str] = {0: 'Auto exposure', 1: 'Manual exposure',
                                  2: 'Auto bracket'}
_WHITE_BALANCE: Dict[int, str] = {0: 'Auto white balance', 1: 'Manual white balance'}
_SCENE_CAPTURE: Dict[int, str] = {0: 'Standard', 1: 'Landscape', 2: 'Portrait',
                                  3: 'Night scene', 4: 'Other'}
_GAIN_CONTROL: Dict[int, str] = {0: 'None', 1: 'Low gain up', 2: 'High gain up',
                                 3: 'Low gain down', 4: 'High gain down'}
_LEVEL: Dict[int, str] = {0: 'Normal', 1: 'Low', 2: 'High', 0xFFFF: 'Unknown'}
_SHARPNESS: Dict[int, str] = {0: 'Normal', 1: 'Soft', 2: 'Hard', 0xFFFF: 'Unknown'}
_SENSING_METHOD: Dict[int, str] = {0: 'Undefined', 1: 'Not defined', 2: 'One-chip color area',
                                   3: 'Two-chip color area', 4: 'Three-chip color area',
                                   5: 'Color sequential area', 6: 'Trilinear sensor',
                                   7: 'Color sequential linear'}
_FILE_SOURCE: Dict[int, str] = {1: 'Film scanner', 2: 'Reflection print scanner',
                                3: 'Digital still camera'}
_CUSTOM_RENDERED: Dict[int, str] = {0: 'Normal process', 1: 'Custom process'}
_DISTANCE_RANGE: Dict[int, str] = {0: 'Unknown', 1: 'Macro', 2: 'Close view',
                                   3: 'Distant view'}
_RESOLUTION_UNIT: Dict[int, str] = {1: 'None', 2: 'Inches', 3: 'Centimeters'}
_FOCAL_PLANE_UNIT: Dict[int, str] = {1: 'None', 2: 'Inches', 3: 'Centimeters',
                                     4: 'Millimeters', 5: 'Micrometers'}
_SENSITIVITY_TYPE: Dict[int, str] = {
    0: 'Unknown', 1: 'Standard output sensitivity',
    2: 'Recommended exposure index', 3: 'ISO speed',
    4: 'SOS and REI', 5: 'SOS and ISO speed', 6: 'REI and ISO speed',
    7: 'SOS, REI and ISO speed',
}
_YCBCR_POSITION: Dict[int, str] = {1: 'Centered', 2: 'Co-sited'}
_COMPRESSION: Dict[int, str] = {1: 'Uncompressed', 2: 'CCITT modified Huffman RLE',
                                5: 'LZW', 6: 'JPEG compression', 8: 'Deflate (Adobe)',
                                32773: 'PackBits'}
_COMPONENTS: Dict[int, str] = {0: '-', 1: 'Y', 2: 'Cb', 3: 'Cr', 4: 'R', 5: 'G', 6: 'B'}
_GPS_STATUS: Dict[int, str] = {65: 'Measurement active (A)', 86: 'Measurement void (V)'}
_GPS_SPEED_REF: Dict[int, str] = {75: 'km/h', 77: 'mph', 78: 'knots'}
_GPS_DIFFERENTIAL: Dict[int, str] = {0: 'No correction', 1: 'Differential corrected'}

_PNG_COLOR_TYPES: Dict[int, str] = {0: 'grayscale', 2: 'truecolor (RGB)',
                                    3: 'palette', 4: 'grayscale + alpha',
                                    6: 'truecolor + alpha (RGBA)'}

# XMP element extraction: keyword -> regex over the XML text.
_XMP_PATTERNS: Dict[str, str] = {
    'creator': r'<dc:creator[\s\S]{0,200}?<rdf:li[^>]*>([^<]+)</rdf:li>',
    'title': r'<dc:title[\s\S]{0,200}?<rdf:li[^>]*>([^<]+)</rdf:li>',
    'description': r'<dc:description[\s\S]{0,200}?<rdf:li[^>]*>([^<]+)</rdf:li>',
    'rights': r'<dc:rights[\s\S]{0,200}?<rdf:li[^>]*>([^<]+)</rdf:li>',
    'CreateDate': r'<xmp:CreateDate[^>]*>([^<]+)</xmp:CreateDate>',
    'ModifyDate': r'<xmp:ModifyDate[^>]*>([^<]+)</xmp:ModifyDate>',
    'CreatorTool': r'<xmp:CreatorTool[^>]*>([^<]+)</xmp:CreatorTool>',
}
# EXIF datetime: 'YYYY:MM:DD HH:MM:SS' (+ optional subsec) -> ISO 8601.
_EXIF_DATETIME_RE = re.compile(
    r'^(\d{4}):(\d{2}):(\d{2})[ T](\d{2}):(\d{2}):(\d{2})')

_INTERESTING_STRING_RE = re.compile(
    r'(?i)(https?://|www\.|mailto:|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|adobe|photoshop'
    r'|lightroom|gimp|canon|nikon|sony|fuji|olympus|panasonic|pentax|leica|apple|iphone'
    r'|ipad|android|samsung|xiaomi|huawei|gopro|dji|windows|macintosh|linux|exif|iptc'
    r'|xmp|gps|serial|firmware|\beos\b|\balpha\b|\bdsc\b|coordinates|camera)')


# ---------------------------------------------------------------------------
# Generic helpers
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


def _sniff_format(data: bytes) -> str:
    """Identify the container by magic bytes; 'unknown' when unrecognized."""
    if data[:2] == b'\xff\xd8':
        return 'jpeg'
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        return 'png'
    if data[:6] in (b'GIF87a', b'GIF89a'):
        return 'gif'
    if data[:2] == b'BM':
        return 'bmp'
    if data[:4] == b'RIFF' and data[8:12] == b'WEBP':
        return 'webp'
    return 'unknown'


def _read_u16(data: bytes, offset: int, prefix: str) -> int:
    """Read one unsigned 16-bit integer at ``offset`` honoring byte order."""
    if offset + 2 > len(data):
        return 0
    return struct.unpack_from(prefix + 'H', data, offset)[0]


def _read_u32(data: bytes, offset: int, prefix: str) -> int:
    """Read one unsigned 32-bit integer at ``offset`` honoring byte order."""
    if offset + 4 > len(data):
        return 0
    return struct.unpack_from(prefix + 'I', data, offset)[0]


def _iso_datetime(text: Any) -> Optional[str]:
    """Normalize EXIF-style 'YYYY:MM:DD HH:MM:SS' (or ISO-ish) text to ISO 8601."""
    if not isinstance(text, str):
        return None
    match = _EXIF_DATETIME_RE.match(text.strip())
    if not match:
        return None
    year, month, day, hour, minute, second = match.groups()
    if int(month) > 12 or int(day) > 31 or int(hour) > 23:
        return None
    return f'{year}-{month}-{day}T{hour}:{minute}:{second}'


# ---------------------------------------------------------------------------
# TIFF / EXIF core
# ---------------------------------------------------------------------------

def _entry_value(data: bytes, base: int, prefix: str, etype: int, count: int,
                 value_field: bytes) -> Tuple[Optional[Any], bool]:
    """
    Decode one IFD entry value.

    Returns ``(value, is_inline)``. ``value`` is None when the value falls
    outside the buffer (corrupt offset) - the caller skips such entries and
    records a warning instead of raising.
    """
    size = _TYPE_SIZES.get(etype)
    if size is None or count < 0:
        return None, True
    total = size * count
    if total <= 4:
        raw = value_field[:total]
        inline = True
    else:
        value_offset = struct.unpack(prefix + 'I', value_field[:4])[0]
        start = base + value_offset
        if start < 0 or start + total > len(data):
            return None, False
        raw = data[start:start + total]
        inline = False
    if len(raw) < total:
        return None, inline
    if etype == 2:  # ASCII, NUL-terminated
        return raw.split(b'\x00', 1)[0].decode('latin-1', errors='replace'), inline
    if etype == 7:  # UNDEFINED: raw bytes
        return bytes(raw), inline
    if etype in (5, 10):  # (S)RATIONAL: pairs of (u)int32
        fmt = ('I' if etype == 5 else 'i') * count * 2
        words = struct.unpack(prefix + fmt, raw) if count else ()
        pairs = [(words[i], words[i + 1]) for i in range(0, len(words), 2)]
        return pairs, inline
    fmt_char = {1: 'B', 3: 'H', 4: 'I', 6: 'b', 8: 'h', 9: 'i',
                11: 'f', 12: 'd'}.get(etype)
    if fmt_char is None:
        return bytes(raw), inline
    values = struct.unpack(prefix + fmt_char * count, raw) if count else ()
    return list(values), inline


def _read_ifd(data: bytes, base: int, prefix: str, offset: int
              ) -> Tuple[Dict[int, Dict[str, Any]], int, List[str]]:
    """
    Read a single IFD: entry headers plus decoded values.

    Returns ``(entries, next_ifd_offset, warnings)``. Corrupt entries are
    skipped with a warning; a truncated entry table is clamped to whatever
    fits in the buffer.
    """
    warnings: List[str] = []
    entries: Dict[int, Dict[str, Any]] = {}
    if offset <= 0 or base + offset + 2 > len(data):
        warnings.append(f'IFD offset 0x{offset:X} out of range')
        return entries, 0, warnings
    count = _read_u16(data, base + offset, prefix)
    if count > 4096:
        warnings.append(f'implausible IFD entry count {count}; clamped')
        count = 4096
    pos = base + offset + 2
    for _ in range(count):
        if pos + 12 > len(data):
            warnings.append('truncated IFD entry table')
            break
        tag, etype, ecount = struct.unpack_from(prefix + 'HHI', data, pos)
        value_field = bytes(data[pos + 8:pos + 12])
        if etype in _TYPE_SIZES:
            value, _inline = _entry_value(data, base, prefix, etype, ecount, value_field)
            if value is None:
                warnings.append(f'tag 0x{tag:04X} value out of bounds; skipped')
            else:
                entries[tag] = {'type': etype, 'count': ecount, 'value': value}
        else:
            warnings.append(f'tag 0x{tag:04X} has unknown field type {etype}; skipped')
        pos += 12
    next_offset = _read_u32(data, pos, prefix) if pos + 4 <= len(data) else 0
    return entries, next_offset, warnings


def _rational_float(value: Any) -> Optional[float]:
    """Convert a single (num, den) rational pair to float (None on garbage)."""
    if isinstance(value, (list, tuple)) and len(value) == 2:
        num, den = value
        try:
            num_f, den_f = float(num), float(den)
        except (TypeError, ValueError):
            return None
        if den_f == 0:
            return None
        return num_f / den_f
    return None


def _format_flash(value: int) -> str:
    """Decode the EXIF Flash bit field into 'Fired, auto mode' style text."""
    parts: List[str] = []
    parts.append('Fired' if value & 0x01 else 'Did not fire')
    strobe = (value >> 1) & 0x03
    if strobe == 0b10:
        parts.append('strobe return light not detected')
    elif strobe == 0b11:
        parts.append('strobe return light detected')
    mode = (value >> 3) & 0x03
    if mode == 0b01:
        parts.append('compulsory flash mode')
    elif mode == 0b10:
        parts.append('compulsory flash suppression')
    elif mode == 0b11:
        parts.append('auto mode')
    if value & 0x20:
        parts.append('no flash function')
    if value & 0x40:
        parts.append('red-eye reduction')
    return ', '.join(parts)


def _format_tag(tag: int, name: str, kind: str, value: Any) -> Any:
    """Apply friendly formatting (maps, APEX math, unit suffixes) to one value."""
    def as_int(raw: Any) -> Optional[int]:
        if isinstance(raw, list) and raw:
            return int(raw[0])
        if isinstance(raw, int):
            return raw
        if isinstance(raw, bytes) and raw:
            return raw[0]
        return None

    if kind == 'pointer':
        return None
    if kind == 'int':
        if isinstance(value, list) and len(value) == 1:
            return value[0]
        return value if value != [] else None
    if kind == 'ascii':
        return value if value else None
    if kind == 'rational':
        number = _rational_float(value[0] if isinstance(value, list) and value else value)
        return round(number, 4) if number is not None else None
    if kind == 'rational_list':
        if not isinstance(value, list):
            return None
        out = []
        for item in value:
            number = _rational_float(item)
            out.append(round(number, 2) if number is not None else None)
        return out or None
    if kind == 'rational_s':
        number = _rational_float(value[0] if isinstance(value, list) and value else value)
        return round(number, 3) if number is not None else None
    if kind == 'exposure':  # ExposureTime -> '1/x s'
        number = _rational_float(value[0] if isinstance(value, list) and value else value)
        if number is None:
            return None
        if number <= 0:
            return None
        if number < 0.25:
            return f'1/{int(round(1.0 / number))} s'
        return f'{number:.1f} s'
    if kind == 'fnumber':  # FNumber -> 'f/x.x'
        number = _rational_float(value[0] if isinstance(value, list) and value else value)
        return f'f/{number:.1f}' if number else None
    if kind == 'focal':  # FocalLength -> 'x.x mm'
        number = _rational_float(value[0] if isinstance(value, list) and value else value)
        return f'{number:.1f} mm' if number else None
    if kind == 'zoom':  # DigitalZoomRatio -> 'x.xx'
        number = _rational_float(value[0] if isinstance(value, list) and value else value)
        return f'{number:.2f}x' if number else None
    if kind == 'distance':  # SubjectDistance in metres
        number = _rational_float(value[0] if isinstance(value, list) and value else value)
        if number is None:
            return None
        return 'unknown' if number <= 0 else f'{number:.2f} m'
    if kind == 'shutter_apex':  # APEX ShutterSpeedValue -> '1/x s'
        number = _rational_float(value[0] if isinstance(value, list) and value else value)
        if number is None:
            return None
        seconds = 2.0 ** (-number)
        if seconds < 0.25:
            return f'1/{int(round(1.0 / seconds))} s'
        return f'{seconds:.1f} s'
    if kind == 'aperture_apex':  # APEX ApertureValue -> 'f/x.x'
        number = _rational_float(value[0] if isinstance(value, list) and value else value)
        if number is None:
            return None
        return f'f/{2.0 ** (number / 2.0):.1f}'
    if kind == 'version':  # ExifVersion / FlashpixVersion bytes -> '0231'
        if isinstance(value, bytes):
            return value.decode('ascii', errors='replace')
        return value
    if kind == 'components':
        if isinstance(value, bytes):
            return ' '.join(_COMPONENTS.get(b, str(b)) for b in value)
        return value
    if kind == 'usercomment':
        return _strip_charset_prefix(value)
    if kind == 'makernote':
        if isinstance(value, bytes):
            return {'present': True, 'size': len(value)}
        return {'present': bool(value), 'size': 0}
    if kind == 'orientation':
        number = as_int(value)
        return _ORIENTATION.get(number, number) if number is not None else None
    if kind == 'metering':
        number = as_int(value)
        return _METERING.get(number, number) if number is not None else None
    if kind == 'exposure_program':
        number = as_int(value)
        return _EXPOSURE_PROGRAM.get(number, number) if number is not None else None
    if kind == 'light_source':
        number = as_int(value)
        return _LIGHT_SOURCE.get(number, number) if number is not None else None
    if kind == 'flash':
        number = as_int(value)
        return _format_flash(number) if number is not None else None
    if kind == 'color_space':
        number = as_int(value)
        return _COLOR_SPACE.get(number, number) if number is not None else None
    if kind == 'exposure_mode':
        number = as_int(value)
        return _EXPOSURE_MODE.get(number, number) if number is not None else None
    if kind == 'white_balance':
        number = as_int(value)
        return _WHITE_BALANCE.get(number, number) if number is not None else None
    if kind == 'scene_capture':
        number = as_int(value)
        return _SCENE_CAPTURE.get(number, number) if number is not None else None
    if kind == 'gain_control':
        number = as_int(value)
        return _GAIN_CONTROL.get(number, number) if number is not None else None
    if kind == 'contrast':
        number = as_int(value)
        return _LEVEL.get(number, number) if number is not None else None
    if kind == 'saturation':
        number = as_int(value)
        return _LEVEL.get(number, number) if number is not None else None
    if kind == 'sharpness':
        number = as_int(value)
        return _SHARPNESS.get(number, number) if number is not None else None
    if kind == 'sensing_method':
        number = as_int(value)
        return _SENSING_METHOD.get(number, number) if number is not None else None
    if kind == 'file_source':
        number = as_int(value)
        return _FILE_SOURCE.get(number, number) if number is not None else None
    if kind == 'scene_type':
        number = as_int(value)
        return ('Directly photographed image' if number == 1 else number) \
            if number is not None else None
    if kind == 'custom_rendered':
        number = as_int(value)
        return _CUSTOM_RENDERED.get(number, number) if number is not None else None
    if kind == 'distance_range':
        number = as_int(value)
        return _DISTANCE_RANGE.get(number, number) if number is not None else None
    if kind == 'resolution_unit':
        number = as_int(value)
        return _RESOLUTION_UNIT.get(number, number) if number is not None else None
    if kind == 'focal_plane_unit':
        number = as_int(value)
        return _FOCAL_PLANE_UNIT.get(number, number) if number is not None else None
    if kind == 'sensitivity_type':
        number = as_int(value)
        return _SENSITIVITY_TYPE.get(number, number) if number is not None else None
    if kind == 'ycbcr_position':
        number = as_int(value)
        return _YCBCR_POSITION.get(number, number) if number is not None else None
    if kind == 'compression':
        number = as_int(value)
        return _COMPRESSION.get(number, number) if number is not None else None
    if kind in ('gps_latlon_ref',):
        text = value if isinstance(value, str) else str(value)
        return text.strip().upper()[:1] or None
    if kind == 'gps_altitude_ref':
        number = as_int(value)
        if number is None:
            return None
        return 'Below sea level' if number else 'Above sea level'
    if kind == 'gps_version':
        if isinstance(value, (bytes, list)):
            return '.'.join(str(int(b)) for b in value)
        return value
    if kind == 'gps_timestamp':
        return _gps_timestamp(value)
    if kind == 'gps_status':
        number = as_int(value)
        return _GPS_STATUS.get(number, number) if number is not None else None
    if kind == 'gps_measure_mode':
        number = as_int(value)
        return ('2-dimensional' if number == 2 else '3-dimensional') \
            if number == 2 or number == 3 else number
    if kind == 'gps_speed_ref':
        number = as_int(value)
        return _GPS_SPEED_REF.get(number, number) if number is not None else None
    if kind == 'gps_differential':
        number = as_int(value)
        return _GPS_DIFFERENTIAL.get(number, number) if number is not None else None
    if kind == 'gps_comment':
        return _strip_charset_prefix(value)
    if kind == 'gps_coord':
        return value  # consumed by _format_gps for the decimal conversion
    return value


def _strip_charset_prefix(value: Any) -> Optional[str]:
    """
    Strip the 8-byte charset header used by UserComment / GPSProcessingMethod.

    The EXIF spec prefixes these UNDEFINED values with a fixed 8-byte area
    ('ASCII\\0\\0\\0', 'UNICODE\\0', '\\x1b%G' for JIS). UNICODE payloads are
    decoded as UTF-16LE, everything else as latin-1.
    """
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        raw = value.encode('latin-1', errors='replace')
    else:
        return None
    if len(raw) < 8:
        return raw.decode('latin-1', errors='replace').strip('\x00') or None
    header, body = raw[:8], raw[8:]
    if header.startswith(b'UNICODE'):
        text = body.decode('utf-16-le', errors='replace')
    else:
        text = body.decode('latin-1', errors='replace')
    return text.strip('\x00 ').strip() or None


def _gps_timestamp(value: Any) -> Optional[str]:
    """GPSTimeStamp (3 rationals, UTC) -> 'HH:MM:SS'."""
    if not isinstance(value, list) or not value:
        return None
    parts: List[str] = []
    for item in value[:3]:
        number = _rational_float(item)
        if number is None:
            return None
        parts.append(f'{int(round(number)):02d}')
    while len(parts) < 3:
        parts.append('00')
    return ':'.join(parts)


def _gps_to_decimal(rational_list: Any, ref: Optional[str]) -> Optional[float]:
    """GPS (degrees, minutes, seconds) rationals + N/S/E/W ref -> decimal degrees."""
    if not isinstance(rational_list, list) or not rational_list:
        return None
    numbers: List[float] = []
    for item in rational_list[:3]:
        number = _rational_float(item)
        if number is None:
            return None
        numbers.append(number)
    while len(numbers) < 3:
        numbers.append(0.0)
    degrees, minutes, seconds = numbers
    decimal = degrees + minutes / 60.0 + seconds / 3600.0
    if ref in ('S', 'W'):
        decimal = -decimal
    return round(decimal, 6)


def _format_dms(rational_list: Any, ref: Optional[str]) -> Optional[str]:
    """GPS rationals -> \"48° 51' 30.24\\" N\" style sexagesimal string."""
    if not isinstance(rational_list, list) or not rational_list:
        return None
    numbers = []
    for item in rational_list[:3]:
        number = _rational_float(item)
        if number is None:
            return None
        numbers.append(number)
    while len(numbers) < 3:
        numbers.append(0.0)
    degrees, minutes, seconds = numbers
    return f"{degrees:.0f}\u00b0 {minutes:.0f}' {seconds:.2f}\" {ref or ''}".strip()


def _decimal_text(value: Optional[float]) -> Optional[str]:
    """48.8584 -> '48.8584' (trailing zeros trimmed)."""
    if value is None:
        return None
    return f'{value:.6f}'.rstrip('0').rstrip('.')


def _format_gps(entries: Dict[int, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build the friendly GPS dict from raw GPS IFD entries.

    Includes decimal degrees, DMS strings and a ready-to-use 'coords' key
    ('48.8584, 2.2945') formatted for the ObscuraLens coords tracker.
    """
    gps: Dict[str, Any] = {}
    for tag, entry in sorted(entries.items()):
        name, kind = GPS_TAGS.get(tag, (f'GPS_TAG_0x{tag:04X}', 'raw'))
        formatted = _format_tag(tag, name, kind, entry['value'])
        if formatted is not None and kind != 'gps_coord':
            gps[name] = formatted
    latitude = None
    longitude = None
    if 0x0002 in entries:
        latitude = _gps_to_decimal(entries[0x0002]['value'], gps.get('GPSLatitudeRef'))
        gps['latitude'] = latitude
        gps['latitude_dms'] = _format_dms(entries[0x0002]['value'], gps.get('GPSLatitudeRef'))
    if 0x0004 in entries:
        longitude = _gps_to_decimal(entries[0x0004]['value'], gps.get('GPSLongitudeRef'))
        gps['longitude'] = longitude
        gps['longitude_dms'] = _format_dms(entries[0x0004]['value'], gps.get('GPSLongitudeRef'))
    if latitude is not None and longitude is not None:
        gps['coords'] = f'{_decimal_text(latitude)}, {_decimal_text(longitude)}'
    if 0x0006 in entries:  # GPSAltitude
        altitude = _rational_float(entries[0x0006]['value'][0]
                                    if isinstance(entries[0x0006]['value'], list)
                                    and entries[0x0006]['value'] else None)
        if altitude is not None:
            below = _format_tag(0x0005, 'GPSAltitudeRef', 'gps_altitude_ref',
                                entries.get(0x0005, {}).get('value', 0))
            gps['altitude_m'] = round(-altitude if below == 'Below sea level' else altitude, 1)
    return gps


def _parse_tiff(data: bytes, depth: int = 0) -> Dict[str, Any]:
    """
    Parse a TIFF/EXIF blob (as found in JPEG APP1 or PNG eXIf chunks).

    Walks IFD0, the EXIF sub-IFD (tag 0x8769), GPS IFD (0x8825), Interop IFD
    (0xA005) and the IFD1 thumbnail chain. Values are returned with friendly
    names via ``EXIF_TAGS`` / ``GPS_TAGS`` / ``IFD0_TAGS``.
    """
    result: Dict[str, Any] = {}
    if len(data) < 8:
        return {'error': 'truncated TIFF header', 'parsed': result}
    order = data[:2]
    if order == b'II':
        prefix = '<'
        result['byte_order'] = 'little'
    elif order == b'MM':
        prefix = '>'
        result['byte_order'] = 'big'
    else:
        return {'error': f'bad TIFF byte-order mark {order!r}', 'parsed': result}
    magic = _read_u16(data, 2, prefix)
    if magic != 42:
        return {'error': f'bad TIFF magic {magic}', 'parsed': result}
    warnings: List[str] = []

    def walk_ifd(offset: int, table: Dict[int, Tuple[str, str]], level: int
                 ) -> Tuple[Dict[str, Any], int, Dict[int, Dict[str, Any]], int]:
        """Read one IFD; return (friendly dict, next offset, raw entries, entry count)."""
        label = 'IFD0' if table is IFD0_TAGS else 'IFD'
        raw_entries, next_offset, notes = _read_ifd(data, 0, prefix, offset)
        warnings.extend(f'{label}: {note}' for note in notes)
        friendly: Dict[str, Any] = {}
        for tag, entry in sorted(raw_entries.items()):
            name, kind = table.get(tag, (f'Tag_0x{tag:04X}', 'raw'))
            formatted = _format_tag(tag, name, kind, entry['value'])
            if formatted is not None:
                friendly[name] = formatted
        return friendly, next_offset, raw_entries, len(raw_entries)

    ifd0_offset = _read_u32(data, 4, prefix)
    ifd0, next_offset, ifd0_raw, _count = walk_ifd(ifd0_offset, IFD0_TAGS, 0)
    result['ifd0'] = ifd0

    exif_offset = ifd0_raw.get(0x8769, {}).get('value')
    exif_raw: Dict[int, Dict[str, Any]] = {}
    if isinstance(exif_offset, list) and exif_offset and depth < 4:
        exif_dict, _n, exif_raw, _c = walk_ifd(int(exif_offset[0]), EXIF_TAGS, 1)
        result['exif'] = exif_dict
    elif isinstance(exif_offset, int) and depth < 4:
        exif_dict, _n, exif_raw, _c = walk_ifd(exif_offset, EXIF_TAGS, 1)
        result['exif'] = exif_dict

    gps_offset = (ifd0_raw.get(0x8825, {}).get('value')
                  or exif_raw.get(0x8825, {}).get('value'))
    if gps_offset is not None and depth < 4:
        if isinstance(gps_offset, list):
            gps_offset = gps_offset[0] if gps_offset else None
        if isinstance(gps_offset, int):
            result['gps'] = _format_gps(_read_ifd(data, 0, prefix, gps_offset)[0])

    interop_offset = (exif_raw.get(0xA005, {}).get('value')
                      or ifd0_raw.get(0xA005, {}).get('value'))
    if interop_offset is not None and depth < 4:
        if isinstance(interop_offset, list):
            interop_offset = interop_offset[0] if interop_offset else None
        if isinstance(interop_offset, int):
            interop, _n, _raw, _c = walk_ifd(interop_offset, EXIF_TAGS, 2)
            result['interop'] = interop

    # IFD1: embedded JPEG thumbnail.
    if next_offset:
        thumb_dict, _n, thumb_raw, _c = walk_ifd(next_offset, IFD0_TAGS, 1)
        result['ifd1'] = thumb_dict
        thumb_offset = thumb_raw.get(0x0201, {}).get('value')
        thumb_length = thumb_raw.get(0x0202, {}).get('value')
        if isinstance(thumb_offset, list) and thumb_offset:
            thumb_offset = thumb_offset[0]
        if isinstance(thumb_length, list) and thumb_length:
            thumb_length = thumb_length[0]
        if isinstance(thumb_offset, int) and isinstance(thumb_length, int) \
                and thumb_length > 0:
            blob = data[thumb_offset:thumb_offset + thumb_length]
            start = blob.find(b'\xff\xd8')
            if start != -1:
                jpeg = blob[start:]
                result['thumbnail'] = {
                    'thumbnail_jpeg': jpeg,
                    'thumbnail_size': len(jpeg),
                    'thumbnail_offset': thumb_offset + start,
                }
    if warnings:
        result['warnings'] = warnings
    return result


def _merge_tiff_into(meta: Dict[str, Any], tiff: Dict[str, Any]) -> None:
    """Lift a parsed TIFF result into a container metadata dict (jpeg/png)."""
    if tiff.get('error'):
        meta['exif_error'] = tiff['error']
    exif: Dict[str, Any] = {}
    for section in ('ifd0', 'exif', 'interop'):
        section_dict = tiff.get(section)
        if isinstance(section_dict, dict):
            exif.update(section_dict)
    if exif:
        meta['exif'] = exif
    if isinstance(tiff.get('gps'), dict) and tiff['gps']:
        meta['gps'] = tiff['gps']
    if isinstance(tiff.get('thumbnail'), dict):
        meta['thumbnail'] = tiff['thumbnail']
    if tiff.get('warnings'):
        existing = meta.setdefault('warnings', [])
        existing.extend(tiff['warnings'])


# ---------------------------------------------------------------------------
# JPEG container
# ---------------------------------------------------------------------------

def _parse_xmp(xml_text: str) -> Dict[str, Any]:
    """Regex-extract the OSINT-interesting XMP elements (dc:*, xmp:*, photoshop:*)."""
    xmp: Dict[str, Any] = {}
    for key, pattern in _XMP_PATTERNS.items():
        match = re.search(pattern, xml_text)
        if match:
            value = match.group(1).strip()
            if value:
                xmp[key] = value
    photoshop: Dict[str, str] = {}
    for match in re.finditer(r'<photoshop:([A-Za-z0-9_]+)[^>]*>([^<]{1,300})', xml_text):
        element, value = match.group(1), match.group(2).strip()
        if value and element not in photoshop:
            photoshop[element] = value
    if photoshop:
        xmp['photoshop'] = photoshop
    return xmp


def _parse_photoshop(blob: bytes) -> Dict[str, Any]:
    """Minimally walk Photoshop 8BIM records (APP13); notes IPTC presence."""
    records: List[Dict[str, Any]] = []
    pos = 0
    while pos + 8 <= len(blob):
        if blob[pos:pos + 4] != b'8BIM':
            break
        record_id = struct.unpack_from('>H', blob, pos + 4)[0]
        name_len = blob[pos + 6]
        name_field = name_len + 1
        if name_field % 2:
            name_field += 1
        cursor = pos + 6 + name_field
        if cursor + 4 > len(blob):
            break
        size = struct.unpack_from('>I', blob, cursor)[0]
        cursor += 4
        records.append({
            'id': f'0x{record_id:04X}',
            'name': 'IPTC-NAA' if record_id == 0x0404 else f'8BIM-{record_id:04X}',
            'size': size,
        })
        pos = cursor + size + (size & 1)
    out: Dict[str, Any] = {'record_count': len(records), 'records': records[:24]}
    out['iptc'] = any(rec['id'] == '0x0404' for rec in records)
    return out


def _parse_jpeg(data: bytes) -> Dict[str, Any]:
    """
    Walk the JPEG segment chain (SOI ... APPn ... SOS ... EOI).

    Extracts JFIF info, EXIF (APP1 'Exif\\0\\0'), XMP (APP1 Adobe XMP),
    ICC profile presence (APP2), Photoshop 8BIM records (APP13) and COM
    comments. Stops at SOS/EOI and reports trailing bytes after EOI.
    """
    meta: Dict[str, Any] = {'format': 'jpeg'}
    comments: List[str] = []
    notes: List[str] = []
    icc_seq: List[int] = []
    pos = 2
    while pos < len(data):
        if data[pos] != 0xFF:
            # Real-world files often carry stray bytes between segments;
            # resynchronize on the next 0xFF instead of giving up.
            resync = data.find(b'\xff', pos)
            if resync == -1:
                meta['error'] = f'desynchronized at offset {pos} (no further marker)'
                break
            notes.append(f'skipped {resync - pos} byte(s) after offset {pos} '
                         'to resynchronize on the next marker')
            pos = resync
        while pos < len(data) and data[pos] == 0xFF:
            pos += 1
        if pos >= len(data):
            meta['error'] = 'truncated marker'
            break
        marker = data[pos]
        pos += 1
        if marker in (0x01, 0xD8) or 0xD0 <= marker <= 0xD7:
            continue  # stuffing / restart markers carry no payload
        if marker == 0xD9:  # EOI
            meta['trailing_after_eoi'] = len(data) - pos
            break
        if marker == 0xDA:  # SOS: entropy-coded data follows
            eoi = data.find(b'\xff\xd9', pos)
            if eoi == -1:
                meta['trailing_after_eoi'] = 0
                notes.append('EOI marker not found after SOS (truncated stream)')
            else:
                meta['trailing_after_eoi'] = len(data) - eoi - 2
            break
        if pos + 2 > len(data):
            meta['error'] = 'truncated segment header'
            break
        length = struct.unpack_from('>H', data, pos)[0]
        if length < 2:
            meta['error'] = f'invalid segment length {length} at offset {pos}'
            break
        segment = data[pos + 2:pos + length]
        if marker == 0xE0:
            if segment[:5] == b'JFIF\x00' and len(segment) >= 14:
                units = segment[7]
                xdensity, ydensity = struct.unpack_from('>HH', segment, 8)
                meta['jfif'] = {
                    'version': f'{segment[5]}.{segment[6]:02d}',
                    'units': {0: 'none (aspect ratio)', 1: 'dots per inch',
                              2: 'dots per cm'}.get(units, units),
                    'x_density': xdensity,
                    'y_density': ydensity,
                    'thumbnail': {'width': segment[12], 'height': segment[13]},
                }
            elif segment[:5] == b'JFIF\x00':
                notes.append('APP0 JFIF payload truncated')
            elif segment[:4] == b'JFXX':
                notes.append('APP0 JFXX extension present')
            else:
                notes.append('APP0 present (non-JFIF)')
        elif marker == 0xE1:
            if segment[:6] == b'Exif\x00\x00' and len(segment) > 8:
                _merge_tiff_into(meta, _parse_tiff(segment[6:]))
            elif segment[:29] == b'http://ns.adobe.com/xap/1.0/\x00':
                xml_text = segment[29:].decode('utf-8', errors='replace')
                xmp = _parse_xmp(xml_text)
                if xmp:
                    meta['xmp'] = xmp
                meta['xmp_size'] = len(segment) - 29
            else:
                notes.append('APP1 present (unknown payload)')
        elif marker == 0xE2:
            if segment[:12] == b'ICC_PROFILE\x00' and len(segment) > 14:
                icc_seq.append(segment[12])
                if segment[12] == 1:
                    meta['icc_profile'] = {'present': True, 'chunks': segment[13]}
        elif marker == 0xED:
            if segment[:14] == b'Photoshop 3.0\x00':
                meta['photoshop'] = _parse_photoshop(segment[14:])
            else:
                notes.append('APP13 present (non-Photoshop)')
        elif marker == 0xFE:
            text = segment.decode('latin-1', errors='replace').strip('\x00').strip()
            if text:
                comments.append(text)
        pos += length
    if comments:
        meta['comments'] = comments
        meta['comment'] = '\n'.join(comments)
    if notes:
        meta['notes'] = notes
    return meta


# ---------------------------------------------------------------------------
# PNG container
# ---------------------------------------------------------------------------

def _parse_png(data: bytes) -> Dict[str, Any]:
    """
    Walk PNG chunks verifying CRC32 (zlib.crc32) for integrity notes.

    Parses IHDR dimensions, tEXt/zTXt/iTXt textual metadata (zTXt payloads
    are zlib-decompressed), tIME modification time, the eXIf chunk (full
    TIFF re-parse), pHYs / gAMA and flags ImageMagick IPTC/EXIF profiles.
    """
    meta: Dict[str, Any] = {'format': 'png'}
    texts: Dict[str, str] = {}
    text_notes: List[str] = []
    chunk_names: List[str] = []
    crc_errors: List[str] = []
    pos = 8
    while pos + 8 <= len(data):
        length = struct.unpack_from('>I', data, pos)[0]
        ctype = data[pos + 4:pos + 8]
        cdata = data[pos + 8:pos + 8 + length]
        if len(cdata) < length:
            meta['error'] = f'chunk {ctype!r} truncated'
            break
        crc_stored = struct.unpack_from('>I', data, pos + 8 + length)[0] \
            if pos + 12 + length <= len(data) else None
        if crc_stored is not None:
            crc_actual = zlib.crc32(ctype + cdata) & 0xFFFFFFFF
            if crc_actual != crc_stored:
                crc_errors.append(ctype.decode('latin-1', errors='replace'))
        chunk_names.append(ctype.decode('latin-1', errors='replace'))
        if ctype == b'IHDR' and length >= 13:
            width, height, depth, color, compression, filtering, interlace = \
                struct.unpack_from('>IIBBBBB', cdata, 0)
            meta.update({
                'width': width, 'height': height, 'bit_depth': depth,
                'color_type': _PNG_COLOR_TYPES.get(color, color),
                'compression': compression, 'filter_method': filtering,
                'interlace': 'progressive (Adam7)' if interlace else 'none',
            })
        elif ctype == b'tEXt':
            keyword, _, value = cdata.partition(b'\x00')
            texts[keyword.decode('latin-1', errors='replace')] = \
                value.decode('latin-1', errors='replace')
        elif ctype == b'zTXt':
            keyword, _, rest = cdata.partition(b'\x00')
            try:
                value = zlib.decompress(rest[1:]).decode('latin-1', errors='replace')
            except zlib.error as exc:
                value = ''
                text_notes.append(f'zTXt {keyword!r} failed to decompress: {exc}')
            if value:
                texts[keyword.decode('latin-1', errors='replace')] = value
        elif ctype == b'iTXt' and length >= 3:
            keyword, _, rest = cdata.partition(b'\x00')
            comp_flag = rest[0] if rest else 0
            language, _, tail = rest[1:].partition(b'\x00')
            translated, _, value = tail.partition(b'\x00')
            if comp_flag == 1:
                try:
                    value = zlib.decompress(value)
                except zlib.error as exc:
                    text_notes.append(f'iTXt {keyword!r} failed to decompress: {exc}')
                    value = b''
            texts[keyword.decode('latin-1', errors='replace')] = \
                value.decode('utf-8', errors='replace')
            if language:
                text_notes.append(f'iTXt language {language.decode("latin-1", "replace")}')
            if translated:
                text_notes.append(f'iTXt translated keyword '
                                  f'{translated.decode("utf-8", "replace")}')
        elif ctype == b'tIME' and length >= 7:
            year, month, day, hour, minute, second = struct.unpack_from('>HBBBBB', cdata, 0)
            meta['modification_time'] = \
                f'{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}'
        elif ctype == b'eXIf':
            _merge_tiff_into(meta, _parse_tiff(cdata))
        elif ctype == b'pHYs' and length >= 9:
            ppux, ppuy, unit = struct.unpack_from('>IIB', cdata, 0)
            meta['physical'] = {
                'pixels_per_unit_x': ppux, 'pixels_per_unit_y': ppuy,
                'unit': 'meter' if unit == 1 else 'unknown (0)',
                'dpi': [round(ppux * 0.0254), round(ppuy * 0.0254)] if unit == 1 else None,
            }
        elif ctype == b'gAMA' and length >= 4:
            meta['gamma'] = round(struct.unpack_from('>I', cdata, 0)[0] / 100000.0, 5)
        elif ctype == b'PLTE':
            meta['palette_entries'] = length // 3
        if ctype == b'IEND':
            trailing = len(data) - (pos + 12 + length)
            if trailing > 0:
                meta['trailing_after_iend'] = trailing
            break
        pos += 12 + length
    else:
        meta['error'] = 'IEND chunk missing'
    if texts:
        meta['text'] = texts
        for interesting in ('Description', 'Author', 'Comment', 'Software', 'Creation Time'):
            if interesting in texts:
                meta[interesting.lower().replace(' ', '_')] = texts[interesting]
        for profile in ('Raw profile type iptc', 'Raw profile type exif',
                        'Raw profile type xmp'):
            if profile in texts:
                text_notes.append(f'{profile} block present '
                                  f'({len(texts[profile])} chars, ImageMagick-style)')
    if crc_errors:
        meta['crc_errors'] = crc_errors
    if text_notes:
        meta['text_notes'] = text_notes
    meta['chunks'] = chunk_names
    meta['chunk_count'] = len(chunk_names)
    return meta


# ---------------------------------------------------------------------------
# GIF / BMP / WebP containers
# ---------------------------------------------------------------------------

def _parse_gif(data: bytes) -> Dict[str, Any]:
    """Parse the GIF logical screen, count frames (image separators 0x2C),
    read the NETSCAPE2.0 loop count and comment extension text."""
    meta: Dict[str, Any] = {'format': 'gif'}
    if len(data) < 13:
        return {'format': 'gif', 'error': 'truncated GIF header', 'parsed': meta}
    meta['version'] = data[:6].decode('ascii', errors='replace')
    width, height = struct.unpack_from('<HH', data, 6)
    packed = data[10]
    meta.update({'width': width, 'height': height,
                 'global_color_table': bool(packed & 0x80),
                 'global_color_table_size': 3 * (2 ** ((packed & 0x07) + 1))
                 if packed & 0x80 else 0})
    pos = 13 + (meta['global_color_table_size'] if packed & 0x80 else 0)
    frames = 0
    comments: List[str] = []
    while pos < len(data):
        block = data[pos]
        if block == 0x3B:  # trailer
            pos += 1
            break
        if block == 0x21 and pos + 1 < len(data):  # extension
            label = data[pos + 1]
            pos += 2
            if label == 0xFF and pos < len(data):  # application extension
                app_size = data[pos]
                app_id = data[pos + 1:pos + 1 + app_size]
                pos += 1 + app_size
                if app_id[:11] == b'NETSCAPE2.0':
                    sub_pos = pos
                    while sub_pos < len(data) and data[sub_pos]:
                        sub_len = data[sub_pos]
                        if sub_len >= 3 and data[sub_pos + 1] == 1:
                            meta['loop_count'] = struct.unpack_from(
                                '<H', data, sub_pos + 2)[0]
                        sub_pos += 1 + sub_len
                    pos = sub_pos
                else:
                    while pos < len(data) and data[pos]:
                        pos += 1 + data[pos]
            elif label == 0xFE:  # comment extension
                parts: List[bytes] = []
                while pos < len(data) and data[pos]:
                    sub_len = data[pos]
                    parts.append(data[pos + 1:pos + 1 + sub_len])
                    pos += 1 + sub_len
                text = b''.join(parts).decode('latin-1', errors='replace').strip()
                if text:
                    comments.append(text)
            else:  # graphic control / other: skip sub-blocks
                while pos < len(data) and data[pos]:
                    pos += 1 + data[pos]
        elif block == 0x2C and pos + 10 <= len(data):  # image separator
            frames += 1
            image_packed = data[pos + 8]
            pos += 10
            if image_packed & 0x80:  # local color table
                pos += 3 * (2 ** ((image_packed & 0x07) + 1))
            if pos < len(data):
                pos += 1  # LZW minimum code size
                while pos < len(data) and data[pos]:
                    pos += 1 + data[pos]
        else:
            meta['error'] = f'unexpected block byte 0x{block:02X} at offset {pos}'
            break
    if pos < len(data):
        meta['trailing_after_trailer'] = len(data) - pos
    meta['frame_count'] = frames
    if comments:
        meta['comments'] = comments
        meta['comment'] = '\n'.join(comments)
    return meta


def _parse_bmp(data: bytes) -> Dict[str, Any]:
    """Parse the BMP file header + BITMAPINFOHEADER/COREHEADER (w/h/bpp)."""
    meta: Dict[str, Any] = {'format': 'bmp'}
    if len(data) < 26:
        return {'format': 'bmp', 'error': 'truncated BMP header', 'parsed': meta}
    pixel_offset = struct.unpack_from('<I', data, 10)[0]
    dib_size = struct.unpack_from('<I', data, 14)[0]
    if dib_size == 12:  # BITMAPCOREHEADER
        width, height, planes, bpp = struct.unpack_from('<HHHH', data, 18)
        meta['header_type'] = 'BITMAPCOREHEADER'
    else:
        width, height = struct.unpack_from('<ii', data, 18)
        planes, bpp = struct.unpack_from('<HH', data, 26)
        meta['header_type'] = 'BITMAPINFOHEADER' if dib_size == 40 else f'DIB-{dib_size}bytes'
        if not (0 < abs(width) <= 50000 and 0 < abs(height) <= 50000):
            # Salvage headers that (contrary to their declared size) encode
            # core-style u16 dimensions - common in hand-rolled BMPs.
            core_width, core_height = struct.unpack_from('<HH', data, 18)
            if 0 < core_width <= 50000 and 0 < core_height <= 50000 \
                    and bpp in (1, 4, 8, 16, 24, 32):
                width, height = core_width, core_height
                meta['notes'] = ['declared 40-byte DIB but dimensions encoded '
                                 'core-style (u16) - salvaged']
    if not (0 < abs(width) <= 50000 and 0 < abs(height) <= 50000):
        return {'format': 'bmp', 'error': f'implausible dimensions {width}x{height}',
                'parsed': meta}
    meta.update({
        'width': width,
        'height': height,
        'bottom_up': height > 0,
        'planes': planes,
        'bpp': bpp,
    })
    if dib_size >= 20 and len(data) >= 34:
        meta['compression'] = struct.unpack_from('<I', data, 30)[0]
    if dib_size >= 24 and len(data) >= 38:
        meta['image_size'] = struct.unpack_from('<I', data, 34)[0]
    row_size = ((abs(width) * bpp + 31) // 32) * 4
    expected = row_size * abs(height)
    meta['pixel_data_offset'] = pixel_offset
    meta['row_size'] = row_size
    meta['expected_pixel_bytes'] = expected
    if pixel_offset + expected > len(data):
        meta['error'] = (f'pixel data truncated: need {expected} bytes at '
                         f'offset {pixel_offset}, have {max(0, len(data) - pixel_offset)}')
    return meta


def _parse_webp(data: bytes) -> Dict[str, Any]:
    """Parse the WebP RIFF container: VP8/VP8L/VP8X chunk dimensions."""
    meta: Dict[str, Any] = {'format': 'webp'}
    chunks: List[str] = []
    pos = 12
    while pos + 8 <= len(data):
        csize = struct.unpack_from('<I', data, pos + 4)[0]
        ctype = data[pos:pos + 4]
        cdata = data[pos + 8:pos + 8 + csize]
        chunks.append(ctype.decode('latin-1', errors='replace'))
        if ctype == b'VP8L' and len(cdata) >= 5:
            bits = int.from_bytes(cdata[1:5], 'little')
            meta['width'] = (bits & 0x3FFF) + 1
            meta['height'] = ((bits >> 14) & 0x3FFF) + 1
            meta['compression'] = 'lossless'
        elif ctype == b'VP8 ' and len(cdata) >= 10:
            if cdata[3:6] == b'\x9d\x01\x2a':
                meta['width'] = struct.unpack_from('<H', cdata, 6)[0] & 0x3FFF
                meta['height'] = struct.unpack_from('<H', cdata, 8)[0] & 0x3FFF
                meta['compression'] = 'lossy (VP8)'
        elif ctype == b'VP8X' and len(cdata) >= 10:
            meta['width'] = int.from_bytes(cdata[4:7], 'little') + 1
            meta['height'] = int.from_bytes(cdata[7:10], 'little') + 1
            meta['compression'] = 'extended (VP8X)'
        elif ctype == b'EXIF' and cdata:
            _merge_tiff_into(meta, _parse_tiff(cdata))
        elif ctype == b'XMP ' and cdata:
            xmp = _parse_xmp(cdata.decode('utf-8', errors='replace'))
            if xmp:
                meta['xmp'] = xmp
        pos += 8 + csize + (csize & 1)
    meta['chunks'] = chunks
    if 'width' not in meta:
        meta['error'] = 'no dimension chunk (VP8/VP8L/VP8X) found'
    return meta


# ---------------------------------------------------------------------------
# Strings extraction
# ---------------------------------------------------------------------------

def _is_noise(text: str) -> bool:
    """True for pure-repetition strings ('AAAAAA', 'abababab', '......')."""
    if len(set(text)) <= 1:
        return True
    if len(set(text)) == 2 and len(text) > 8:
        return text[:2] * ((len(text) + 1) // 2) == text + text[0]
    return False


def strings_report(data: bytes, min_len: int = 6) -> List[Dict[str, Any]]:
    """
    Extract embedded printable strings with their offsets.

    ASCII runs and UTF-16LE runs (``char\\x00`` pairs) are both harvested -
    UTF-16 matters because Windows tools smuggle metadata into slack space
    in UTF-16LE. Results are capped at 400 entries and pure-repetition noise
    ('AAAAAA', 'ababab') is skipped. Never raises.

    Returns a list of ``{'offset', 'encoding', 'value'}`` dicts sorted by
    offset.
    """
    if not isinstance(data, (bytes, bytearray)) or not data:
        return []
    buffer = bytes(data)
    found: List[Dict[str, Any]] = []
    ascii_re = re.compile(rb'[\x20-\x7e]{%d,}' % max(1, min_len))
    utf16_re = re.compile(rb'(?:[\x20-\x7e]\x00){%d,}' % max(1, min_len))
    for match in ascii_re.finditer(buffer):
        value = match.group().decode('ascii')
        if _is_noise(value):
            continue
        found.append({'offset': match.start(), 'encoding': 'ascii', 'value': value})
        if len(found) >= 400:
            return found
    for match in utf16_re.finditer(buffer):
        value = match.group().decode('utf-16-le')
        if _is_noise(value):
            continue
        found.append({'offset': match.start(), 'encoding': 'utf-16le', 'value': value})
        if len(found) >= 400:
            break
    found.sort(key=lambda item: item['offset'])
    return found[:400]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def read_metadata(path_or_bytes: Any) -> Dict[str, Any]:
    """
    Parse image metadata for a JPEG, PNG, GIF, BMP or WebP input.

    Args:
        path_or_bytes: filesystem path (str / os.PathLike) or raw bytes.

    Returns:
        A format-specific dict (with ``'format'`` key). Unsupported or
        corrupt inputs yield ``{'format': 'unknown', 'error': ...}`` plus a
        first-16-bytes hex preview and extracted printable strings - never
        an exception.
    """
    data, load_error = _load_bytes(path_or_bytes)
    if load_error:
        return {'format': 'unknown', 'error': load_error}
    if not data:
        return {'format': 'unknown', 'error': 'empty input'}
    kind = _sniff_format(data)
    if kind == 'jpeg':
        result = _parse_jpeg(data)
    elif kind == 'png':
        result = _parse_png(data)
    elif kind == 'gif':
        result = _parse_gif(data)
    elif kind == 'bmp':
        result = _parse_bmp(data)
    elif kind == 'webp':
        result = _parse_webp(data)
    else:
        return {
            'format': 'unknown',
            'error': 'unsupported format',
            'magic_hex': binascii.hexlify(data[:16]).decode('ascii'),
            'strings': strings_report(data)[:40],
        }
    if result.get('error') and 'parsed' not in result:
        # Contract: malformed/truncated input -> {'error': ..., 'parsed': partial}
        result['parsed'] = {key: value for key, value in result.items()
                            if key not in ('error', 'parsed', 'thumbnail')}
    return result


def _camera_summary(exif: Dict[str, Any]) -> Optional[str]:
    """Combine Make + Model (+ lens) into 'Apple iPhone 13 Pro' style text."""
    make = str(exif.get('Make') or '').strip()
    model = str(exif.get('Model') or '').strip()
    summary = ''
    if make and model:
        summary = model if model.lower().startswith(make.lower()) else f'{make} {model}'
    else:
        summary = make or model
    lens = str(exif.get('LensModel') or '').strip()
    if lens and lens != model:
        summary = f'{summary} (lens: {lens})' if summary else f'lens: {lens}'
    return summary.strip() or None


def _timezone_note(exif: Dict[str, Any]) -> Optional[str]:
    """Turn OffsetTime* tags into an analyst hint about the camera timezone."""
    offset = None
    for key in ('OffsetTimeOriginal', 'OffsetTimeDigitized', 'OffsetTime'):
        value = exif.get(key)
        if isinstance(value, str) and re.match(r'^[+-]\d{2}:\d{2}$', value.strip()):
            offset = value.strip()
            break
    if offset is None:
        return None
    hours = int(offset[1:3])
    if offset[0] == '-':
        hours = -hours
    regions = {-8: 'US Pacific / Canada', -5: 'US Eastern / Peru', 0: 'UK / GMT',
               1: 'Central Europe / West Africa', 2: 'Eastern Europe / South Africa',
               3: 'Moscow / East Africa', 4: 'Gulf states', 5: 'Pakistan',
               5.5: 'India', 8: 'China / Singapore / Philippines', 9: 'Japan / Korea'}
    hint = regions.get(hours, 'unknown region')
    return (f"Timestamp offset {offset} suggests the camera clock was set to "
            f"UTC{offset} ({hint}) - narrows the photographer's location.")


def analyze(path_or_bytes: Any) -> Dict[str, Any]:
    """
    One-shot, local-only metadata triage for an image.

    Combines the container-specific metadata (via :func:`read_metadata`),
    friendly EXIF, GPS (decimal + DMS + 'lat, lon' coords string ready for
    the ObscuraLens coords tracker), a camera summary, timeline hints,
    interesting strings, file hashes and actionable ``osint_notes`` for the
    analyst. Malformed inputs produce ``{'error': ..., 'parsed': ...}``
    partials - never an exception. Nothing leaves the calling process.
    """
    data, load_error = _load_bytes(path_or_bytes)
    if load_error:
        return {'error': load_error, 'parsed': {}}
    if not data:
        return {'error': 'empty input', 'parsed': {}}
    meta = read_metadata(data)
    fmt = meta.get('format', 'unknown')
    exif = meta.get('exif') if isinstance(meta.get('exif'), dict) else {}
    exif = exif or {}
    gps = meta.get('gps') if isinstance(meta.get('gps'), dict) else {}
    xmp = meta.get('xmp') if isinstance(meta.get('xmp'), dict) else {}

    file_facts: Dict[str, Any] = {
        'size': len(data),
        'sha256': hashlib.sha256(data).hexdigest(),
        'md5': hashlib.md5(data).hexdigest(),
        'magic': binascii.hexlify(data[:16]).decode('ascii'),
        'format': fmt,
    }
    for key in ('width', 'height'):
        if isinstance(meta.get(key), int):
            file_facts[key] = meta[key]
    for key in ('trailing_after_eoi', 'trailing_after_iend', 'trailing_after_trailer'):
        if meta.get(key):
            file_facts[key] = meta[key]

    # Timeline hints (ISO 8601 datetimes from every source we can find).
    timeline: List[str] = []
    for key in ('DateTimeOriginal', 'DateTimeDigitized', 'DateTime'):
        stamp = _iso_datetime(exif.get(key))
        if stamp and stamp not in timeline:
            timeline.append(stamp)
    if isinstance(gps.get('GPSTimeStamp'), str) and isinstance(gps.get('GPSDateStamp'), str):
        datestamp = str(gps['GPSDateStamp']).replace(':', '-')
        stamp = _iso_datetime(f'{datestamp} {gps["GPSTimeStamp"]}')
        if stamp and stamp not in timeline:
            timeline.append(f'{stamp}Z (GPS)')
    if isinstance(meta.get('modification_time'), str):
        timeline.append(meta['modification_time'])
    for key in ('CreateDate', 'ModifyDate'):
        if isinstance(xmp.get(key), str):
            stamp = str(xmp[key]).replace('Z', '')
            if re.match(r'^\d{4}-\d{2}-\d{2}T', stamp) and stamp not in timeline:
                timeline.append(stamp)

    software = exif.get('Software') or xmp.get('CreatorTool') \
        or (meta.get('software') if isinstance(meta, dict) else None)
    artist = exif.get('Artist') or exif.get('CameraOwnerName') or xmp.get('creator') \
        or (meta.get('author') if isinstance(meta, dict) else None)

    interesting: List[str] = []
    if gps.get('coords'):
        interesting.append('gps_coordinates')
    if artist:
        interesting.append('artist')
    for key in ('BodySerialNumber', 'LensSerialNumber', 'ImageUniqueID'):
        if exif.get(key):
            interesting.append('serial_number')
            break
    if meta.get('thumbnail') or meta.get('ifd1'):
        interesting.append('thumbnail_data')
    if meta.get('comments') or meta.get('comment'):
        interesting.append('comment')
    if xmp:
        interesting.append('xmp')
    if meta.get('photoshop') and meta['photoshop'].get('iptc'):
        interesting.append('iptc')
    if exif.get('MakerNote'):
        interesting.append('maker_note')
    if software:
        interesting.append('software')
    if exif.get('Copyright'):
        interesting.append('copyright')
    if exif.get('UserComment'):
        interesting.append('user_comment')

    all_strings = strings_report(data)
    interesting_strings = [item for item in all_strings
                           if _INTERESTING_STRING_RE.search(item['value'])][:40]

    osint_notes: List[str] = []
    if gps.get('coords'):
        osint_notes.append(f"GPS coordinates present: {gps['coords']} - paste into "
                           'the coords tracker (POST /api/tools/coords) for reverse '
                           'geocoding and country attribution.')
    timezone = _timezone_note(exif)
    if timezone:
        osint_notes.append(timezone)
    summary = _camera_summary(exif)
    if summary:
        osint_notes.append(f'Camera: {summary}.')
    if software:
        osint_notes.append(f'Software: {software} - editing-tool history; compare with '
                           'capture timestamps for post-processing evidence.')
    if artist:
        osint_notes.append(f'Artist / owner: {artist} - possible identity lead.')
    serial = exif.get('BodySerialNumber')
    unique_id = exif.get('ImageUniqueID')
    if serial or unique_id:
        parts = [str(serial) if serial else '', str(unique_id) if unique_id else '']
        osint_notes.append('Device identifiers: ' + ', '.join(p for p in parts if p)
                           + ' - unique to this camera body.')
    if meta.get('thumbnail'):
        osint_notes.append(f"Embedded EXIF thumbnail ({meta['thumbnail'].get('thumbnail_size')}"
                           ' bytes) - thumbnails often show the pre-crop, pre-edit original.')
    if meta.get('comments') or meta.get('comment'):
        first = str(meta.get('comment') or '').strip().splitlines()[0][:80]
        osint_notes.append(f'Embedded comment: {first!r}.')
    if xmp:
        osint_notes.append(f'XMP packet present ({meta.get("xmp_size", 0)} bytes) - '
                           'editing toolchain history (Adobe/Photoshop fields).')
    if gps.get('altitude_m') is not None:
        osint_notes.append(f"Altitude {gps['altitude_m']} m "
                           f"({'below' if gps['altitude_m'] < 0 else 'above'} sea level).")
    for key in ('trailing_after_eoi', 'trailing_after_iend'):
        if meta.get(key):
            osint_notes.append(f'{meta[key]} bytes of data appended after image end '
                               f'({"EOI" if key == "trailing_after_eoi" else "IEND"}) - '
                               'classic payload smuggle; check with the steganography '
                               'analyzer.')
    if not osint_notes:
        osint_notes.append('No notable metadata findings - image appears scrubbed '
                           'or synthetic.')

    result: Dict[str, Any] = {
        'format': fmt,
        'file': file_facts,
        'exif': exif,
        'gps': gps,
        'camera_summary': summary,
        'timeline': timeline,
        'software': software,
        'artist': artist,
        'interesting': interesting,
        'strings': interesting_strings,
        'osint_notes': osint_notes,
    }
    if meta.get('thumbnail'):
        result['thumbnail'] = meta['thumbnail']
    if meta.get('error'):
        result['error'] = meta['error']
        result['parsed'] = {key: value for key, value in meta.items()
                            if key not in ('error', 'thumbnail')}
    if meta.get('xmp'):
        result['xmp'] = meta['xmp']
    if meta.get('comments'):
        result['comments'] = meta['comments']
    if fmt == 'unknown':
        result['magic_hex'] = meta.get('magic_hex', '')
        result['all_strings'] = all_strings[:40]
    return result
