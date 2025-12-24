"""
Apple X-Apple-I-FD-Client-Info Fingerprint Generator

Reverse-engineered from Apple's authentication JavaScript.
This generates the fingerprint used in Apple ID authentication requests.

СТАТУС: В РАЗРАБОТКЕ - fingerprint генерируется, но может отличаться от браузерного

Usage:
    from apple_fingerprint import generate_fingerprint
    
    fingerprint = generate_fingerprint()
    # Returns JSON string like: {"U":"Mozilla/5.0...","L":"en-US","Z":"GMT+03:00","V":"1.1","F":"..."}
"""

import json
import time
import random
import string
from datetime import datetime
from urllib.parse import quote

# Alphabet for encoding (base64-like)
ALPHABET = ".0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"

# Huffman-like encoding table from Apple's JS
# Maps character codes to [bits, value] pairs
ENCODING_TABLE = {
    1: [4, 15], 110: [8, 239], 74: [8, 238], 57: [7, 118], 56: [7, 117],
    71: [8, 233], 25: [8, 232], 101: [5, 28], 104: [7, 111], 4: [7, 110],
    105: [6, 54], 5: [7, 107], 109: [7, 106], 103: [9, 423], 82: [9, 422],
    26: [8, 210], 6: [7, 104], 46: [6, 51], 97: [6, 50], 111: [6, 49],
    7: [7, 97], 45: [7, 96], 59: [5, 23], 15: [7, 91], 11: [8, 181],
    72: [8, 180], 27: [8, 179], 28: [8, 178], 16: [7, 88], 88: [10, 703],
    113: [11, 1405], 89: [12, 2809], 107: [13, 5617], 90: [14, 11233],
    42: [15, 22465], 64: [16, 44929], 0: [16, 44928], 81: [9, 350],
    29: [8, 174], 118: [8, 173], 30: [8, 172], 98: [8, 171], 12: [8, 170],
    99: [7, 84], 117: [6, 41], 112: [6, 40], 102: [9, 319], 68: [9, 318],
    31: [8, 158], 100: [7, 78], 84: [6, 38], 55: [6, 37], 17: [7, 73],
    8: [7, 72], 9: [7, 71], 77: [7, 70], 18: [7, 69], 65: [7, 68],
    48: [6, 33], 116: [6, 32], 10: [7, 63], 121: [8, 125], 78: [8, 124],
    80: [7, 61], 69: [7, 60], 119: [7, 59], 13: [8, 117], 79: [8, 116],
    19: [7, 57], 67: [7, 56], 114: [6, 27], 83: [6, 26], 115: [6, 25],
    14: [6, 24], 122: [8, 95], 95: [8, 94], 76: [7, 46], 24: [7, 45],
    37: [7, 44], 50: [5, 10], 51: [5, 9], 108: [6, 17], 22: [7, 33],
    120: [8, 65], 66: [8, 64], 21: [7, 31], 106: [7, 30], 47: [6, 14],
    53: [5, 6], 49: [5, 5], 86: [8, 39], 85: [8, 38], 23: [7, 18],
    75: [7, 17], 20: [7, 16], 2: [5, 3], 73: [8, 23], 43: [9, 45],
    87: [9, 44], 70: [7, 10], 3: [6, 4], 52: [5, 1], 54: [5, 0]
}

# Compression patterns from Apple's JS - these get replaced with chr(1) to chr(31)
COMPRESSION_PATTERNS = [
    "%20", ";;;", "%3B", "%2C", "und", "fin", "ed;", "%28", "%29", "%3A",
    "/53", "ike", "Web", "0;", ".0", "e;", "on", "il", "ck", "01",
    "in", "Mo", "fa", "00", "32", "la", ".1", "ri", "it", "%u", "le"
]


def encode_string(s: str) -> str:
    """
    Encode string using Apple's Huffman-like encoding.
    This is the 'l' function from Apple's JS.
    """
    result = ""
    r = 0  # bit buffer
    i = 0  # bits in buffer
    
    def add_bits(bits, value):
        nonlocal r, i, result
        r = (r << bits) | value
        i += bits
        while i >= 6:
            char_idx = (r >> (i - 6)) & 63
            result += ALPHABET[char_idx]
            r ^= char_idx << (i - 6)
            i -= 6
    
    # Add length info (first two 6-bit chunks encode length)
    add_bits(6, ((len(s) & 7) << 3) | 0)
    add_bits(6, (len(s) & 56) | 1)
    
    # Encode each character
    for char in s:
        code = ord(char)
        if code not in ENCODING_TABLE:
            return None
        bits, value = ENCODING_TABLE[code]
        add_bits(bits, value)
    
    # Add terminator (char code 0)
    add_bits(*ENCODING_TABLE[0])
    
    # Flush remaining bits
    if i > 0:
        add_bits(6 - i, 0)
    
    return result


def compress_and_checksum(data: str) -> str:
    """
    Compress data using pattern substitution and add CRC16 checksum.
    This is the 'd' function from Apple's JS.
    """
    # Apply compression patterns - replace common strings with control chars
    compressed = data
    for idx, pattern in enumerate(COMPRESSION_PATTERNS):
        compressed = compressed.replace(pattern, chr(idx + 1))
    
    # Encode using Huffman-like encoding
    encoded = encode_string(compressed)
    if encoded is None:
        return data
    
    # Calculate CRC16 checksum on ORIGINAL data (not compressed)
    checksum = 65535
    for char in data:
        checksum = ((checksum >> 8) | (checksum << 8)) & 65535
        checksum ^= ord(char) & 255
        checksum ^= (checksum & 255) >> 4
        checksum ^= (checksum << 12) & 65535
        checksum ^= ((checksum & 255) << 5) & 65535
    checksum &= 65535
    
    # Append 3-character checksum to encoded result
    result = encoded
    result += ALPHABET[checksum >> 12]
    result += ALPHABET[(checksum >> 6) & 63]
    result += ALPHABET[checksum & 63]
    
    return result


def generate_browser_data(user_agent: str = None, screen_width: int = 1920, 
                          screen_height: int = 1080, color_depth: int = 24,
                          timezone_offset: int = None) -> str:
    """
    Generate browser fingerprint data string.
    
    This simulates what Apple's JavaScript collects from the browser.
    The data is collected from ~70 different browser properties.
    """
    if user_agent is None:
        user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    
    # Current timestamps
    now = datetime.now()
    utc_time = int(time.time() * 1000)
    
    # Timezone calculations (like Apple's JS)
    if timezone_offset is None:
        timezone_offset = -int(time.timezone / 60)  # in minutes
        if time.daylight:
            timezone_offset = -int(time.altzone / 60)
    
    # Winter/Summer timezone offsets (Jan 15 and Jul 15, 2005)
    winter_offset = 180  # Example: GMT+3
    summer_offset = 180  # Example: GMT+3 (no DST)
    
    # Build data parts - this matches Apple's JS array of ~70 functions
    # Each function returns a value that gets escaped and joined with ;
    data_parts = []
    
    # TF1, 020 markers
    data_parts.append("TF1")  # Marker
    data_parts.append("020")  # Version
    
    # Script engine info (empty for non-IE)
    data_parts.append("")  # ScriptEngineMajorVersion
    data_parts.append("")  # ScriptEngineMinorVersion  
    data_parts.append("")  # ScriptEngineBuildVersion
    
    # ActiveX component checks (empty for non-IE) - ~12 items
    for _ in range(12):
        data_parts.append("")
    
    # Navigator properties
    data_parts.append("")  # productSub/appMinorVersion
    data_parts.append("")  # empty
    data_parts.append("")  # empty
    data_parts.append("")  # oscpu/cpuClass
    data_parts.append("")  # empty
    data_parts.append("")  # empty
    data_parts.append("")  # empty
    data_parts.append("")  # empty
    data_parts.append("")  # language/userLanguage - will be set separately
    
    # More empty slots
    for _ in range(5):
        data_parts.append("")
    
    # Timezone related
    data_parts.append("true" if winter_offset != summer_offset else "false")  # DST check
    data_parts.append("false")  # isDST
    data_parts.append(str(utc_time))  # @UTC@ placeholder - will be replaced
    data_parts.append(str(-timezone_offset / 60))  # timezone offset in hours
    
    # Locale string
    data_parts.append(now.strftime("%m/%d/%Y, %I:%M:%S %p"))  # toLocaleString
    
    # More empty slots
    for _ in range(5):
        data_parts.append("")
    
    # Plugin info (Acrobat, Flash, QuickTime, Java, Director, Office)
    for _ in range(6):
        data_parts.append("")
    
    # Screen properties
    data_parts.append(str(screen_width))   # screen.width
    data_parts.append(str(screen_height))  # screen.height
    data_parts.append(str(color_depth))    # screen.colorDepth
    
    # More browser info
    data_parts.append("")  # empty
    data_parts.append(str(utc_time))  # @CT@ placeholder
    
    # Plugin detection results (empty for modern browsers)
    for _ in range(20):
        data_parts.append("")
    
    # Font height test
    data_parts.append("20")  # span offsetHeight
    
    # More empty slots
    for _ in range(15):
        data_parts.append("")
    
    # Version marker
    data_parts.append("5.6.1-0")
    
    # Final empty
    data_parts.append("")
    
    # Build final string - escape each part and join with ;
    escaped_parts = []
    for part in data_parts:
        escaped_parts.append(quote(str(part), safe=''))
    
    raw_data = ";".join(escaped_parts) + ";"
    
    # Replace @UTC@ and @CT@ placeholders
    raw_data = raw_data.replace(quote("@UTC@"), str(utc_time))
    raw_data = raw_data.replace(quote("@CT@"), str(int(time.time() * 1000) - utc_time))
    
    return raw_data


def generate_f_field(user_agent: str = None, screen_width: int = 1920,
                     screen_height: int = 1080) -> str:
    """
    Generate the F field for X-Apple-I-FD-Client-Info.
    
    This is the main fingerprint value that Apple uses.
    """
    # Generate browser data (already URL-encoded internally)
    browser_data = generate_browser_data(
        user_agent=user_agent,
        screen_width=screen_width,
        screen_height=screen_height
    )
    
    # Compress and add checksum
    f_value = compress_and_checksum(browser_data)
    
    return f_value


def generate_fingerprint(
    user_agent: str = None,
    language: str = None,
    timezone: str = None
) -> str:
    """
    Generate complete X-Apple-I-FD-Client-Info header value.
    
    Args:
        user_agent: Browser user agent string
        language: Browser language (e.g., "en-US", "ru-RU")
        timezone: Timezone string (e.g., "GMT+03:00")
    
    Returns:
        JSON string for X-Apple-I-FD-Client-Info header
    """
    if user_agent is None:
        user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    
    if language is None:
        language = "en-US"
    
    if timezone is None:
        # Calculate from current timezone
        offset = -time.timezone // 60  # in minutes
        if time.daylight:
            offset = -time.altzone // 60
        
        hours = abs(offset) // 60
        minutes = abs(offset) % 60
        sign = "+" if offset >= 0 else "-"
        timezone = f"GMT{sign}{hours:02d}:{minutes:02d}"
    
    # Generate F field
    f_value = generate_f_field(user_agent)
    
    # Build fingerprint object
    fingerprint = {
        "U": user_agent,
        "L": language,
        "Z": timezone,
        "V": "1.1",
        "F": f_value
    }
    
    return json.dumps(fingerprint)


def generate_simple_fingerprint(
    user_agent: str = None,
    language: str = "en-US",
    timezone: str = "GMT+03:00"
) -> str:
    """
    Generate a simple fingerprint without the F field.
    
    Some Apple endpoints accept fingerprints without the F field.
    """
    if user_agent is None:
        user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    
    fingerprint = {
        "U": user_agent,
        "L": language,
        "Z": timezone,
        "V": "1.1"
    }
    
    return json.dumps(fingerprint)


if __name__ == "__main__":
    print("=== Apple Fingerprint Generator ===\n")
    
    # Generate fingerprint
    fp = generate_fingerprint()
    print("Generated fingerprint:")
    print(fp)
    
    # Parse and show
    print("\nParsed:")
    data = json.loads(fp)
    for key, value in data.items():
        if len(str(value)) > 50:
            print(f"  {key}: {str(value)[:50]}...")
        else:
            print(f"  {key}: {value}")
