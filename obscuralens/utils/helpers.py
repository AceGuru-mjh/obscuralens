"""
Helper utilities for output formatting and display.

Every rendering helper degrades gracefully: Unicode falls back to ASCII on
legacy code pages, and ANSI colours are disabled automatically when the output
is not a terminal, when NO_COLOR is set, or when OBSCURALENS_NO_COLOR is set.
"""

import json
import os
import sys
from typing import Any, Dict, List, Optional

from tabulate import tabulate

from .. import __version__

_UNICODE_PROBE = '\u2713\u2717\u2550\u2551\u2500\u2022\u2192'


def _encoding_supports(chars: str) -> bool:
    """Check whether an encoding can represent the given characters."""
    encoding = getattr(sys.stdout, 'encoding', None) or 'ascii'
    try:
        chars.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def _setup_console() -> bool:
    """
    Try to put the terminal into UTF-8 mode and report whether it worked.

    On Windows the default code page is often GBK/cp936, which cannot encode
    '✓' or box-drawing characters. We ask the console to switch to UTF-8
    (code page 65001) and reconfigure the Python streams to match.

    Returns True when rich Unicode output is safe to use.
    """
    switched = False

    if os.name == 'nt':
        # Only worth trying when writing to a real terminal.
        try:
            is_tty = sys.stdout.isatty()
        except (AttributeError, ValueError):
            is_tty = False

        if is_tty:
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                if kernel32.SetConsoleOutputCP(65001):
                    switched = True
                try:
                    kernel32.SetConsoleCP(65001)
                except Exception:
                    pass
            except Exception:
                switched = False

    for stream_name in ('stdout', 'stderr'):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, 'reconfigure', None)
        if callable(reconfigure):
            try:
                reconfigure(encoding='utf-8', errors='replace')
                switched = True
            except (ValueError, OSError, AttributeError):
                pass

    # Trust the console only if the stream itself can encode the characters.
    return switched and _encoding_supports(_UNICODE_PROBE)


def _stdout_is_tty() -> bool:
    try:
        return bool(sys.stdout.isatty())
    except (AttributeError, ValueError):
        return False


_UNICODE_OK = _setup_console()

# Symbols used across the UI. Fall back to ASCII on legacy code pages.
if _UNICODE_OK:
    SYM_OK = '✓'
    SYM_FAIL = '✗'
    SYM_WARN = '!'
    SYM_INFO = 'i'
    SYM_BULLET = '•'
    SYM_ARROW = '→'
    BOX_H = '═'
    BOX_V = '║'
    BOX_TL = '╔'
    BOX_TR = '╗'
    BOX_BL = '╚'
    BOX_BR = '╝'
    BOX_DIV = '╠'
    BOX_RULE = '─'
else:
    SYM_OK = '[OK]'
    SYM_FAIL = '[X]'
    SYM_WARN = '[!]'
    SYM_INFO = '[i]'
    SYM_BULLET = '*'
    SYM_ARROW = '->'
    BOX_H = '='
    BOX_V = '|'
    BOX_TL = '+'
    BOX_TR = '+'
    BOX_BL = '+'
    BOX_BR = '+'
    BOX_DIV = '+'
    BOX_RULE = '-'


def _colors_requested() -> bool:
    """Colour output unless disabled by env var or a non-interactive stream."""
    if os.environ.get('NO_COLOR') or os.environ.get('OBSCURALENS_NO_COLOR'):
        return False
    return _stdout_is_tty()


# Color codes
class Colors:
    """ANSI color codes (blanked out when colours are disabled)."""
    BLACK = '\033[30m'
    RED = '\033[1;31m'
    GREEN = '\033[1;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[1;34m'
    MAGENTA = '\033[1;35m'
    CYAN = '\033[1;36m'
    WHITE = '\033[1;37m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def set_colors(enabled: bool) -> None:
    """Force colours on or off for this process (used by --color/--no-color)."""
    for name in ('BLACK', 'RED', 'GREEN', 'YELLOW', 'BLUE', 'MAGENTA',
                 'CYAN', 'WHITE', 'RESET', 'BOLD', 'UNDERLINE'):
        if not enabled:
            setattr(Colors, name, '')
        else:
            setattr(Colors, name, _COLOR_CODES[name])


_COLOR_CODES = {
    'BLACK': '\033[30m',
    'RED': '\033[1;31m',
    'GREEN': '\033[1;32m',
    'YELLOW': '\033[1;33m',
    'BLUE': '\033[1;34m',
    'MAGENTA': '\033[1;35m',
    'CYAN': '\033[1;36m',
    'WHITE': '\033[1;37m',
    'RESET': '\033[0m',
    'BOLD': '\033[1m',
    'UNDERLINE': '\033[4m',
}

if not _colors_requested():
    set_colors(False)


def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    """Print the ObscuraLens banner"""
    banner = f"""
{Colors.CYAN}
   ________               __      ______
  / ____/ /_  ____  _____/ /_    /_  __/________ ______/ /__
 / / __/ __ \\/ __ \\/ ___/ __/_____/ / / ___/ __ `/ ___/ //_/
/ /_/ / / / / /_/ (__  ) /_/_____/ / / /  / /_/ / /__/ ,<
\\____/_/ /_/\\____/____/\\__/     /_/ /_/   \\__,_/\\___/_/|_|
{Colors.RESET}
{Colors.GREEN}[ + ]  O B S C U R A L E N S  v{__version__}  [ + ]{Colors.RESET}
{Colors.YELLOW}[ + ]  Advanced OSINT Tool  [ + ]{Colors.RESET}
    """
    print(banner)


def print_success(message: str):
    """Print a success message"""
    print(f"{Colors.GREEN}{SYM_OK} {message}{Colors.RESET}")


def print_error(message: str):
    """Print an error message"""
    print(f"{Colors.RED}{SYM_FAIL} {message}{Colors.RESET}")


def print_warning(message: str):
    """Print a warning message"""
    print(f"{Colors.YELLOW}{SYM_WARN} {message}{Colors.RESET}")


def print_info(message: str):
    """Print an info message"""
    print(f"{Colors.CYAN}{SYM_INFO} {message}{Colors.RESET}")


def render_table(data: Any, headers: Optional[List[str]] = None) -> str:
    """Render tabular data to a grid table string (same rules as print_table)."""
    if not data:
        return ""

    table_data: List[List[Any]] = []

    if isinstance(data, dict):
        headers = headers or ['Key', 'Value']
        table_data = [[key, value] for key, value in data.items()]
    else:
        rows = list(data)
        if not rows:
            return ""
        if isinstance(rows[0], dict):
            headers = headers or list(rows[0].keys())
            table_data = [[item.get(header, '') for header in headers]
                          for item in rows]
        else:
            table_data = [list(row) for row in rows]
            if headers is None:
                headers = [str(i) for i in range(1, len(table_data[0]) + 1)]

    if not headers:
        return ""

    cleaned = [
        ['' if cell is None else str(cell) for cell in row]
        for row in table_data
    ]
    return tabulate(cleaned, headers=headers, tablefmt='grid')


def print_table(data: Any, headers: Optional[List[str]] = None):
    """
    Print tabular data.

    Accepts:
      * a list of mappings (headers default to the first mapping's keys),
      * a list/tuple of row sequences (e.g. [['Country', 'US'], ...]), or
      * a plain mapping (rendered as a two-column Key/Value table).
    """
    if not data:
        print_warning("No data to display")
        return
    rendered = render_table(data, headers)
    if not rendered:
        print_warning("No data to display")
        return
    print(rendered)


def print_json(data: Dict[str, Any], indent: int = 2):
    """
    Print data as formatted JSON

    Args:
        data: Dictionary to print
        indent: Indentation level
    """
    print(json.dumps(data, indent=indent, ensure_ascii=False))


def format_output(data: Dict[str, Any], output_format: str = 'table') -> str:
    """
    Format output data as a string.

    Args:
        data: Data to format
        output_format: Output format (table, json, csv)

    Returns:
        Formatted string
    """
    if output_format == 'json':
        return json.dumps(data, indent=2, ensure_ascii=False)

    if output_format == 'csv':
        import csv as _csv
        import io

        if isinstance(data, list) and data:
            buffer = io.StringIO()
            writer = _csv.DictWriter(buffer, fieldnames=list(data[0].keys()))
            writer.writeheader()
            writer.writerows(data)
            return buffer.getvalue().rstrip('\n')
        return "No data"

    # table format
    if isinstance(data, list):
        if data:
            headers = list(data[0].keys()) if isinstance(data[0], dict) else None
            return tabulate(data, headers=headers, tablefmt='grid')
        return "No data"

    return tabulate([[k, str(v)] for k, v in data.items()],
                    headers=['Key', 'Value'], tablefmt='grid')


def print_progress(message: str, current: int, total: int):
    """
    Print a progress bar

    Args:
        message: Progress message
        current: Current progress
        total: Total items
    """
    percent = (current / total) * 100
    bar_length = 40
    filled = int(bar_length * current // total)
    bar = '█' * filled + '░' * (bar_length - filled)

    sys.stdout.write(f'\r{Colors.CYAN}[{bar}] {percent:.1f}% {message}{Colors.RESET}')
    sys.stdout.flush()

    if current == total:
        print()


def print_section(title: str):
    """Print a section header"""
    print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.WHITE}{title.center(60)}{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")


def print_subsection(title: str):
    """Print a subsection header"""
    print(f"\n{Colors.YELLOW}{BOX_RULE*40}{Colors.RESET}")
    print(f"{Colors.BOLD}{title}{Colors.RESET}")
    print(f"{Colors.YELLOW}{BOX_RULE*40}{Colors.RESET}")


def confirm_action(message: str) -> bool:
    """
    Ask for user confirmation

    Args:
        message: Confirmation message

    Returns:
        True if confirmed, False otherwise
    """
    response = input(f"{Colors.YELLOW}{message} [y/N]: {Colors.RESET}")
    return response.lower() in ('y', 'yes')


def get_input(prompt: str, required: bool = True) -> str:
    """
    Get user input with validation

    Args:
        prompt: Input prompt
        required: Whether input is required

    Returns:
        User input
    """
    while True:
        value = input(f"{Colors.GREEN}{prompt}: {Colors.RESET}").strip()
        if value or not required:
            return value
        print_error("This field is required")
