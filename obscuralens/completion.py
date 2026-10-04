"""
Shell completion script generation for the ObscuraLens CLI.

The module walks the *real* command table — the argparse tree built by
:func:`obscuralens.commands.build_parser` — and renders self-contained
completion scripts for bash, zsh and fish. No external completion helper
libraries are required: the bash script is a hand-rolled word generator, the
zsh script uses only ``compadd``/``_describe``/``_arguments`` from the stock
completion system, and the fish script is a plain list of ``complete`` calls.

Users never import this module directly; the CLI surface is::

    obscuralens completion bash
    obscuralens completion zsh
    obscuralens completion fish

each printing the script to stdout plus an install hint on stderr (use
``--stdout`` to suppress the hint, or ``-o FILE`` to write the script to a
file). Programmatically, :func:`write_completion` is the single entry point.

Robustness: argparse internals (``_actions``, ``_SubParsersAction.choices``,
``_choices_actions``) are private API and may drift. Every access is guarded
and any failure degrades to an empty command tree plus a captured warning
(see :func:`last_warnings`) instead of a broken script or an exception —
completion is a convenience feature and must never take the CLI down.

Determinism: commands are emitted sorted by command path, options sorted by
their flag spelling, so regenerating a script always produces byte-identical
output (safe for packaging and diffing).
"""

import argparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    'SHELLS',
    'CommandSpec',
    'bash_completion',
    'command_tree',
    'fish_completion',
    'install_hint',
    'last_warnings',
    'write_completion',
    'zsh_completion',
]

#: Shells with a generated completion script, in canonical order.
SHELLS = ('bash', 'zsh', 'fish')

# argparse action types that never consume a value on the command line.
_NO_VALUE_ACTIONS = (
    argparse._StoreTrueAction,
    argparse._StoreFalseAction,
    argparse._StoreConstAction,
    argparse._AppendConstAction,
    argparse._CountAction,
    argparse._HelpAction,
    argparse._VersionAction,
)

# Warnings captured by the last command_tree() walk (never raised).
_WARNINGS: List[str] = []


@dataclass
class CommandSpec:
    """
    One CLI command (leaf or group) discovered on the real parser.

    Attributes:
        path: the command path, e.g. ``('watch', 'add')`` for
            ``obscuralens watch add``. The empty tuple is never produced;
            root-level flags are handled by the generators themselves.
        help: the help string declared with ``add_parser(..., help=...)``.
        positionals: declaration-ordered dicts ``{'dest', 'help',
            'choices'}`` for positional arguments (``choices`` is ``None``
            unless the parser restricted the values, like the ``shell``
            argument of ``obscuralens completion``).
        options: sorted dicts ``{'flags', 'help', 'choices', 'metavar',
            'takes_value'}`` for the command's options; ``flags`` is the
            tuple of spellings (``('-f', '--format')``), ``choices`` the
            argparse choices when present, ``metavar`` the display name for
            the option's value and ``takes_value`` False for flag options
            such as ``--no-cache``.
    """

    path: Tuple[str, ...] = ()
    help: str = ''
    positionals: List[Dict[str, Any]] = field(default_factory=list)
    options: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def name(self) -> str:
        """The final path element (the command's own name)."""
        return self.path[-1] if self.path else ''

    def flag_words(self) -> List[str]:
        """Flat, deduplicated list of every option spelling, sorted."""
        words: List[str] = []
        for option in self.options:
            for flag in option['flags']:
                if flag not in words:
                    words.append(flag)
        return sorted(words)


# ---------------------------------------------------------------------------
# Parser introspection
# ---------------------------------------------------------------------------

def command_tree() -> List[CommandSpec]:
    """
    Walk the parser built by ``obscuralens.commands.build_parser()``.

    Returns:
        One :class:`CommandSpec` per command and per nested subcommand
        (groups like ``watch``/``case``/``pipeline``/``tools``/``analytics``
        /``notify``/``automation`` appear both as their own spec and as the
        parent of their children), sorted by command path. When the parser
        cannot be introspected — missing subparsers, renamed internals, a
        build failure — an empty list is returned and the reason is
        available through :func:`last_warnings`. This function never raises.
    """
    _WARNINGS.clear()
    try:
        return _walk_parser_tree()
    except Exception as exc:  # private argparse internals drifted
        _WARNINGS.append(f'command_tree failed: {type(exc).__name__}: {exc}')
        return []


def last_warnings() -> List[str]:
    """Warnings captured by the most recent :func:`command_tree` call."""
    return list(_WARNINGS)


def _walk_parser_tree() -> List[CommandSpec]:
    """Do the actual walk; only called inside command_tree's try block."""
    from . import commands  # imported lazily so tests can monkeypatch it

    try:
        parser = commands.build_parser()
    except Exception as exc:
        _WARNINGS.append(f'build_parser failed: {type(exc).__name__}: {exc}')
        return []

    specs: List[CommandSpec] = []
    choices = _subparser_choices(parser)
    helps = _subparser_helps(parser)
    for name in sorted(choices):
        specs.append(_spec_for((name,), choices[name], helps.get(name, '')))
        specs.extend(_walk_children((name,), choices[name]))
    specs.sort(key=lambda spec: spec.path)
    return specs


def _walk_children(path: Tuple[str, ...],
                   parser: argparse.ArgumentParser) -> List[CommandSpec]:
    """Collect the nested subcommands of one command, recursively."""
    specs: List[CommandSpec] = []
    choices = _subparser_choices(parser)
    if not choices:
        return specs
    helps = _subparser_helps(parser)
    for name in sorted(choices):
        specs.append(_spec_for(path + (name,), choices[name], helps.get(name, '')))
        specs.extend(_walk_children(path + (name,), choices[name]))
    return specs


def _subparsers_action(parser: Any) -> Optional[argparse._SubParsersAction]:
    """Find the one subparsers action of a parser, tolerating private API drift."""
    for candidate in getattr(parser, '_actions', None) or []:
        if isinstance(candidate, argparse._SubParsersAction):
            return candidate
    # Older/newer argparse layouts keep the group on the private attribute.
    group = getattr(parser, '_subparsers', None)
    for candidate in getattr(group, '_group_actions', None) or []:
        if isinstance(candidate, argparse._SubParsersAction):
            return candidate
    return None


def _subparser_choices(parser: Any) -> Dict[str, argparse.ArgumentParser]:
    """Map subcommand name -> subparser for one parser (empty when none)."""
    action = _subparsers_action(parser)
    if action is None:
        return {}
    choices = getattr(action, 'choices', None)
    return dict(choices) if isinstance(choices, dict) else {}


def _subparser_helps(parser: Any) -> Dict[str, str]:
    """Map subcommand name -> help text as declared via ``add_parser(help=...)``."""
    action = _subparsers_action(parser)
    if action is None:
        return {}
    helps: Dict[str, str] = {}
    for pseudo in getattr(action, '_choices_actions', None) or []:
        helps[getattr(pseudo, 'dest', '')] = getattr(pseudo, 'help', '') or ''
    return helps


def _spec_for(path: Tuple[str, ...], parser: Any,
              help_text: str) -> CommandSpec:
    """Build the CommandSpec for one (sub)parser: positionals + options."""
    positionals: List[Dict[str, Any]] = []
    options: List[Dict[str, Any]] = []

    for action in getattr(parser, '_actions', None) or []:
        if isinstance(action, argparse._SubParsersAction):
            continue  # the subcommand dispatch, not an argument
        if action.option_strings:
            choices = _action_choices(action)
            if not choices and any(f.endswith('kind')
                                   for f in action.option_strings):
                choices = _sdk_kinds()  # guarded enrichment from the SDK
            options.append({
                'flags': tuple(action.option_strings),
                'help': action.help or '',
                'choices': choices,
                'metavar': action.metavar or (action.dest or '').upper(),
                'takes_value': not isinstance(action, _NO_VALUE_ACTIONS),
            })
        else:
            positional_choices = _action_choices(action)
            if (not positional_choices and action.dest == 'shell'
                    and path[:1] == ('completion',)):
                positional_choices = list(SHELLS)  # shells the CLI accepts
            positionals.append({
                'dest': action.dest,
                'help': action.help or '',
                'choices': positional_choices,
            })

    options.sort(key=lambda option: ' '.join(option['flags']))
    return CommandSpec(path=tuple(path), help=help_text,
                       positionals=positionals, options=options)


def _action_choices(action: Any) -> Optional[List[str]]:
    """Stringify an action's choices (None when unrestricted)."""
    choices = getattr(action, 'choices', None)
    if not choices:
        return None
    try:
        return [str(value) for value in choices]
    except Exception:  # pragma: no cover - exotic choice values
        return None


def _sdk_kinds() -> List[str]:
    """Target kinds from ``obscuralens.sdk.models`` (empty when unimportable)."""
    try:
        from .sdk.models import KINDS
        return [str(kind) for kind in KINDS]
    except Exception:  # pragma: no cover - SDK optional at runtime
        return []


# ---------------------------------------------------------------------------
# Shared text helpers
# ---------------------------------------------------------------------------

def _version() -> str:
    """The ObscuraLens version string ('' when the package hides it)."""
    try:
        from . import __version__
        return str(__version__)
    except Exception:  # pragma: no cover - __version__ always exists today
        return ''


def _clean(text: str) -> str:
    """Collapse whitespace and strip — help strings go into one line."""
    return ' '.join(str(text or '').split())


def _sq(text: str) -> str:
    """Escape a string for a POSIX single-quoted context."""
    return str(text).replace("'", "'\\''")


def _zsh_help(text: str) -> str:
    """Strip characters that are structural inside zsh spec brackets."""
    cleaned = _clean(text)
    for character in '[]:(){}\'"\\`':
        cleaned = cleaned.replace(character, ' ')
    return ' '.join(cleaned.split())


def _choices_map(specs: List[CommandSpec]) -> Dict[str, List[str]]:
    """Map every option flag to its known values across the whole tree."""
    mapping: Dict[str, List[str]] = {}
    for spec in specs:
        for option in spec.options:
            values = option.get('choices')
            if not values:
                continue
            for flag in option['flags']:
                bucket = mapping.setdefault(flag, [])
                for value in values:
                    if value not in bucket:
                        bucket.append(value)
    return mapping


# ---------------------------------------------------------------------------
# bash
# ---------------------------------------------------------------------------

def bash_completion() -> str:
    """
    Return a complete, self-contained bash completion script.

    The script defines one ``__obscuralens_words`` function that understands
    the command path (top-level command plus one nested subcommand), offers
    the options of the deepest recognised command, the value sets of options
    with known choices (``--format``, ``--kind``, ...) and the subcommand
    names of groups like ``watch``. It needs nothing beyond bash itself;
    ``complete -o default`` falls back to filename completion for targets.

    Output is deterministic: commands and options are emitted sorted.
    """
    specs = command_tree()
    top = [spec for spec in specs if len(spec.path) == 1]
    children: Dict[str, List[CommandSpec]] = {}
    for spec in specs:
        if len(spec.path) == 2:
            children.setdefault(spec.path[0], []).append(spec)
    choices = _choices_map(specs)
    version = _version()

    lines: List[str] = [
        f'# bash completion for ObscuraLens{f" {version}" if version else ""}',
        '# Generated by `obscuralens completion bash` — do not edit by hand.',
        '',
        '__obscuralens_words() {',
        '    local cur prev sub sub2 i',
        '    cur="${COMP_WORDS[COMP_CWORD]}"',
        '    prev="${COMP_WORDS[COMP_CWORD-1]}"',
        '',
        '    # options with a known set of values',
        '    case "$prev" in',
    ]

    for flag in sorted(choices):
        values = ' '.join(_sq(value) for value in choices[flag])
        lines.append(f'        {_sq(flag)})')
        lines.append('            COMPREPLY=( '
                     f"$(compgen -W '{values}' -- \"$cur\") )")
        lines.append('            return 0')
        lines.append('            ;;')

    lines += [
        '    esac',
        '',
        '    # command path: first two non-option words after the program',
        '    sub=""; sub2=""',
        '    for (( i=1; i < COMP_CWORD; i++ )); do',
        '        case "${COMP_WORDS[i]}" in',
        '            -*) ;;',
        '            *) if [ -z "$sub" ]; then sub="${COMP_WORDS[i]}"',
        '               elif [ -z "$sub2" ]; then sub2="${COMP_WORDS[i]}"',
        '               fi ;;',
        '        esac',
        '    done',
        '',
        '    case "$sub" in',
        "        '')",
        '            case "$cur" in',
        "                -*) COMPREPLY=( $(compgen -W '--version' -- \"$cur\") ) ;;",
        '                *) COMPREPLY=( $(compgen -W '
        f"'{' '.join(_sq(spec.name) for spec in top)}' -- \"$cur\") ) ;;",
        '            esac',
        '            ;;',
    ]

    for spec in top:
        lines.append(f'        {_sq(spec.name)})')
        group = children.get(spec.name, [])
        if group:
            child_names = ' '.join(_sq(child.name) for child in group)
            own_flags = ' '.join(_sq(flag) for flag in spec.flag_words())
            lines += [
                '            if [ -z "$sub2" ]; then',
                '                case "$cur" in',
                "                    -*) COMPREPLY=( $(compgen -W "
                f"'{own_flags}' -- \"$cur\") ) ;;",
                f"                    *) COMPREPLY=( $(compgen -W '{child_names}' "
                '-- "$cur") ) ;;',
                '                esac',
                '            else',
                '                case "$sub2" in',
            ]
            for child in group:
                child_flags = ' '.join(_sq(flag) for flag in child.flag_words())
                lines.append(f'                    {_sq(child.name)})')
                lines.append('                        case "$cur" in')
                if child_flags:
                    lines.append('                            -*) '
                                 f"COMPREPLY=( $(compgen -W '{child_flags}' "
                                 '-- "$cur") ) ;;')
                else:
                    lines.append('                            -*) ;;')
                lines.append(_bash_positional_arm(child, indent=28))
                lines.append('                        esac ;;')
            lines += [
                '                esac',
                '            fi',
                '            ;;',
            ]
        else:
            own_flags = ' '.join(_sq(flag) for flag in spec.flag_words())
            lines.append('            case "$cur" in')
            if own_flags:
                lines.append(f"                -*) COMPREPLY=( $(compgen -W "
                             f"'{own_flags}' -- \"$cur\") ) ;;")
            else:
                lines.append('                -*) ;;')
            lines.append(_bash_positional_arm(spec, indent=16))
            lines.append('            esac')
            lines.append('            ;;')

    lines += [
        '    esac',
        '    return 0',
        '}',
        '',
        'complete -o default -F __obscuralens obscuralens',
        '',
    ]
    return '\n'.join(lines)


def _bash_positional_arm(spec: CommandSpec, indent: int = 16) -> str:
    """The non-dash arm for a leaf command: choices when a positional has them."""
    pad = ' ' * indent
    for positional in spec.positionals:
        if positional.get('choices'):
            values = ' '.join(_sq(value) for value in positional['choices'])
            return (f"{pad}*) COMPREPLY=( $(compgen -W '{values}' "
                    f'-- "$cur") ) ;;')
    return f'{pad}*) ;;'


# ---------------------------------------------------------------------------
# zsh
# ---------------------------------------------------------------------------

def zsh_completion() -> str:
    """
    Return a complete, self-contained zsh completion script.

    The script starts with the ``#compdef obscuralens`` marker and uses only
    the stock zsh completion system: ``_describe`` for command and action
    names, ``_arguments`` for per-command options (with value sets for
    options that have argparse choices) and ``compadd`` for the root-level
    flags. Install it as ``~/.zsh/completions/_obscuralens``.
    """
    specs = command_tree()
    top = [spec for spec in specs if len(spec.path) == 1]
    children: Dict[str, List[CommandSpec]] = {}
    for spec in specs:
        if len(spec.path) == 2:
            children.setdefault(spec.path[0], []).append(spec)
    version = _version()

    lines: List[str] = [
        '#compdef obscuralens',
        f'# zsh completion for ObscuraLens{f" {version}" if version else ""}',
        '# Generated by `obscuralens completion zsh` — do not edit by hand.',
        '',
        '_obscuralens() {',
        '    local -a commands',
        '    commands=(',
    ]
    for spec in top:
        lines.append(f"        '{_sq(spec.name)}:{_sq(_zsh_help(spec.help))}'")
    lines += [
        '    )',
        '',
        '    if (( CURRENT == 2 )); then',
        "        _describe -t commands 'obscuralens command' commands",
        "        compadd -- '--version' '-h' '--help'",
        '        return 0',
        '    fi',
        '',
        '    local cmd subcmd',
        '    cmd="${words[2]}"',
        '    case "$cmd" in',
    ]

    for spec in top:
        lines.append(f'        ({_sq(spec.name)})')
        group = children.get(spec.name, [])
        if group:
            lines += [
                '            if (( CURRENT == 3 )); then',
                '                local -a actions',
                '                actions=(',
            ]
            for child in group:
                lines.append(
                    f"                    '{_sq(child.name)}:"
                    f"{_sq(_zsh_help(child.help))}'")
            lines += [
                '                )',
                "                _describe -t actions "
                f"'{spec.name} action' actions",
                '            else',
                '                case "${words[3]}" in',
            ]
            for child in group:
                lines.append(f'                    ({_sq(child.name)})')
                lines.extend(_zsh_arguments_call(child, indent=24))
                lines.append('                        ;;')
            lines += [
                '                esac',
                '            fi',
                '            ;;',
            ]
        else:
            lines.extend(_zsh_arguments_call(spec, indent=12))
            lines.append('            ;;')

    lines += [
        '    esac',
        '    return 0',
        '}',
        '',
        'if [ "$funcstack[1]" = "_obscuralens" ]; then',
        '    _obscuralens "$@"',
        'else',
        '    compdef _obscuralens obscuralens',
        'fi',
        '',
    ]
    return '\n'.join(lines)


def _zsh_arguments_call(spec: CommandSpec, indent: int = 12) -> List[str]:
    """Build the ``_arguments ...`` lines for one command's options."""
    pad = ' ' * indent
    chunks: List[str] = []
    for option in spec.options:
        flags = option['flags']
        help_text = _zsh_help(option['help'])
        bracket = f"'[{help_text}]'" if help_text else ''
        if len(flags) == 2 and flags[0].startswith('-') \
                and not flags[0].startswith('--'):
            head = f"'({' '.join(flags)})'{{{','.join(flags)}}}"
        else:
            head = ' '.join(f"'{flag}'" for flag in flags)
        if not option['takes_value']:
            chunks.append(f'{head}{bracket}')
            continue
        metavar = _zsh_help(option['metavar'] or 'value') or 'value'
        if option['choices']:
            values = ' '.join(_sq(value) for value in option['choices'])
            chunks.append(f'{head}{bracket}:{metavar}:({values})')
        else:
            chunks.append(f'{head}{bracket}:{metavar}:')

    if not chunks:
        return [f'{pad}_arguments']
    if len(chunks) == 1:
        return [f'{pad}_arguments {chunks[0]}']
    lines = [f'{pad}_arguments \\']
    lines.extend(f'{pad}{chunk} \\' for chunk in chunks[:-1])
    lines.append(f'{pad}{chunks[-1]}')
    return lines


# ---------------------------------------------------------------------------
# fish
# ---------------------------------------------------------------------------

def fish_completion() -> str:
    """
    Return a complete fish completion script (a list of ``complete`` calls).

    Top-level commands complete only when no subcommand was typed yet
    (``__fish_use_subcommand``); nested actions complete right after their
    group name; options are attached to their command with ``-r`` and a
    value set when the option requires an argument with known choices.
    Install it as ``~/.config/fish/completions/obscuralens.fish``.
    """
    specs = command_tree()
    top = [spec for spec in specs if len(spec.path) == 1]
    children: Dict[str, List[CommandSpec]] = {}
    for spec in specs:
        if len(spec.path) == 2:
            children.setdefault(spec.path[0], []).append(spec)
    version = _version()

    lines: List[str] = [
        f'# fish completion for ObscuraLens{f" {version}" if version else ""}',
        '# Generated by `obscuralens completion fish` — do not edit by hand.',
        '',
        'complete -c obscuralens -f',
        '',
        '# root-level options',
        "complete -c obscuralens -n '__fish_use_subcommand()' "
        "-s h -l help -d 'show this help message and exit'",
        "complete -c obscuralens -n '__fish_use_subcommand()' "
        "-l version -d 'show program version number and exit'",
        '',
        '# top-level commands',
    ]
    for spec in top:
        lines.append("complete -c obscuralens -n '__fish_use_subcommand()' "
                     f"-a '{_sq(spec.name)}' -d '{_sq(_clean(spec.help))}'")

    for spec in top:
        group = children.get(spec.name, [])
        if not group:
            continue
        guard = ' '.join(_sq(child.name) for child in group)
        lines += ['', f"# {spec.name} actions"]
        for child in group:
            condition = (f'__fish_seen_subcommand_from {_sq(spec.name)}; '
                         f'and not __fish_seen_subcommand_from {guard}')
            lines.append(f'complete -c obscuralens -n "{condition}" '
                         f"-a '{_sq(child.name)}' "
                         f"-d '{_sq(_clean(child.help))}'")

    lines += ['', '# options per command']
    for spec in specs:
        seen = _fish_seen_condition(spec, children)
        for option in spec.options:
            parts = [f'complete -c obscuralens -n "{seen}"']
            flags = option['flags']
            for flag in flags:
                if flag.startswith('--'):
                    parts.append(f'-l {flag[2:]}')
                else:
                    parts.append(f'-s {flag.lstrip("-")}')
            if option['help']:
                parts.append(f"-d '{_sq(_clean(option['help']))}'")
            if option['takes_value']:
                parts.append('-r')
                if option['choices']:
                    values = ' '.join(_sq(value) for value in option['choices'])
                    parts.append(f"-a '{values}'")
            lines.append(' '.join(parts))

    for spec in specs:
        for positional in spec.positionals:
            if not positional.get('choices'):
                continue
            seen = _fish_seen_condition(spec, children)
            values = ' '.join(_sq(value) for value in positional['choices'])
            lines.append(f'complete -c obscuralens -n "{seen}" -a \'{values}\'')

    lines.append('')
    return '\n'.join(lines)


def _fish_seen_condition(spec: CommandSpec,
                         children: Dict[str, List[CommandSpec]]) -> str:
    """The fish condition that is true exactly when ``spec`` is active."""
    # __fish_seen_subcommand_from matches ANY of its words, so a nested
    # command path needs one conjunct per path element.
    return '; and '.join(
        f'__fish_seen_subcommand_from {_sq(part)}' for part in spec.path)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

_GENERATORS = {
    'bash': bash_completion,
    'zsh': zsh_completion,
    'fish': fish_completion,
}


def write_completion(shell: str, path: Optional[str] = None) -> str:
    """
    Generate the completion script for ``shell`` and optionally write it out.

    Args:
        shell: one of :data:`SHELLS` (case-insensitive).
        path: when given, the script is also written to this file (parent
            directories are created as needed).

    Returns:
        The generated script, whether or not it was written to disk.

    Raises:
        ValueError: when ``shell`` is not one of ``bash``/``zsh``/``fish``.
    """
    generator = _GENERATORS.get(str(shell or '').lower())
    if generator is None:
        raise ValueError(
            f"unknown shell {shell!r}; expected one of: {', '.join(SHELLS)}")

    script = generator()
    if path:
        target = Path(path)
        if str(target.parent) not in ('', '.'):
            target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(script, encoding='utf-8')
    return script


def install_hint(shell: str) -> str:
    """
    Return the per-shell install instructions printed by the CLI on stderr.

    The hint names the conventional completion location for the shell; it is
    informational only — the script on stdout is always complete.
    """
    normalized = str(shell or '').lower()
    if normalized == 'bash':
        return ('Install with:\n'
                '  obscuralens completion bash | '
                'sudo tee /etc/bash_completion.d/obscuralens >/dev/null\n'
                'or for a single user:\n'
                '  obscuralens completion bash > '
                '~/.local/share/bash-completion/completions/obscuralens\n'
                'then start a new shell.')
    if normalized == 'zsh':
        return ('Install with:\n'
                '  obscuralens completion zsh > ~/.zsh/completions/_obscuralens\n'
                'and make sure ~/.zsh/completions is on $fpath, e.g. in '
                '~/.zshrc:\n'
                '  fpath=(~/.zsh/completions $fpath); autoload -Uz compinit; '
                'compinit\n'
                'then start a new shell.')
    if normalized == 'fish':
        return ('Install with:\n'
                '  obscuralens completion fish > '
                '~/.config/fish/completions/obscuralens.fish\n'
                'fish picks it up automatically on the next start.')
    return f'unknown shell {shell!r}; expected one of: {", ".join(SHELLS)}'
