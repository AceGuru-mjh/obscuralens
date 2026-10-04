"""Shell completion tests: command tree walk, generators, CLI wiring."""

import argparse

import pytest

from obscuralens import commands
from obscuralens.completion import (
    SHELLS,
    bash_completion,
    command_tree,
    fish_completion,
    install_hint,
    last_warnings,
    write_completion,
    zsh_completion,
)


def _paths():
    return [spec.path for spec in command_tree()]


def _spec(path):
    for spec in command_tree():
        if spec.path == tuple(path):
            return spec
    return None


class TestCommandTree:
    """The walk over the real parser built by commands.build_parser()."""

    def test_known_commands_present(self):
        paths = _paths()

        for expected in [('ip',), ('domain',), ('watch',), ('watch', 'add'),
                         ('case', 'list'), ('tools', 'encode'),
                         ('analytics', 'stats'), ('notify', 'add'),
                         ('automation', 'tasks'), ('completion',),
                         ('plugins',), ('plugins', 'run')]:
            assert tuple(expected) in paths, expected

    def test_specs_sorted_and_unique(self):
        paths = _paths()

        assert paths == sorted(paths)
        assert len(paths) == len(set(paths))

    def test_every_spec_carries_help(self):
        for spec in command_tree():
            assert isinstance(spec.help, str)
            assert spec.help, spec.path

    def test_recursion_into_groups(self):
        watch = _spec(['watch'])
        assert watch is not None

        children = [p for p in _paths() if p[:1] == ('watch',)]
        assert len(children) >= 5            # watch itself + 4 actions
        assert ('watch', 'add') in children
        assert ('watch', 'remove') in children
        assert ('watch', 'check') in children

    def test_leaf_command_has_target_positional_and_options(self):
        ip = _spec(['ip'])

        assert ip is not None
        assert ip.positionals and ip.positionals[0]['dest'] == 'target'
        flag_words = ip.flag_words()
        assert '-f' in flag_words and '--format' in flag_words
        assert '--timeout' in flag_words and '--no-cache' in flag_words

    def test_option_choices_discovered(self):
        add = _spec(['watch', 'add'])

        assert add is not None
        kind_option = next(option for option in add.options
                           if '--kind' in option['flags'])
        assert 'ip' in kind_option['choices']
        assert 'bssid' in kind_option['choices']

        ip = _spec(['ip'])
        format_option = next(option for option in ip.options
                             if '--format' in option['flags'])
        assert format_option['choices'][0] == 'table'
        assert 'mermaid' in format_option['choices']
        assert format_option['takes_value'] is True

    def test_flag_options_take_no_value(self):
        ip = _spec(['ip'])
        no_cache = next(option for option in ip.options
                        if option['flags'] == ('--no-cache',))
        assert no_cache['takes_value'] is False

    def test_completion_shell_positional_has_choices(self):
        completion = _spec(['completion'])

        assert completion is not None
        assert completion.positionals[0]['dest'] == 'shell'
        assert completion.positionals[0]['choices'] == ['bash', 'zsh', 'fish']

    def test_tree_survives_parser_without_subparsers(self, monkeypatch):
        monkeypatch.setattr(commands, 'build_parser',
                            lambda: argparse.ArgumentParser(prog='obscuralens'))

        assert command_tree() == []

    def test_tree_survives_raising_build_parser(self, monkeypatch):
        def boom():
            raise RuntimeError('parser exploded')

        monkeypatch.setattr(commands, 'build_parser', boom)

        assert command_tree() == []
        assert any('build_parser failed' in warning
                   for warning in last_warnings())

    def test_build_parser_lazy_import_is_monkeypatch_visible(self, monkeypatch):
        """command_tree() must read commands.build_parser at call time."""
        calls = []

        real = commands.build_parser

        def counting():
            calls.append(1)
            return real()

        monkeypatch.setattr(commands, 'build_parser', counting)
        command_tree()
        assert calls == [1]


class TestBashCompletion:
    """The bash generator."""

    def test_markers(self):
        script = bash_completion()

        assert 'complete -o default -F __obscuralens obscuralens' in script
        assert '__obscuralens_words()' in script
        assert script.startswith('# bash completion for ObscuraLens')

    def test_contains_commands_and_options(self):
        script = bash_completion()

        for name in ('analytics', 'watch', 'ip', 'completion', 'plugins'):
            assert '        %s)' % name in script
        assert "'ip phone username email domain" in script       # kinds
        assert "'table json markdown html csv mermaid'" in script
        assert 'add check list remove' in script                 # watch actions
        assert '--timeout' in script and '--no-cache' in script
        assert '--version' in script

    def test_completion_shell_choices_offered(self):
        script = bash_completion()

        assert "'bash zsh fish'" in script

    def test_deterministic(self):
        assert bash_completion() == bash_completion()

    def test_valid_bash_syntax(self, tmp_path):
        import subprocess

        target = tmp_path / 'obscuralens.bash'
        target.write_text(bash_completion(), encoding='utf-8')
        result = subprocess.run(['bash', '-n', str(target)], capture_output=True)
        assert result.returncode == 0, result.stderr.decode()


class TestZshCompletion:
    """The zsh generator."""

    def test_markers(self):
        script = zsh_completion()

        assert script.startswith('#compdef obscuralens')
        assert '_obscuralens()' in script
        assert 'compdef _obscuralens obscuralens' in script
        assert "_describe -t commands 'obscuralens command' commands" in script

    def test_contains_commands_and_options(self):
        script = zsh_completion()

        for name in ('analytics', 'watch', 'ip', 'completion', 'plugins'):
            assert '        (%s)' % name in script
        assert ':FORMAT:(table json markdown html csv mermaid)' in script
        assert ':KIND:(ip phone username email domain' in script
        assert '--no-cache' in script
        assert "'add:start watching a target'" in script

    def test_deterministic(self):
        assert zsh_completion() == zsh_completion()


class TestFishCompletion:
    """The fish generator."""

    def test_markers(self):
        script = fish_completion()

        assert 'complete -c obscuralens' in script
        assert script.startswith('# fish completion for ObscuraLens')
        assert "complete -c obscuralens -f" in script

    def test_contains_commands_and_options(self):
        script = fish_completion()

        for name in ('analytics', 'watch', 'ip', 'completion', 'plugins'):
            assert f"-a '{name}'" in script
        assert '__fish_use_subcommand()' in script
        assert '__fish_seen_subcommand_from watch' in script
        assert '-l format' in script and '-l timeout' in script
        assert '-l no-cache' in script
        assert "'table json markdown html csv mermaid'" in script

    def test_nested_path_uses_conjunctions(self):
        script = fish_completion()

        assert ('"__fish_seen_subcommand_from watch; and '
                '__fish_seen_subcommand_from add"') in script

    def test_deterministic(self):
        assert fish_completion() == fish_completion()


class TestWriteCompletion:
    """The programmatic entry point."""

    def test_shells_tuple(self):
        assert SHELLS == ('bash', 'zsh', 'fish')

    @pytest.mark.parametrize('shell', SHELLS)
    def test_write_completion_returns_script(self, shell):
        script = write_completion(shell)
        assert script
        assert 'ObscuraLens' in script

    def test_write_completion_case_insensitive(self):
        assert write_completion('BASH') == write_completion('bash')

    def test_unknown_shell_raises(self):
        with pytest.raises(ValueError) as exc:
            write_completion('tcsh')
        assert 'tcsh' in str(exc.value)
        assert 'bash, zsh, fish' in str(exc.value)

    def test_write_completion_writes_file(self, tmp_path):
        target = tmp_path / 'nested' / 'obscuralens.bash'

        returned = write_completion('bash', str(target))

        assert target.read_text(encoding='utf-8') == returned
        assert returned == bash_completion()

    @pytest.mark.parametrize('shell', SHELLS)
    def test_install_hint_names_location(self, shell):
        hint = install_hint(shell)

        assert hint
        assert 'obscuralens completion' in hint
        if shell == 'bash':
            assert '/etc/bash_completion.d/' in hint
        elif shell == 'zsh':
            assert '~/.zsh/completions/_obscuralens' in hint
        else:
            assert '~/.config/fish/completions/obscuralens.fish' in hint

    def test_install_hint_unknown_shell(self):
        assert 'unknown shell' in install_hint('tcsh')


class TestCompletionCli:
    """`obscuralens completion <shell>` through commands.run()."""

    def test_bash_prints_script_and_hint(self, capsys):
        code = commands.run(['completion', 'bash'])

        captured = capsys.readouterr()
        assert code == 0
        assert 'complete -o default -F __obscuralens obscuralens' in captured.out
        assert '/etc/bash_completion.d/' in captured.err

    def test_zsh_stdout_flag_suppresses_hint(self, capsys):
        code = commands.run(['completion', 'zsh', '--stdout'])

        captured = capsys.readouterr()
        assert code == 0
        assert captured.out.startswith('#compdef obscuralens')
        assert captured.err == ''

    def test_fish_prints_script_and_hint(self, capsys):
        code = commands.run(['completion', 'fish'])

        captured = capsys.readouterr()
        assert code == 0
        assert 'complete -c obscuralens' in captured.out
        assert '~/.config/fish/completions/obscuralens.fish' in captured.err

    def test_unknown_shell_exits_one(self, capsys):
        code = commands.run(['completion', 'tcsh'])

        captured = capsys.readouterr()
        assert code == 1
        assert 'unknown shell' in captured.err
        assert captured.out == ''

    def test_output_file_mode(self, tmp_path, capsys):
        target = tmp_path / 'out.fish'

        code = commands.run(['completion', 'fish', '-o', str(target)])

        captured = capsys.readouterr()
        assert code == 0
        assert target.read_text(encoding='utf-8') == fish_completion()
        assert 'Saved:' in captured.err
        assert captured.out == ''
