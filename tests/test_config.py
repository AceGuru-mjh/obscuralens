"""Configuration layering and persistence tests."""

import yaml

from obscuralens.config import ConfigManager


def test_defaults_without_files(tmp_path):
    manager = ConfigManager(config_dir=str(tmp_path))
    assert manager.app_config.request_timeout == 30
    assert manager.db_config.db_type == 'sqlite'
    assert manager.get_api_key('shodan') is None


def test_yaml_layering_and_secrets(tmp_path):
    (tmp_path / 'config.yaml').write_text(yaml.safe_dump({
        'app': {'request_timeout': 12, 'log_level': 'DEBUG'},
        'database': {'db_port': 1234},
    }), encoding='utf-8')
    (tmp_path / 'secrets.yaml').write_text(yaml.safe_dump({
        'shodan_api_key': 'from-secrets',
    }), encoding='utf-8')

    manager = ConfigManager(config_dir=str(tmp_path))
    assert manager.app_config.request_timeout == 12
    assert manager.app_config.log_level == 'DEBUG'
    assert manager.db_config.db_port == 1234
    assert manager.get_api_key('shodan') == 'from-secrets'


def test_env_overrides_files(tmp_path, monkeypatch):
    (tmp_path / 'config.yaml').write_text(yaml.safe_dump({
        'app': {'request_timeout': 12},
    }), encoding='utf-8')
    monkeypatch.setenv('OBSCURALENS_REQUEST_TIMEOUT', '99')
    monkeypatch.setenv('OBSCURALENS_DEEP_USERNAME_SCAN', 'false')
    monkeypatch.setenv('OBSCURALENS_DISABLED_SOURCES', 'rdap, gravatar')
    monkeypatch.setenv('OBSCURALENS_VIRUSTOTAL_API_KEY', 'env-key')

    manager = ConfigManager(config_dir=str(tmp_path))
    assert manager.app_config.request_timeout == 99
    assert manager.app_config.deep_username_scan is False
    assert manager.app_config.disabled_sources == ['rdap', 'gravatar']
    assert manager.get_api_key('virustotal') == 'env-key'


def test_source_enabled_toggle(tmp_path):
    manager = ConfigManager(config_dir=str(tmp_path))
    assert manager.is_source_enabled('rdap') is True
    manager.app_config.disabled_sources = ['rdap']
    assert manager.is_source_enabled('RDAP') is False


def test_save_roundtrip(tmp_path):
    manager = ConfigManager(config_dir=str(tmp_path))
    manager.app_config.request_timeout = 45
    manager.set_api_key('hunter', 'secret-value')
    manager.save_config()
    manager.save_secrets()

    data = yaml.safe_load((tmp_path / 'config.yaml').read_text(encoding='utf-8'))
    assert data['app']['request_timeout'] == 45
    secrets = yaml.safe_load((tmp_path / 'secrets.yaml').read_text(encoding='utf-8'))
    assert secrets['hunter_api_key'] == 'secret-value'

    reloaded = ConfigManager(config_dir=str(tmp_path))
    assert reloaded.app_config.request_timeout == 45
    assert reloaded.get_api_key('hunter') == 'secret-value'


def test_new_optional_services_present(tmp_path):
    manager = ConfigManager(config_dir=str(tmp_path))
    services = manager.configured_services()
    assert 'abuseipdb' in services
    assert 'ipinfo' in services
