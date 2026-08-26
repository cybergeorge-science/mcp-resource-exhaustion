"""Smoke tests for dos_module.config against the shipped example config and
synthetic malformed variants -- no MCP server."""
import copy
import os

import pytest
import yaml

from dos_module.config import ConfigError, load_config, validate_config

_HERE = os.path.dirname(os.path.abspath(__file__))
_EXAMPLE_CONFIG = os.path.join(
    _HERE, "..", "dos_module", "configs", "run.example.yaml"
)


def _load_example_dict() -> dict:
    with open(_EXAMPLE_CONFIG, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def test_shipped_example_config_is_valid():
    cfg = load_config(_EXAMPLE_CONFIG)
    assert cfg["target"]["host"] == "127.0.0.1"
    assert len(cfg["vectors"]) == 7


def test_non_loopback_host_is_rejected():
    cfg = _load_example_dict()
    cfg["target"]["host"] = "0.0.0.0"
    with pytest.raises(ConfigError):
        validate_config(cfg)


def test_unknown_vector_id_is_rejected():
    cfg = _load_example_dict()
    cfg["vectors"].append({"id": "totally_made_up_vector", "enabled": True})
    with pytest.raises(ConfigError):
        validate_config(cfg)


def test_missing_required_field_is_rejected():
    cfg = _load_example_dict()
    del cfg["sampler"]["interval_ms"]
    with pytest.raises(ConfigError):
        validate_config(cfg)


def test_bad_transport_enum_value_is_rejected():
    cfg = _load_example_dict()
    cfg["target"]["transport"] = "carrier_pigeon"
    with pytest.raises(ConfigError):
        validate_config(cfg)


def test_valid_config_is_not_mutated_by_validation():
    cfg = _load_example_dict()
    original = copy.deepcopy(cfg)
    validate_config(cfg)
    assert cfg == original
