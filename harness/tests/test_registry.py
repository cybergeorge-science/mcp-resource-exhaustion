"""Smoke tests for dos_module.registry / dos_module.vectors."""
import pytest

from dos_module import vectors  # noqa: F401  (registers all 7 stubs)
from dos_module.interface import AttackContext, Sdk, Transport
from dos_module.registry import get_module, list_modules


def test_all_seven_vectors_are_registered():
    expected = {
        "oversized_body",
        "init_session_flood",
        "unbounded_stdio_stream",
        "deeply_nested_json",
        "tool_invocation_flooding",
        "slow_sse_slow_read",
        "redos_input_validation",
    }
    assert set(list_modules()) == expected


def test_every_registered_module_has_a_cwe_and_description():
    for vector_id in list_modules():
        mod = get_module(vector_id)
        assert mod.cwe.startswith("CWE-")
        assert mod.description


def test_unregistered_vector_id_raises_keyerror():
    with pytest.raises(KeyError):
        get_module("not_a_real_vector")


def test_stub_run_raises_not_implemented_but_validates_context_first():
    mod_cls = get_module("oversized_body")
    mod = mod_cls()
    ctx = AttackContext(
        run_id="r1",
        vector_id="oversized_body",
        sdk=Sdk.PYTHON,
        transport=Transport.STREAMABLE_HTTP,
        host="0.0.0.0",  # non-loopback -- must be rejected before NotImplementedError
        port=8080,
        server_command=None,
        load_level=1.0,
        concurrency=1,
        mitigation=False,
        duration_s=1.0,
    )
    with pytest.raises(ValueError, match="loopback"):
        mod.run(ctx)


def test_stub_run_raises_not_implemented_for_valid_loopback_context():
    mod_cls = get_module("oversized_body")
    mod = mod_cls()
    ctx = AttackContext(
        run_id="r1",
        vector_id="oversized_body",
        sdk=Sdk.PYTHON,
        transport=Transport.STREAMABLE_HTTP,
        host="127.0.0.1",
        port=8080,
        server_command=None,
        load_level=1.0,
        concurrency=1,
        mitigation=False,
        duration_s=1.0,
    )
    with pytest.raises(NotImplementedError):
        mod.run(ctx)
