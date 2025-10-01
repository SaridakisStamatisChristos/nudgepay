from typing import get_args

from nudgepay.httpx import _client, _types


def test_use_client_default_is_singleton():
    sentinel = _client.USE_CLIENT_DEFAULT
    assert isinstance(sentinel, _client.UseClientDefault)
    assert sentinel is _client.USE_CLIENT_DEFAULT
    assert sentinel is not _client.UseClientDefault()


def test_timeout_types_accept_float_and_tuple():
    args = get_args(_types.TimeoutTypes)
    assert float in args
    assert any(isinstance(arg, tuple) or getattr(arg, '__origin__', None) is tuple for arg in args)


def test_url_types_include_str_and_url_forward_ref():
    args = get_args(_types.URLTypes)
    assert str in args
    assert any(getattr(arg, '__forward_arg__', None) == 'URL' for arg in args)
