"""Docker deployment unit tests (do not require Docker Desktop)."""

import os
from pathlib import Path

import jwt
import pytest

from scripts.docker_init_keys import initialize


def test_docker_key_initializer_creates_matching_restricted_keys(tmp_path: Path):
    private = tmp_path / 'private' / 'gateway-private.pem'
    public = tmp_path / 'public' / 'gateway-public.pem'
    initialize(private, public)
    assert private.exists() and public.exists()
    assert private.read_bytes().startswith(b'-----BEGIN PRIVATE KEY-----')
    assert public.read_bytes().startswith(b'-----BEGIN PUBLIC KEY-----')
    assert private.stat().st_mode & 0o777 == 0o600
    token = jwt.encode({'aud': 'incident-service'}, private.read_bytes(), algorithm='RS256')
    assert jwt.decode(token, public.read_bytes(), algorithms=['RS256'], audience='incident-service')['aud'] == 'incident-service'


def test_docker_key_initializer_never_overwrites_existing_keys(tmp_path: Path):
    private = tmp_path / 'private.pem'
    public = tmp_path / 'public.pem'
    initialize(private, public)
    existing_private = private.read_bytes()
    existing_public = public.read_bytes()
    with pytest.raises(FileExistsError):
        initialize(private, public)
    assert private.read_bytes() == existing_private
    assert public.read_bytes() == existing_public


def test_docker_key_initializer_refuses_partial_pair(tmp_path: Path):
    private = tmp_path / 'private.pem'
    public = tmp_path / 'public.pem'
    private.write_text('pretend partial private key')
    with pytest.raises(FileExistsError):
        initialize(private, public)
    assert not public.exists()


def test_docker_key_initializer_refuses_same_path(tmp_path: Path):
    private = tmp_path / 'key.pem'
    with pytest.raises(ValueError):
        initialize(private, private)
    assert not private.exists()
