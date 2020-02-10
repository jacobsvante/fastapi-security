import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from fastapi_security.registry import _permissions_registry


@pytest.fixture
def app():
    _permissions_registry.clear()  # TODO: Make permissions context local!
    return FastAPI()


@pytest.fixture
def client(app):
    return TestClient(app)
