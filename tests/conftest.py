import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient


@pytest.fixture
def app():
    return FastAPI()


@pytest.fixture
def client(app):
    return TestClient(app)
