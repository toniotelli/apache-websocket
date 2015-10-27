import pytest

from twisted.internet import reactor
from twisted.web import client

@pytest.fixture
def agent():
    """Returns a t.w.c.Agent for use by tests."""
    return client.Agent(reactor)

