import pytest

from twisted.internet import reactor
from twisted.web import client

from testutil.websocket import make_request

#
# Fixtures
#

@pytest.fixture
def agent():
    return client.Agent(reactor)

#
# Tests
#

@pytest.inlineCallbacks
def test_Location_without_plugin_returns_500(agent):
    response = yield make_request(agent, path='/bad-config')
    assert response.code == 500
    client.readBody(response).cancel() # immediately close the connection
