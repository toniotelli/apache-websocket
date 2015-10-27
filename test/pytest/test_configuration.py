import pytest

from twisted.web import client

from testutil.fixtures import agent
from testutil.websocket import make_request

#
# Tests
#

@pytest.inlineCallbacks
def test_Location_without_plugin_returns_500(agent):
    response = yield make_request(agent, path='/bad-config')
    assert response.code == 500
    client.readBody(response).cancel() # immediately close the connection
