import pytest

from twisted.web import client

from testutil.fixtures import agent
from testutil.websocket import assert_successful_upgrade, make_request

#
# Tests
#

@pytest.inlineCallbacks
def test_Location_without_plugin_returns_500(agent):
    response = yield make_request(agent, path='/bad-config')
    assert response.code == 500
    client.readBody(response).cancel() # immediately close the connection

@pytest.inlineCallbacks
def test_mismatched_Origins_are_allowed_with_OriginCheck_Off(agent):
    response = yield make_request(agent, path='/no-origin-check',
                                  origin='http://not-my-origin.com')
    assert_successful_upgrade(response)
    client.readBody(response).cancel() # immediately close the connection
