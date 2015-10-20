import pytest

from twisted.internet import reactor
from twisted.web import client

from testutil.websocket import assert_successful_upgrade, make_request

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
def test_no_subprotocol_is_negotiated_by_default(agent):
    response = yield make_request(agent, protocol="my_protocol")
    assert_successful_upgrade(response)

    protocol = response.headers.getRawHeaders("Sec-WebSocket-Protocol")
    assert protocol is None
