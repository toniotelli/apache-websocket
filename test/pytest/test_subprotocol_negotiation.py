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

@pytest.yield_fixture(params=["dumb-increment-protocol",
                              "   dumb-increment-protocol  ,",
                              "\tdumb-increment-protocol\t",
                              "echo, dumb-increment-protocol",
                              "dumb-increment-protocol, echo",
                              ", , dumb-increment-protocol, "])
def increment_response(agent, request):
    """
    A fixture that connects to the dumb-increment plugin with the given
    subprotocol list.
    """
    response = pytest.blockon(make_request(agent, path='/dumb-increment',
                                           protocol=request.param))
    yield response
    client.readBody(response).cancel() # immediately close the connection

#
# Tests
#

@pytest.inlineCallbacks
def test_no_subprotocol_is_negotiated_by_default(agent):
    response = yield make_request(agent, protocol="my_protocol")
    assert_successful_upgrade(response)

    protocol = response.headers.getRawHeaders("Sec-WebSocket-Protocol")
    assert protocol is None

def test_negotiation_of_known_subprotocol_succeeds(increment_response):
    assert_successful_upgrade(increment_response)

    headers = increment_response.headers
    protocol = headers.getRawHeaders("Sec-WebSocket-Protocol")
    assert len(protocol) == 1
    assert protocol[0] == 'dumb-increment-protocol'
