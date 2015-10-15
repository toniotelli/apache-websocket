import pytest

from twisted.internet import defer, reactor
from twisted.web import client
from twisted.web.http_headers import Headers

# XXX for the xxx_headerReceived monkey-patch
from twisted.web._newclient import HTTPParser

HOST = 'http://127.0.0.1'

# from `openssl rand -base64 16`
UPGRADE_KEY = '36zg57EA+cDLixMBxrDj4g=='

# base64(SHA1(UPGRADE_KEY:"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
UPGRADE_ACCEPT = 'eGic2At3BJQkGyA4Dq+3nczxEJo='

#
# Helpers
#

# XXX Twisted's HTTPParser doesn't give us access to connection control headers,
# but we need them. This is a monkey-patch that adds connection control headers
# back to the main headers list.
def xxx_headerReceived(self, name, value):
    self._oldHeaderReceived(name, value)

    name = name.lower()
    if self.isConnectionControlHeader(name):
        self.headers.addRawHeader(name, value)

HTTPParser._oldHeaderReceived = HTTPParser.headerReceived
HTTPParser.headerReceived = xxx_headerReceived

def assert_successful_upgrade(response):
    # The server must upgrade with a 101 response.
    assert response.code == 101

    # We need to see Connection: Upgrade and Upgrade: websocket.
    connection = response.headers.getRawHeaders("Connection")
    assert "upgrade" in [h.lower() for h in connection]

    upgrade = response.headers.getRawHeaders("Upgrade")
    assert len(upgrade) == 1
    assert upgrade[0].lower() == "websocket"

    # The Sec-WebSocket-Accept header should match our precomputed digest.
    accept = response.headers.getRawHeaders("Sec-WebSocket-Accept")
    assert len(accept) == 1
    assert accept[0] == UPGRADE_ACCEPT

def make_request(agent, method='GET', key=UPGRADE_KEY, version='13'):
    """
    Performs a WebSocket handshake using Agent#request. Returns whatever
    Agent#request returns (which is a Deferred that should be waited on for the
    server response).
    """
    return agent.request(method,
                         HOST + '/echo',
                         Headers({
                             "Upgrade": ["websocket"],
                             "Connection": ["Upgrade"],
                             "Sec-WebSocket-Key": [key],
                             "Sec-WebSocket-Version": [version],
                         }),
                         None)

#
# Fixtures
#

@pytest.fixture
def agent():
    return client.Agent(reactor)

@pytest.yield_fixture(params=['POST', 'PUT', 'DELETE', 'HEAD'])
def bad_method_response(agent, request):
    response = pytest.blockon(make_request(agent, method=request.param))
    yield response
    client.readBody(response).cancel() # immediately close the connection

@pytest.yield_fixture(params=['abcdef', '+13', '13sdfj', '1300', '013', '-1', '256'])
def invalid_version_response(agent, request):
    """All of the above "versions" are prohibited by the RFC."""
    response = pytest.blockon(make_request(agent, version=request.param))
    yield response
    client.readBody(response).cancel() # immediately close the connection

#
# Tests
#

@pytest.inlineCallbacks
def test_valid_handshake_is_upgraded_correctly(agent):
    response = yield make_request(agent)
    assert_successful_upgrade(response)
    client.readBody(response).cancel() # immediately close the connection

def test_handshake_is_refused_if_method_is_not_GET(bad_method_response):
    assert 400 <= bad_method_response.code < 500

def test_handshake_is_refused_for_invalid_version(invalid_version_response):
    assert invalid_version_response.code == 400
