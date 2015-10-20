import pytest
import re

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

def assert_headers_match(actual_headers, expected_list):
    """
    Asserts that the header values in the given list match the expected list of
    values. Headers will be split on commas.
    """
    # This regex matches all "OWS , OWS" separators in a header value.
    sep_ex = re.compile(r"[ \t]*,[ \t]*")

    actual_list = []
    if actual_headers is None:
        actual_headers = []

    for header in actual_headers:
        # Collapse list whitespace, then split on commas to get the list of
        # values.
        values = sep_ex.sub(',', header).split(',')
        actual_list.extend(values)

    assert actual_list == expected_list

def make_request(agent, method='GET', key=UPGRADE_KEY, version='13',
                 protocol=None):
    """
    Performs a WebSocket handshake using Agent#request. Returns whatever
    Agent#request returns (which is a Deferred that should be waited on for the
    server response).
    """
    hdrs = {
        "Upgrade": ["websocket"],
        "Connection": ["Upgrade"],
        "Sec-WebSocket-Key": [key],
        "Sec-WebSocket-Version": [version],
    }

    if protocol is not None:
        hdrs["Sec-WebSocket-Protocol"] = [protocol]

    return agent.request(method,
                         HOST + '/echo',
                         Headers(hdrs),
                         None)

#
# Fixtures
#

@pytest.fixture
def agent():
    return client.Agent(reactor)

@pytest.yield_fixture(params=['7', '8', '13'])
def success_response(agent, request):
    """A fixture that performs a correct handshake with the given version."""
    response = pytest.blockon(make_request(agent, version=request.param))
    yield response
    client.readBody(response).cancel() # immediately close the connection

@pytest.yield_fixture(params=['POST', 'PUT', 'DELETE', 'HEAD'])
def bad_method_response(agent, request):
    """A fixture that performs a bad handshake with a disallowed HTTP method."""
    response = pytest.blockon(make_request(agent, method=request.param))
    yield response
    client.readBody(response).cancel() # immediately close the connection

@pytest.yield_fixture(params=['', 'abcdef', '+13', '13sdfj', '1300', '013',
                              '-1', '256', '8_'])
def invalid_version_response(agent, request):
    """
    A fixture that performs a bad handshake with a prohibited WebSocket version.
    """
    response = pytest.blockon(make_request(agent, version=request.param))
    yield response
    client.readBody(response).cancel() # immediately close the connection

@pytest.yield_fixture(params=['0', '9', '14', '255'])
def unsupported_version_response(agent, request):
    """
    A fixture that performs a correct handshake with an unsupported WebSocket
    version.
    """
    response = pytest.blockon(make_request(agent, version=request.param))
    yield response
    client.readBody(response).cancel() # immediately close the connection

@pytest.yield_fixture(params=["toosmall", "wayyyyyyyyyyyyyyyyyyyytoobig",
                              "invalid!characters_89A==",
                              "badlastcharacterinkey+==",
                              "WRONGPADDINGLENGTH012A?=",
                              "JUNKATENDOFPADDING456A=?"])
def bad_key_response(agent, request):
    """A fixture that performs a bad handshake with an invalid key."""
    response = pytest.blockon(make_request(agent, key=request.param))
    yield response
    client.readBody(response).cancel() # immediately close the connection

@pytest.yield_fixture(params=["", " ", "\t", ",", ",,", "bad token","\"token\"",
                              "bad/token", "bad\\token", "valid, invalid{}"])
def bad_protocol_response(agent, request):
    """
    A fixture that performs a bad handshake with an invalid
    Sec-WebSocket-Protocol header.
    """
    response = pytest.blockon(make_request(agent, protocol=request.param))
    yield response
    client.readBody(response).cancel() # immediately close the connection

#
# Tests
#

def test_valid_handshake_is_upgraded_correctly(success_response):
    assert_successful_upgrade(success_response)

def test_handshake_is_refused_if_method_is_not_GET(bad_method_response):
    assert 400 <= bad_method_response.code < 500

def test_handshake_is_refused_for_invalid_version(invalid_version_response):
    assert invalid_version_response.code == 400

def test_handshake_is_refused_for_unsupported_versions(unsupported_version_response):
    assert unsupported_version_response.code == 400

    # Make sure the server advertises its supported versions, as well.
    versions = unsupported_version_response.headers.getRawHeaders("Sec-WebSocket-Version")
    assert_headers_match(versions, ['13', '8', '7'])

def test_handshake_is_refused_for_bad_key(bad_key_response):
    assert bad_key_response.code == 400

def test_handshake_is_refused_for_bad_subprotocols(bad_protocol_response):
    assert bad_protocol_response.code == 400
