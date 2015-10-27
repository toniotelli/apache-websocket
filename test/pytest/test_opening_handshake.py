import pytest
import re
import urlparse

from twisted.internet import defer, reactor
from twisted.web import client

from testutil.websocket import assert_successful_upgrade, make_authority, \
                               make_root, make_request, HOST, HOST_IPV6

# XXX for the xxx_headerReceived monkey-patch
from twisted.web._newclient import HTTPParser

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

class HTTP10Agent:
    """
    A hacky attempt at an HTTP/1.0 version of t.w.c.Agent.  Unfortunately
    t.w.c.Agent only supports HTTP/1.1, so we have to create this ourselves. It
    uses the old HTTPClientFactory implementation in Twisted.

    Note that this only sort of implements Agent (it doesn't callback until the
    response is received, and it doesn't even return the full response from
    request()) and is really only useful for the purposes of these tests.
    """
    def __init__(self, reactor):
        self._reactor = reactor

    class _FakeResponse:
        def __init__(self, code):
            self.code = code

    def request(self, method, uri, headers=None, bodyProducer=None):
        url = urlparse.urlparse(uri, scheme='http')
        host = url.hostname
        port = url.port

        if port is None:
            port = 443 if (url.scheme == 'https') else 80

        # Translate from Agent's Headers object back into a dict.
        if headers is not None:
            old_headers = {}
            for name, value_list in headers.getAllRawHeaders():
                old_headers[name] = value_list[0]
            headers = old_headers

        f = client.HTTPClientFactory(uri, method=method, headers=headers,
                                     timeout=2)

        def gotResponse(page):
            return HTTP10Agent._FakeResponse(int(f.status))
        f.deferred.addBoth(gotResponse)

        self._reactor.connectTCP(host, port, f)

        return f.deferred

#
# Fixtures
#

@pytest.fixture
def agent():
    return client.Agent(reactor)

@pytest.fixture
def agent_10():
    return HTTP10Agent(reactor)

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
                              "bad/token", "bad\\token", "valid, invalid{}",
                              "bad; separator", "control\x05character",
                              "bad\ttoken"])
def bad_protocol_response(agent, request):
    """
    A fixture that performs a bad handshake with an invalid
    Sec-WebSocket-Protocol header.
    """
    response = pytest.blockon(make_request(agent, protocol=request.param))
    yield response
    client.readBody(response).cancel() # immediately close the connection

@pytest.yield_fixture(params=[HOST, HOST_IPV6])
def good_origin_response(agent, request):
    """
    A fixture that performs a handshake with an Origin that matches the server.
    """
    host = make_authority(host=request.param)
    origin = make_root(host=request.param)

    response = pytest.blockon(make_request(agent, origin=origin, host=host))
    yield response
    client.readBody(response).cancel() # immediately close the connection

@pytest.yield_fixture(params=[
                              ["http://not-my-origin.com", None],
                              [make_root(port=55), None],
                              [make_root(), make_authority(port=55)]
                             ])
def bad_origin_response(agent, request):
    """
    A fixture that performs a good handshake, but with an Origin that does not
    match the server.
    """
    origin = request.param[0]
    host = request.param[1]

    response = pytest.blockon(make_request(agent, origin=origin, host=host))
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

@pytest.inlineCallbacks
def test_HTTP_10_handshakes_are_refused(agent_10):
    response = yield make_request(agent_10)
    assert 400 <= response.code < 500

def test_same_Origin_is_allowed(good_origin_response):
    assert_successful_upgrade(good_origin_response)

def test_mismatched_Origins_are_refused(bad_origin_response):
    assert bad_origin_response.code == 403
