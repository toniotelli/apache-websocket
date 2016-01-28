from twisted.web.http_headers import Headers

# TODO: make these configurable
HOST = '127.0.0.1'
HOST_IPV6 = '[::1]'

SCHEME = "http"
PORT = 80

# from `openssl rand -base64 16`
UPGRADE_KEY = '36zg57EA+cDLixMBxrDj4g=='

# base64(SHA1(UPGRADE_KEY:"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
UPGRADE_ACCEPT = 'eGic2At3BJQkGyA4Dq+3nczxEJo='

def assert_successful_upgrade(response):
    """
    Asserts that a server's response to a WebSocket Upgrade request is correct
    and successful.
    """
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

def make_authority(scheme=SCHEME, host=HOST, port=PORT):
    """Returns host[:port] for use in a Host header."""
    is_default_port = ((scheme in ["http", "ws"] and port == 80) or
                       (scheme in ["https", "wss"] and port == 443))
    root = host

    if not is_default_port:
        root += ":{0}".format(port)

    return root

def make_root(scheme=SCHEME, host=HOST, port=PORT):
    """Returns scheme://host[:port] to create a root URL for testing."""
    return scheme + "://" + make_authority(scheme, host, port)

def make_request(agent, method='GET', path='/echo', key=UPGRADE_KEY,
                 version=None, protocol=None, origin=None, host=None):
    """
    Performs a WebSocket handshake using Agent#request. Returns whatever
    Agent#request returns (which is a Deferred that should be waited on for the
    server response).
    """
    if version is None:
        version = '13'

    hdrs = {
        "Upgrade": ["websocket"],
        "Connection": ["Upgrade"],
        "Sec-WebSocket-Key": [key],
        "Sec-WebSocket-Version": [version],
    }

    if protocol is not None:
        hdrs["Sec-WebSocket-Protocol"] = [protocol]

    if origin is not None:
        if int(version) < 8:
            hdrs["Sec-WebSocket-Origin"] = [origin]
        else:
            hdrs["Origin"] = [origin]

    if host is not None:
        hdrs["Host"] = [host]

    return agent.request(method,
                         make_root() + path,
                         Headers(hdrs),
                         None)
