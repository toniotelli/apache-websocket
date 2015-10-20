from twisted.web.http_headers import Headers

# TODO: make this configurable
HOST = 'http://127.0.0.1'

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

def make_request(agent, method='GET', path='/echo', key=UPGRADE_KEY,
                 version='13', protocol=None):
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
                         HOST + path,
                         Headers(hdrs),
                         None)
