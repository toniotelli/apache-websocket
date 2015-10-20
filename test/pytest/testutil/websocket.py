from twisted.web.http_headers import Headers

# TODO: make this configurable
HOST = 'http://127.0.0.1'

# from `openssl rand -base64 16`
UPGRADE_KEY = '36zg57EA+cDLixMBxrDj4g=='

# base64(SHA1(UPGRADE_KEY:"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
UPGRADE_ACCEPT = 'eGic2At3BJQkGyA4Dq+3nczxEJo='

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

