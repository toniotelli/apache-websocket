import psutil
import pytest

from twisted.internet import reactor
from twisted.web import client
from twisted.web.http_headers import Headers

HOST = 'http://127.0.0.1'

# from `openssl rand -base64 16`
UPGRADE_KEY = '36zg57EA+cDLixMBxrDj4g=='

# The maximum CPU usage we consider acceptable.
MAX_CPU_PERCENTAGE = 50

#
# Helpers
#

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

def any_cpus_railed():
   """Returns True if any CPU cores have crossed the MAX_CPU_PERCENTAGE."""
   percentages = psutil.cpu_percent(interval=0.5, percpu=True)
   
   for p in percentages:
       if p > MAX_CPU_PERCENTAGE:
           return True

   return False

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
@pytest.mark.skipif(any_cpus_railed(),
                    reason="current CPU load is too high to reliably test for spikes")
def test_cpu_load_does_not_spike_when_idle(agent):
    """
    A regression test for issue #9 (railed CPU when a WebSocket connection is
    open but idle).
    """
    response = yield make_request(agent)

    try:
        # Now that the connection is open, see if any CPUs are in trouble.
        assert not any_cpus_railed()
    finally:
        client.readBody(response).cancel() # close the connection
