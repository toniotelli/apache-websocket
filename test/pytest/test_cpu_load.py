import psutil
import pytest

from twisted.web import client

from testutil.fixtures import agent
from testutil.websocket import make_request

# The maximum CPU usage we consider acceptable.
MAX_CPU_PERCENTAGE = 50

#
# Helpers
#

def any_cpus_railed():
   """Returns True if any CPU cores have crossed the MAX_CPU_PERCENTAGE."""
   percentages = psutil.cpu_percent(interval=0.5, percpu=True)
   
   for p in percentages:
       if p > MAX_CPU_PERCENTAGE:
           return True

   return False

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
