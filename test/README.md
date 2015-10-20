# Testing with Autobahn

This test script makes use of
[Autobahn|TestSuite](http://autobahn.ws/testsuite/).

## Prerequisites

* Python 2.7.x (TestSuite doesn't do Python 3 yet)
* [pip](https://pip.pypa.io/)
* GNU Make (or just run each test suite manually)

## Setup

The required Python packages are listed in requirements.txt. On Linux, you can
install them by executing the following from this directory:

    $ [sudo] pip install -r requirements.txt

If you don't want to install globally, you can alternatively run

    $ pip install -r requirements.txt --user
    $ export PATH=$PATH:$HOME/.local/bin

See your pip documentation for other installation options.

## Testing

Compile and install the `mod_websocket_echo` and `mod_websocket_dumb_increment`
example modules (see the main project README for instructions), include (or
copy-paste) the `test.conf` snippet from this directory in your server config,
and restart your server.  (Note that the test suite assumes the server is
running at `ws://localhost`.)

Then, from this directory, run

    $ make test

The test suite is large, so it may take a few minutes to run. The results will
be parsed and output as a [TAP](http://testanything.org) stream.

If you want to just get the TAP output itself so you can pipe it into your
favorite [TAP consumer](http://testanything.org/consumers.html), run the
following *after* you have already run the test suite once and generated the
`test-results` folder:

    $ ./aggregate.py

This will output the results again without re-running the Autobahn test suite.

## Adding Tests

New pytest suites can be added directly to the `pytest/` directory.

If you need to run a program that isn't pytest-based, add it to the `commands`
array in `tests.yaml`. Said program _must_ output valid TAP, version 13 or
prior.
