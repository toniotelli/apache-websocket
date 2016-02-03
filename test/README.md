# Testing with Autobahn

This test script makes use of
[Autobahn|TestSuite](http://autobahn.ws/testsuite/).

## Prerequisites

* Python 2.7.x (TestSuite doesn't do Python 3 yet)
* [pip](https://pip.pypa.io/)
* GNU Autotools (or just run the test server and each test suite manually)

## Setup

The required Python packages are listed in requirements.txt. On Linux, you can
install them by executing the following from this directory:

    $ [sudo] pip install -r requirements.txt

If you don't want to install globally, you can alternatively run

    $ pip install -r requirements.txt --user
    $ export PATH=$PATH:$HOME/.local/bin

or install via `virtualenv` or similar. See your pip/virtualenv documentation
for other installation options.

## Testing

For now, the test suite can only be run fully automatically with Linux and GNU
Autotools; Windows instructions are forthcoming.

### Linux/Autotools

After you have installed the prerequisites, run

    $ make check

from the top-level directory. The test suite is large, so it may take a few
minutes to run. The results will be parsed and output as a
[TAP](http://testanything.org) stream.

If you want to just get the TAP output itself so you can pipe it into your
favorite [TAP consumer](http://testanything.org/consumers.html), run the
following *after* you have already run the test suite once and generated the
`test/test-results` folder:

    $ make start-test-server
    $ cd test
    $ ./aggregate.py

This will output the results again without re-running the Autobahn test suite.
Remember to stop the standalone test server afterwards with

    $ cd ..
    $ make stop-test-server

## Adding Tests

New pytest suites can be added directly to the `pytest/` directory.

If you need to run a program that isn't pytest-based, add it to the `commands`
array in `tests.yaml`. Said program _must_ output valid TAP, version 13 or
prior.
