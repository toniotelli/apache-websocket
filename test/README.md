# Testing with Autobahn

This test script makes use of
[Autobahn|TestSuite](http://autobahn.ws/testsuite/).

## Prerequisites

* Python 2.7.x (TestSuite doesn't do Python 3 yet)
* [pip](https://pip.pypa.io/)
* GNU Make (or just run wstest manually)

## Setup

The required Python packages are listed in requirements.txt. On Linux, you can
install them by executing the following from this directory:

    $ [sudo] pip install -r requirements.txt

If you don't want to install globally, you can alternatively run

    $ pip install -r requirements.txt --user
    $ export PATH=$PATH:$HOME/.local/bin

See your pip documentation for other installation options.

## Testing

Compile and install the `mod_websocket_echo` example module (see the main
project README for instructions). The test script assumes the module is
listening at `ws://localhost/echo`; if this is not correct for your system,
modify `fuzzingclient.json` to point to the correct URI.

Then, from this directory, run

    $ make test

The test suite is large, so it may take a few minutes to run. The results will
be parsed and output as a [TAP](http://testanything.org) stream.

If you want to just get the TAP output itself so you can pipe it into your
favorite [TAP consumer](http://testanything.org/consumers.html), run the
following *after* you have already run the test suite once and generated the
`test-results` folder:

    $ PYTHONIOENCODING=utf-8 ./present.py

This will output the results again without running the entire test suite. (The
`PYTHONIOENCODING` envvar is to ensure that the script prints UTF-8 correctly;
you'll know you've forgotten it if you get something like `UnicodeEncodeError:
'ascii' codec can't encode character u'\xb5' in position 90: ordinal not in
range(128)'`.)

