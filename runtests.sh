#! /bin/bash

echo Starting test server...
make start-test-server || exit 1
echo

echo Running tests...
(cd test && wstest -m fuzzingclient && ./aggregate.py)
echo

echo Stopping test server...
make stop-test-server
