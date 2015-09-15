#! /usr/bin/python
#
# Presents the results of an Autobahn TestSuite run in TAP format.
#
# Copyright 2015 Jacob Champion
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from __future__ import print_function

from distutils.version import StrictVersion
import json
import os.path
import sys

# Read the index.
results_dir = 'test-results'
with open(os.path.join(results_dir, 'index.json'), 'r') as index_file:
    index = json.load(index_file)['AutobahnPython']

# Sort the tests by numeric ID so we print them in a sane order.
test_ids = index.keys()
test_ids.sort(key=StrictVersion)

# Print the TAP header.
print('TAP version 13')
print('1..{0!s}'.format(len(test_ids)))

count = 0
failed_count = 0

for test_id in test_ids:
    count += 1
    result = index[test_id]
    path = os.path.join(results_dir, result['reportfile'])

    # Interpret the result for this test.
    # TODO: try to get a better description from the test result file
    description = '[{0}]'.format(test_id)

    if result['behavior'] != 'OK':
        passed = False
    elif result['behaviorClose'] != 'OK':
        passed = False
    else:
        passed = True

    # Print the TAP result.
    print('{0} {1} - {2}'.format('ok' if passed else 'not ok',
                                 count,
                                 description))

    # TODO: print diagnostics for debugging failed tests.

    if not passed:
        failed_count += 1

# Print a final result.
sys.stderr.write(
    'Autobahn|TestSuite {0} ({1!s} total, {2!s} passed, {3!s} failed)\n'.format(
        'PASSED' if not failed_count else 'FAILED',
        count,
        count - failed_count,
        failed_count
    )
)

exit(0 if not failed_count else 1)
