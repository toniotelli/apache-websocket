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
skipped_count = 0
failed_count = 0

for test_id in test_ids:
    count += 1
    passed = True
    skipped = False

    result = index[test_id]
    path = os.path.join(results_dir, result['reportfile'])

    # Interpret the result for this test.
    # TODO: try to get a better description from the test result file
    description = '[{0}]'.format(test_id)

    test_result = result['behavior']
    close_result = result['behaviorClose']

    if test_result != 'OK' and test_result != 'INFORMATIONAL':
        if test_result == 'UNIMPLEMENTED':
            skipped = True
        else:
            passed = False
    elif close_result != 'OK' and close_result != 'INFORMATIONAL':
        passed = False

    # Print the TAP result.
    print('{0} {1} - {2}{3}'.format('ok' if passed else 'not ok',
                                    count,
                                    description,
                                    ' # SKIP unimplemented' if skipped else ''))

    # TODO: print diagnostics for debugging failed tests.

    if not passed:
        failed_count += 1
    if skipped:
        skipped_count += 1

# Print a final result.
print('# Autobahn|TestSuite {0}'.format('PASSED' if not failed_count else 'FAILED'))
print('# total {0}'.format(count))
print('# passed {0}'.format(count - failed_count - skipped_count))
print('# skipped {0}'.format(skipped_count))
print('# failed {0}'.format(failed_count))

exit(0 if not failed_count else 1)
