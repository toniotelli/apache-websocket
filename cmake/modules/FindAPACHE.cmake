#
# FindApache
# ----------
#
# Finds Apache httpd on the system.
#
# The following variables are defined by this module:
#
# * APACHE_FOUND           - true if httpd was found on the system
# * APACHE_INCLUDE_DIRS    - set to the include paths for Apache httpd
#
# The following advanced variables may be used to influence the configuration:
#
# * APACHE_APXS_EXECUTABLE - the path to apxs
# * APACHE_INCLUDE_DIR
#

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

FIND_PROGRAM(APACHE_APXS_EXECUTABLE
             NAMES apxs apxs2)

IF(APACHE_APXS_EXECUTABLE)
  EXECUTE_PROCESS(COMMAND
                    ${APACHE_APXS_EXECUTABLE} -q includedir
                  OUTPUT_VARIABLE _apache_include_dir_hint
                  OUTPUT_STRIP_TRAILING_WHITESPACE
                  ERROR_QUIET)
ENDIF()

FIND_PATH(APACHE_INCLUDE_DIR
          NAMES httpd.h
          HINTS ${_apache_include_dir_hint})

#
# Standard find module boilerplate.
#

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(APACHE
  FOUND_VAR APACHE_FOUND
  REQUIRED_VARS
    APACHE_APXS_EXECUTABLE
    APACHE_INCLUDE_DIR)

IF(APACHE_FOUND)
  SET(APACHE_INCLUDE_DIRS ${APACHE_INCLUDE_DIR})
ENDIF()

MARK_AS_ADVANCED(APACHE_APXS_EXECUTABLE APACHE_INCLUDE_DIR)
