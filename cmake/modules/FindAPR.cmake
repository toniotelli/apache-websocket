#
# FindAPR
# -------
#
# Finds the APR and APRUtil libraries (or, in the case of APR-2, just APR).
#
# The following variables are defined by this module:
#
# * APR_FOUND        - true if APR[Util] was found on the system
# * APR_VERSION      - set to the discovered version of APR
# * APR_INCLUDE_DIRS - set to the include paths for APR[Util]
# * APR_LIBRARIES    - set to the libraries to link against for APR[Util]
# * APR_UTIL_VERSION - set to the discovered version of APRUtil (if any)
#
# Additionally, the following advanced variables may be used to influence
# discovery:
#
# * APR[_UTIL]_CONFIG_EXECUTABLE - the path of the apr-/apu-config program
# * APR[_UTIL]_INCLUDE_DIR       - the APR[Util] include directory
# * APR[_UTIL]_LIBRARY           - the path of the APR[Util] link library
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

#
# Helper macro for apr-/apu-config discovery.
#
#  executable  - the path to the apr-/apu-config binary
#  version_var - set to the APR/APU version
#  include_var - set to a list of required include paths
#  libs_var    - set to a list of required library paths
#
MACRO(_APR_CONFIG_DISCOVER executable version_var includes_var libs_var)
  EXECUTE_PROCESS(COMMAND
                    ${executable} --version
                  OUTPUT_VARIABLE ${version_var}
                  OUTPUT_STRIP_TRAILING_WHITESPACE
                  ERROR_QUIET)
  EXECUTE_PROCESS(COMMAND
                    ${executable} --includedir
                  OUTPUT_VARIABLE ${includes_var}
                  OUTPUT_STRIP_TRAILING_WHITESPACE
                  ERROR_QUIET)

  # Getting the library path is trickier, since apr-config doesn't have a
  # library directory flag.
  EXECUTE_PROCESS(COMMAND
                    ${executable} --link-ld
                  OUTPUT_VARIABLE _link_ld
                  OUTPUT_STRIP_TRAILING_WHITESPACE
                  ERROR_QUIET)

  # Get all the -L arguments in a list.
  STRING(REGEX MATCHALL
           "(^| )-L([^ ]+)"
         _dir_list
         ${_link_ld})

  SET(${libs_var} "")

  # Strip the -L off of the front of each argument, and put it into the hint.
  FOREACH(arg ${_dir_list})
    STRING(REGEX REPLACE
             "^ ?-L"
             ""
           arg
           ${arg})
    LIST(APPEND ${libs_var} ${arg})
  ENDFOREACH()
ENDMACRO()

#
# Set up hints based on apr-config/apu-config.
#

# Keep track of which variables should be considered required.
SET(_required_vars APR_INCLUDE_DIR APR_LIBRARY)

FIND_PROGRAM(APR_CONFIG_EXECUTABLE
             NAMES apr-config apr-1-config apr-2-config)

IF(APR_CONFIG_EXECUTABLE)
  _APR_CONFIG_DISCOVER(${APR_CONFIG_EXECUTABLE}
                         _apr_version
                         _apr_include_dir_hint
                         _apr_library_dir_hint)
ENDIF(APR_CONFIG_EXECUTABLE)

IF(_apr_version AND _apr_version VERSION_LESS "2.0")
  # We need APR-Util as well.
  LIST(APPEND _required_vars APR_UTIL_INCLUDE_DIR APR_UTIL_LIBRARY)

  FIND_PROGRAM(APR_UTIL_CONFIG_EXECUTABLE
               NAMES apu-config apu-1-config)

  IF(APR_UTIL_CONFIG_EXECUTABLE)
    _APR_CONFIG_DISCOVER(${APR_UTIL_CONFIG_EXECUTABLE}
                           _apu_version
                           _apu_include_dir_hint
                           _apu_library_dir_hint)
  ENDIF(APR_UTIL_CONFIG_EXECUTABLE)
ENDIF()

#
# Now actually perform the discovery based on the hints we got above.
#

FIND_PATH(APR_INCLUDE_DIR
          NAMES apr.h
          HINTS ${_apr_include_dir_hint})
FIND_LIBRARY(APR_LIBRARY
             NAMES apr-1 apr-2
             HINTS ${_apr_library_dir_hint}
             NO_DEFAULT_PATH)
SET(APR_VERSION ${_apr_version})

IF(_apu_version)
  FIND_PATH(APR_UTIL_INCLUDE_DIR
            NAMES apu.h
            HINTS ${_apu_include_dir_hint})
  FIND_LIBRARY(APR_UTIL_LIBRARY
               NAMES aprutil-1
               HINTS ${_apu_library_dir_hint}
               NO_DEFAULT_PATH)
  SET(APR_UTIL_VERSION ${_apu_version})
ENDIF()

#
# Standard find module boilerplate.
#

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(APR
  FOUND_VAR APR_FOUND
  REQUIRED_VARS ${_required_vars}
  VERSION_VAR APR_VERSION)

IF(APR_FOUND)
  SET(APR_INCLUDE_DIRS ${APR_INCLUDE_DIR} ${APR_UTIL_INCLUDE_DIR})
  SET(APR_LIBRARIES    ${APR_LIBRARY}     ${APR_UTIL_LIBRARY})
ENDIF()

MARK_AS_ADVANCED(APR_CONFIG_EXECUTABLE APR_INCLUDE_DIR APR_LIBRARY
                 APR_UTIL_CONFIG_EXECUTABLE APR_UTIL_INCLUDE_DIR
                 APR_UTIL_LIBRARY)
