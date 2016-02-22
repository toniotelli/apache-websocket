#
# Library Configuration
#

CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(mod_websocket C)

#
# Options
#

OPTION(BUILD_EXAMPLES "Build the example plugins"         OFF)
OPTION(INSTALL_PDB    "Install .pdb files (if generated)" OFF)


IF(WIN32)
  ## Build For Windows
  INCLUDE(cmake/CMakeWin32.cmake)
ELSE(WIN32)
  ## Build on Unix platforms using FindAPACHE.cmake and FindAPR.cmake
  INCLUDE(cmake/CMakeUnix.cmake)
ENDIF(WIN32)
