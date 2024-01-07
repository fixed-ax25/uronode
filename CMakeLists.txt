cmake_minimum_required(VERSION 3.20)
project(uronode LANGUAGES C)

include(CheckIncludeFile)

set(URONODE_SUPPORT_AX25 ON CACHE BOOL "Include support for AX.25")
set(URONODE_SUPPORT_NETROM ON CACHE BOOL "Include support for NET/ROM")
set(URONODE_SUPPORT_ROSE ON CACHE BOOL "Include support for ROSE")
set(URONODE_SUPPORT_FLEXNET OFF CACHE BOOL "Include support for FLEXNET")
set(URONODE_SUPPORT_MHEARD ON CACHE BOOL "Include supoprt for MHeard")
set(URONODE_SUPPORT_AX25_AUTOROUTER OFF CACHE BOOL "Include support for AX.25 autorouter")
set(URONODE_SUPPORT_TCPIP OFF CACHE BOOL "Include support for TCP/IP")
set(URONODE_CONFIG_DIR "/etc/ax25/uronode" CACHE PATH "directory for uronode config files")
set(URONODE_STATE_DIR "/var/uronode" CACHE PATH "directory for uronode runtime state files")

find_package(ZLIB)
find_library(AX25 NAMES ax25)
find_library(AX25IO NAMES ax25io)
check_include_file(netax25/axlib.h HAVE_AX25_HEADERS)

set(HAVE_AX25 OFF)
set(HAVE_NETROM OFF)
set(HAVE_ROSE OFF)
set(HAVE_FLEX OFF)
set(HAVE_JHEARD OFF)
set(HAVE_AUTOROUTE OFF)

set(HAVE_TCPIP ${URONODE_SUPPORT_TCPIP})

set(COMMON_SRC user.c util.c)
if(ZLIB_FOUND)
  set(COMMON_LIBS ${COMMON_LIBS} ZLIB::ZLIB)
  set(HAVE_ZLIB ON)
else()
  set(HAVE_ZLIB OFF)
endif()
if(URONODE_SUPPORT_AX25)
  if(AX25 AND AX25IO AND HAVE_AX25_HEADERS)
    set(HAVE_AX25 ON)
    set(COMMON_LIBS ${COMMON_LIBS} ${AX25} ${AX25IO})

    set(HAVE_NETROM ${URONODE_SUPPORT_NETROM})
    set(HAVE_FLEX ${URONODE_SUPPORT_FLEXNET})
    set(HAVE_ROSE ${URONODE_SUPPORT_ROSE})
    set(HAVE_JHEARD ${URONODE_SUPPORT_MHEARD})    
    set(HAVE_AUTOROUTE ${URONODE_SUPPORT_AX25_AUTOROUTER})
  else()
    message(FATAL_ERROR "Requested AX.25 family support and couldn't find libax25 or libax25io")
  endif()
endif()

# all sources in this project use POSIX / POSIX SUS features.
add_compile_definitions(_DEFAULT_SOURCE _XOPEN_SOURCE=600)
# find the generated config.h without needing to fix every target
include_directories(${CMAKE_CURRENT_BINARY_DIR})
# make the compiler as noisy as possible :)
add_compile_options(-Wall)

configure_file(config.h.in config.h @ONLY)

add_executable(uronode
  node.c
  cmdparse.c
  config.c
  command.c
  jheard.c
  axcalluser.c
  gateway.c
  extcmd.c
  procinfo.c
  router.c
  system.c
  sysinfo.c
  ipc.c
  ${COMMON_SRC})
target_link_libraries(uronode PRIVATE ${COMMON_LIBS})

add_executable(nodeusers
  nodeusers.c
  ${COMMON_SRC})
target_link_libraries(nodeusers PRIVATE ${COMMON_LIBS})

if(HAVE_FLEX)
  add_executable(flexd
    flexd.c
    procinfo.c)
  target_link_libraries(flexd PRIVATE ${COMMON_LIBS})
endif()

add_executable(axdigi
  axdigi.c)
target_link_libraries(axdigi PRIVATE ${COMMON_LIBS})

add_executable(calibrate
  calibrate.c)
target_link_libraries(calibrate PRIVATE ${COMMON_LIBS})
