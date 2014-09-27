CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(Swarm)


if(NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type selected, default to Release")
    SET(CMAKE_BUILD_TYPE "Release")
endif()

SET(CMAKE_CXX_FLAGS_RELEASE "-Wall -O3 -std=c++0x")
SET(CMAKE_CXX_FLAGS_DEBUG   "-Wall -O0 -std=c++0x -g -DSWARM_DEBUG")
SET(CMAKE_SHARED_LINKER_FLAGS "-lpcap -dynamiclib")

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

# cmake_policy(SET CMP0015 NEW)

INCLUDE_DIRECTORIES(${INC_DIR} ./src)
LINK_DIRECTORIES(${LIB_DIR})

# Build library

FILE(GLOB BASESRCS "src/*.cc" "src/proto/*.cc" "src/utils/*.cc")
FILE(GLOB TESTSRCS "test/*.cc")
FILE(GLOB HEADERS "src/swarm/*.h")

ADD_LIBRARY(swarm SHARED ${BASESRCS})
IF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    TARGET_LINK_LIBRARIES(swarm pcap pthread rt ev)
ELSE(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    TARGET_LINK_LIBRARIES(swarm pcap pthread ev)
ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

INSTALL(TARGETS swarm LIBRARY DESTINATION lib)
INSTALL(FILES src/swarm.h DESTINATION include/)
INSTALL(FILES ${HEADERS} DESTINATION include/swarm)



ADD_EXECUTABLE(swarm-test ${TESTSRCS})
TARGET_LINK_LIBRARIES(swarm-test swarm)

ADD_EXECUTABLE(swarm-bench apps/swarm-bench.cc apps/optparse.cc)
TARGET_LINK_LIBRARIES(swarm-bench swarm)
ADD_EXECUTABLE(swarm-tool apps/swarm-tool.cc apps/optparse.cc)
TARGET_LINK_LIBRARIES(swarm-tool swarm)

