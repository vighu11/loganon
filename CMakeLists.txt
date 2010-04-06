cmake_minimum_required(VERSION 2.6)
project(loganon C)

set(CMAKE_BUILD_TYPE "DEBUG")
set(CMAKE_VERBOSE_MAKEFILE ON)

include(CheckIncludeFile)
include(CheckFunctionExists)
include(CheckLibraryExists)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${loganon_SOURCE_DIR}/cmake)

if(WIN32)
        add_definitions(-DWIN32)
        add_definitions(-D_WIN32)
else(WIN32)
        add_definitions(-DUNIX)
endif(WIN32)

FIND_PACKAGE(PCRE REQUIRED)

add_subdirectory(src)
