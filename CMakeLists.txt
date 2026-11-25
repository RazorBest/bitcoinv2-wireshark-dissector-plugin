cmake_minimum_required(VERSION 3.16)
project(bitcoinv2 VERSION 0.0.1 LANGUAGES C)
include(GNUInstallDirs)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
# Equivalent to -std=c11 instead of -gnu=c11
set(CMAKE_C_EXTENSIONS OFF)
# Includes compile_commands.json in the build directory, which could be used by language servers
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(INSTALL_ON_SYSTEM "If enabled, install the plugin in the default wireshark plugins directory" OFF)

if(NOT WIRESHARK_CMAKE_PACKAGE_SEARCH_PATH STREQUAL "")
    include("${CMAKE_SOURCE_DIR}/cmake/SearchWiresharkPackageRecursively.cmake")
    search_wireshark_package_recursively("${WIRESHARK_CMAKE_PACKAGE_SEARCH_PATH}")
else()
    find_package(Wireshark CONFIG REQUIRED)
endif()

message(STATUS "Wireshark config dir:  ${Wireshark_DIR}")
message(STATUS "Wireshark config file: ${Wireshark_CONFIG}")
message(STATUS "Wireshark lib dir in ${Wireshark_LIB_DIR}")

set(SOURCES src/bitcoinv2.c)

# Do not switch to shared. Wireshark needs modules
add_library(${PROJECT_NAME} MODULE ${SOURCES})

set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION ${PROJECT_VERSION}}
    PREFIX ""
    DEFINE_SYMBOL ""
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

target_link_libraries(${PROJECT_NAME} PRIVATE epan)

if(INSTALL_ON_SYSTEM)
    set(LIBRARY_INSTALL_DESTINATION ${Wireshark_PLUGIN_INSTALL_DIR}/epan)
else()
    set(LIBRARY_INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()


if(NOT Wireshark_PLUGINS_ENABLED)
    message(WARNING "Wireshark was compiled without support for plugins")
endif()

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "${Wireshark_INSTALL_PREFIX}"
        CACHE PATH "Installation prefix" FORCE)
endif()

include_directories(${Wireshark_INCLUDE_DIR})
link_directories(${Wireshark_LIB_DIR})

install(TARGETS ${PROJECT_NAME}
    LIBRARY DESTINATION ${LIBRARY_INSTALL_DESTINATION}
)
