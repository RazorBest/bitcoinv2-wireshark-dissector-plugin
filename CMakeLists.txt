cmake_minimum_required(VERSION 3.16)
project(bitcoinv2 VERSION 0.0.1 LANGUAGES C CXX)
include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# Better portability
set(CMAKE_CXX_EXTENSIONS OFF)

option(INSTALL_ON_SYSTEM "If enabled, install the plugin in the default wireshark plugins directory" OFF)

find_package(Wireshark CONFIG REQUIRED)
message(STATUS "Wireshark config dir:  ${Wireshark_DIR}")
message(STATUS "Wireshark config file: ${Wireshark_CONFIG}")

set(SOURCES src/bitcoinv2.cpp)

# Do not switch to shared. Wireshark needs modules
add_library(${PROJECT_NAME} MODULE ${SOURCES})

set_target_properties(${PROJECT_NAME} PROPERTIES
    PREFIX ""
    DEFINE_SYMBOL ""
)

# set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(bitcoinv2 PROPERTIES VERSION ${PROJECT_VERSION}})

target_link_libraries(${PROJECT_NAME} PRIVATE epan)

if(INSTALL_ON_SYSTEM)
    set(LIBRARY_INSTALL_DESTINATION ${Wireshark_PLUGIN_INSTALL_DIR}/epan)
else()
    set(LIBRARY_INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

find_package(Wireshark)

if (Wireshark_FOUND)

    message(STATUS "Wireshark found in ${Wireshark_LIB_DIR}")

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
endif()
