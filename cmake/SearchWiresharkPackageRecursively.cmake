function(search_wireshark_package_recursively SEARCH_PATH)
    file(GLOB_RECURSE WIRESHARK_CONFIG_FILES
        "${SEARCH_PATH}/WiresharkConfig.cmake"
    )

    if(NOT WIRESHARK_CONFIG_FILES)
        message(FATAL_ERROR
            "Could not find WiresharkConfig.cmake under ${SEARCH_PATH}"
        )
    endif()

    list(LENGTH WIRESHARK_CONFIG_FILES CONFIG_COUNT)

    if(CONFIG_COUNT GREATER 1)
        message(FATAL_ERROR
            "Multiple WiresharkConfig.cmake files found:\n"
            "${WIRESHARK_CONFIG_FILES}\n"
            "Please specify an installation prefix containing only one version."
        )
    endif()

    list(GET WIRESHARK_CONFIG_FILES 0 WIRESHARK_CONFIG_FILE)

    get_filename_component(Wireshark_DIR
        "${WIRESHARK_CONFIG_FILE}"
        DIRECTORY
    )

    set(Wireshark_DIR "${Wireshark_DIR}" PARENT_SCOPE)

    message(STATUS "Found Wireshark package: ${Wireshark_DIR}")
endfunction()

