add_custom_target(documentation COMMAND python3 -m sphinx ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/_build ${CMAKE_CURRENT_SOURCE_DIR}/index.rst)
