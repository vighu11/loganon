include_directories(AFTER ${loganon_SOURCE_DIR}/src/include)

# PCRE
include_directories(AFTER ${PCRE_INCLUDE_DIR})

add_library(loganon SHARED input.c)
set_target_properties(loganon PROPERTIES SOVERSION 1)

target_link_libraries(loganon ${PCRE_PCRE_LIBRARY})

