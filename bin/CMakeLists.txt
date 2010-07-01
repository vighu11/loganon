include_directories(AFTER ${loganon_SOURCE_DIR}/lib/include)

# PCRE
include_directories(AFTER ${PCRE_INCLUDE_DIR})

link_directories(${loganon_SOURCE_DIR}/src/)

add_executable(loganon-tool main.c)

target_link_libraries(loganon-tool ${PCRE_PCRE_LIBRARY} loganon)

