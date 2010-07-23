# Loganon library
include_directories(AFTER ${loganon_SOURCE_DIR}/lib/include)
# PCRE
include_directories(AFTER ${PCRE_INCLUDE_DIR})
# DUMBNET
include_directories(AFTER ${DUMBNET_INCLUDE_DIRS})

add_executable(ipanon ipanon.c)
target_link_libraries(ipanon ${PCRE_PCRE_LIBRARY} ${DUMBNET_LIBRARIES} loganon)

add_executable(stranon stranon.c)
target_link_libraries(stranon ${PCRE_PCRE_LIBRARY} ${DUMBNET_LIBRARIES} loganon)

enable_testing()
add_test(TestIPAnon ipanon)
