include_directories(AFTER ${loganon_SOURCE_DIR}/lib/include)

# PCRE
include_directories(AFTER ${PCRE_INCLUDE_DIR})

# DUMBNET
include_directories(AFTER ${DUMBNET_INCLUDE_DIRS})

#OPENSSL
include_directories(AFTER ${OPENSSL_INCLUDE_DIR})


add_library(loganon SHARED random.c ip_anon.c str_anon.c)
set_target_properties(loganon PROPERTIES SOVERSION 1)

target_link_libraries(loganon ${PCRE_PCRE_LIBRARY} ${DUMBNET_LIBRARIES}
	${OPENSSL_LIBRARIES} )

add_subdirectory(tests)
add_subdirectory(parser)
