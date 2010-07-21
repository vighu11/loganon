include_directories(AFTER ${loganon_SOURCE_DIR}/lib/include)

# PCRE
include_directories(AFTER ${PCRE_INCLUDE_DIR})

# DUMBNET
include_directories(AFTER ${DUMBNET_INCLUDE_DIRS})

#OPENSSL
include_directories(AFTER ${OPENSSL_INCLUDE_DIR})

#PCAP
include_directories(AFTER ${PCAP_INCLUDE_DIRS})



add_library(parser SHARED client.c loganon_parser.c loganon_parser_pcap.c
	loganon_parser_syslog.c loganon_pcre loganon_queue.c)

add_executable(client client.c )
set_target_properties(parser PROPERTIES SOVERSION 1)

target_link_libraries(parser ${PCRE_PCRE_LIBRARY} ${DUMBNET_LIBRARIES}
	${OPENSSL_LIBRARIES} ${PCAP_LIBRARIES} loganon)

target_link_libraries(client ${PCRE_PCRE_LIBRARY} ${DUMBNET_LIBRARIES}
   	${OPENSSL_LIBRARIES} ${PCAP_LIBRARIES} parser loganon)
