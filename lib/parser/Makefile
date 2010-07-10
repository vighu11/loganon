CC=gcc
EXEC=client
CFLAGS=-Wall -g
LDFLAGS=-lpcap -lpcre

all: $(EXEC)

#
# BINARY FILE FOR TESTS
#
$(EXEC): client.o loganon_parser.o loganon_parser_pcap.o loganon_parser_syslog.o loganon_queue.o loganon_pcre.o
	$(CC) -o $@ $^ $(LDFLAGS)

#
# OBJECT FILES
#
client.o: client.c loganon_parser.h loganon_parser_pcap.h
	$(CC) -o $@ -c $< $(CFLAGS)

loganon_parser.o: loganon_parser.c debug_utils.h files_extensions.h loganon_errors.h loganon_parser_pcap.h
	$(CC) -o $@ -c $< $(CFLAGS)

loganon_parser_pcap.o: loganon_parser_pcap.c debug_utils.h proto_utils.h loganon_errors.h loganon_queue.h
	$(CC) -o $@ -c $< $(CFLAGS)

loganon_parser_syslog.o: loganon_parser_syslog.c debug_utils.h loganon_errors.h loganon_pcre.h
	$(CC) -o $@ -c $< $(CFLAGS)

loganon_queue.o: loganon_queue.c loganon_queue.h
	$(CC) -o $@ -c $< $(CFLAGS)

loganon_pcre.o: loganon_pcre.c loganon_pcre.h
	$(CC) -o $@ -c $< $(CFLAGS)

#
# HEADER FILES
#
loganon_queue.h: loganon_structs.h loganon_errors.h

loganon_pcre.h: loganon_structs.h loganon_errors.h

loganon_parser.h: loganon_errors.h

loganon_parser_pcap.h: loganon_structs.h loganon_errors.h

loganon_parser_syslog.h: loganon_structs.h loganon_errors.h

#
# CLEAN
#
.PHONY: 
clean:
	rm -rf *.o *~

reset: clean
	rm -rf $(EXEC)
