all:
	gcc -DHAVE_CONFIG_H -Iws-api -I. `pkg-config --cflags glib-2.0` -W -Wall -g -O2 -c print.c
	gcc -DHAVE_CONFIG_H -I. -Iws-api -I. -I. `pkg-config --cflags glib-2.0` -I/usr/include/wireshark   -W -Wall -g -O2 -c shark-test.c
	gcc -W -Wall -g -O2   -o shark-test  shark-test.o print.o  -lpcap -lwireshark -lwiretap  -L./ws-api/include/

clean:
	rm *.o shark-test
