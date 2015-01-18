CC = gcc
CCOPTS = -c -g -Wall -ggdb -funsigned-char
LINKOPTS = -ggdb

all: main

main: main.o \
	detector.o 
	$(CC) $(LINKOPTS) -o $@ $^ -lpcap

#pcap_test: ../common/autobuf.o \
	../common/common_utils.o \
	../common/common_utils_oop.o \
	../common/ip_port.o \
	../common/ip_address.o \
	../common/ipv6_address.o \
	../common/ironscale_packet.o \
	../common/mac_address.o \
	../common/std_packet.o \
	../common/timed_barrier.o \
	../common/timer.o \
	bin/pcap_interface.o \
	bin/iron_pcap.o \
	bin/ironscale_defs.o \
	bin/ironscale_detector.o \
	bin/ironscale_service.o \
	bin/packet_frag.o \
	bin/pcap_test.o
#	$(CC) $(LINKOPTS) -o $@ $^ -lpcap

main.o: main.c typedefs.h
	$(CC) $(CCOPTS) -o $@ main.c

detector.o: detector.h detector.c typedefs.h
	$(CC) $(CCOPTS) -o $@ detector.c

clean:
	rm -rf *.o main

