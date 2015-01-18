#include <pcap/pcap.h>
#include <string.h>
#include "detector.h"
#include "typedefs.h"

/*
 * main.c: contains code for starting the port scan detector and collecting
 * post-run statistics.
 *
 * DO NOT MODIFY THIS FILE! It will be replaced during grading.
 *
 */


/*
 * define some file-scope variables here
 */
static packet_stats_t packet_stats;
static int destination_stats_count = 0;
static destination_stats_t destination_stats[1024];
static int detected_scans_count = 0;
static port_scan_stats_t detected_scans[1024];

/*
 * define some functions for use by the detector code
 */
void report_total_packets(packet_stats_t stats);
void report_destination_stats(destination_stats_t stats);
void report_port_scan(port_scan_stats_t stats);

/*
 * used at termination to display execution data
 */
void dump_stats() {
	int counter;

	printf("--------------------\n");
	printf("overall statistics:\n");
	printf("--------------------\n");

	printf("%d tcp packets.\n", packet_stats.tcp_packets);
	printf("%d udp packets.\n", packet_stats.udp_packets);

	printf("--------------------\n");
	printf("statistics by destination:\n");
	printf("--------------------\n");

	for (counter = 0; counter < destination_stats_count; ++counter) {
		printf("%d.%d.%d.%d\n", destination_stats[counter].dest_address[0],
			destination_stats[counter].dest_address[1],
			destination_stats[counter].dest_address[2],
			destination_stats[counter].dest_address[3]);
		printf("%d complete handshakes.\n",
			destination_stats[counter].complete_tcp_handshakes);
		printf("%d half open connections.\n",
			destination_stats[counter].half_open_connections);
		printf("%d reset connections.\n",
			destination_stats[counter].reset_connections);
		printf("%d unexpected FINs.\n", destination_stats[counter].unexpected_fins);
		printf("-----\n");
	}

	printf("--------------------\n");
	printf("port scans detected:\n");
	printf("--------------------\n");

	for (counter = 0; counter < detected_scans_count; ++counter) {
		printf("%d.%d.%d.%d\n", detected_scans[counter].src_address[0],
			detected_scans[counter].src_address[1],
			detected_scans[counter].src_address[2],
			detected_scans[counter].src_address[3]);
		printf("%ld seconds.\n%ld useconds.\n",
			detected_scans[counter].detection_time.tv_sec,
			detected_scans[counter].detection_time.tv_usec);
		printf("%d initial detection score.\n",
			detected_scans[counter].detection_score);
		printf("-----\n");
	}
}

/*
 * updates the overall packet count statistics
 */
void report_total_packets(packet_stats_t stats) {
	packet_stats = stats;
}

/*
 * updates the per-destination connection statistics
 * this function may need to be called multiple times, once for each destination
 */
void report_destination_stats(destination_stats_t stats) {

	if (destination_stats_count <
		(int)(sizeof(destination_stats)/sizeof(destination_stats_t))) {
		destination_stats[destination_stats_count++] = stats;
	} else {
		printf("destination stats table full. %d entries needed.\n",
			++destination_stats_count);
	}
}

/*
 * reports a port scan activity
 * this function should be called immediately when a port scan is detected
 */
void report_port_scan(port_scan_stats_t stats) {

	int counter;

	// ignore duplicates
	for (counter = 0; counter < detected_scans_count; ++counter) {
		if (memcmp(detected_scans[counter].src_address, stats.src_address, 4)
			== 0) {
			return;
		}
	}

	if (detected_scans_count <
		(int)(sizeof(detected_scans)/sizeof(port_scan_stats_t))) {
		detected_scans[detected_scans_count++] = stats;
	} else {
		printf("port scan table full. require %d entries needed.\n",
			++detected_scans_count);
	}
}

/*
 * executive entry point
 */
int main(int argc, char** argv) {

	char errbuf[PCAP_ERRBUF_SIZE];
	if (argc != 2) {
		printf("usage: %s filename\n", argv[0]);
		return 1;
	}

	pcap_t* handle = pcap_open_offline(argv[1], errbuf);
	if (handle == NULL) {
		printf("error: %s\n", errbuf);
		return 1;
	}

	run_detector(handle);
	dump_stats();

	return 0;
}
