#ifndef __STATS_STRUCTURES
#define __STATS_STRUCTURES

#include <stdint.h>

/*
 * typedefs.h: contains structure definitions that will be used for submitting
 * statistics and reports to main.c.
 *
 * DO NOT MODIFY THIS FILE! It will be replaced during grading.
 *
 */


/*
 * packet counters.
 */
typedef struct packet_stats_t {

	int tcp_packets;							// total TCP packets seen

	int udp_packets;							// total UDP packets seen

} packet_stats_t;


/*
 * per-destination TCP state
 */
typedef struct destination_stats_t {

	uint8_t dest_address[4];			// IP address in network byte order

	int complete_tcp_handshakes;	// successful TCP handshakes (syn, synack, ack
																// going to this destination)

	int half_open_connections;		// SYN and SYNACK seen but no follow-up ACK
																// to this destination

	int reset_connections;				// number of times RST packets were seen going
																// to/coming from this destination

	int unexpected_fins;					// FINs received by the destination address when
																// connection isn't open

} destination_stats_t;


/*
 * record of a detected port scanner
 */
typedef struct port_scan_stats_t {

	uint8_t src_address[4];				// IP address of attacker in network byte order

	struct timeval detection_time;// timestamp of when the attack commenced,
																// (ie, timestamp of the first packet in the
																// series that triggered the detection).

	int detection_score;					// the heat score of the attack at the time of
																// initial detection, as outlined by the
																// heuristic
} port_scan_stats_t;


#endif
