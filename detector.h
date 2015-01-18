#include <stdio.h>
#include <pcap/pcap.h>
#include "typedefs.h"
#include <arpa/inet.h>

extern void report_total_packets(packet_stats_t stats);
extern void report_destination_stats(destination_stats_t stats);
extern void report_port_scan(port_scan_stats_t stats);

void run_detector(pcap_t* handle);
uint16_t unpack_uint16(const uint8_t* buf);
uint32_t unpack_uint32(const uint8_t* buf);

#define HASH_LOG 11
#define MAX_Hashsize (1 << HASH_LOG)




typedef enum {FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, SYNACK} flag_t;
typedef enum {INITIAL, SYN_REC, SYNACK_REC, ACK_REC, CLOSED, RESET, WRONG_FIN} state_t;


typedef struct ethernet_hdr_t {

	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint8_t ethertype[2];
	uint8_t data[0];

} ethernet_hdr_t;


typedef struct ip_hdr_t {

	uint8_t version_ihl;
	uint8_t dscp_ecn;
	uint8_t total_len[2];
	uint8_t id[2];
	uint8_t flags_offset[2];
	uint8_t ttl;
	uint8_t protocol;
	uint8_t header_checksum[2];
	uint8_t src_ip[4];
	uint8_t dst_ip[4];
	uint8_t data[0];

}ip_hdr_t;


typedef struct tcp_hdr_t {
	
	uint8_t src_port[2];
	uint8_t dst_port[2];
	uint8_t seq_num[4];
	uint8_t ack_num[4];
	uint8_t offset_res;
	uint8_t flag;
	uint8_t win[2];
	uint8_t checksum;
	uint8_t urgent;

}tcp_hdr_t;



typedef struct packet_t {

	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	flag_t flag;
	uint8_t protocol;
	struct timeval ts;
}packet_t;



typedef struct connection {

	uint16_t src_port;
	uint16_t dst_port;
	uint32_t src_ip;
	uint32_t dst_ip;
	state_t state;
	struct connection* next;

}connection;


typedef struct destination {
	
	uint32_t dst_ip;
	int complete_tcp_handshakes;
	int half_conn;
	int dst_next;
	int conn_next;
	int reset_conn;
	int wrong_fins;
} destination;

typedef struct portscan_node {

	uint32_t src_ip;
	uint16_t dst_port;
	struct timeval ts;
	uint16_t heat_score;
	uint16_t cumulative_heat_score;
	struct portscan_node* next;

}portscan_node;