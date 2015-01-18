#include <string.h>
#include "detector.h"
#include "typedefs.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>

portscan_node* portscan_hash[MAX_Hashsize] = {0};
destination* dst_hash[MAX_Hashsize] = {0};
struct entry_s {
    short key;
    char *value;
    struct entry_s *next;
};
 
typedef struct entry_s entry_t;
 
struct hashtable_s {
    int size;
    struct entry_s **table; 
};
 
typedef struct hashtable_s hashtable_t;
 
 
/* Create a new hashtable. */
hashtable_t *ht_create( int size ) {
 
    hashtable_t *hashtable = NULL;
    int i;
 
    if( size < 1 ) return NULL;
 
    /* Allocate the table itself. */
    if( ( hashtable = malloc( sizeof( hashtable_t ) ) ) == NULL ) {
        return NULL;
    }
 
    /* Allocate pointers to the head nodes. */
    if( ( hashtable->table = malloc( sizeof( entry_t * ) * size ) ) == NULL ) {
        return NULL;
    }
    for( i = 0; i < size; i++ ) {
        hashtable->table[i] = NULL;
    }
 
    hashtable->size = size;
 
    return hashtable;   
}
 
/* Hash a string for a particular hash table. */
int ht_hash( hashtable_t *hashtable, short key ) {
 
    unsigned long int hashval;
    int i = 0;
 
    /* Convert our string to an integer */
    while( hashval < ULONG_MAX && i < sizeof(key)) {
        hashval = hashval << 8;
        hashval += key;
        i++;
    }
 
    return hashval % hashtable->size;
}
 
/* Create a key-value pair. */
entry_t *ht_newpair( short key, char *value ) {
    entry_t *newpair;
 
    if( ( newpair = malloc( sizeof( entry_t ) ) ) == NULL ) {
        return NULL;
    }
 
    if( ( newpair->key =  key ) == NULL ) {
        return NULL;
    }
 
    if( ( newpair->value = strdup( value ) ) == NULL ) {
        return NULL;
    }
 
    newpair->next = NULL;
 
    return newpair;
}
 
uint16_t unpack_uint16(const uint8_t* buf) {
	uint16_t val;
	memcpy(&val, buf, sizeof(uint16_t));
	return ntohs(val);
}

uint32_t unpack_uint32(const uint8_t* buf) {
	uint32_t val;
	memcpy(&val, buf, sizeof(uint32_t));
	return ntohl(val);
}

void pack_uint32(uint32_t val, uint8_t* buf) {

	val = htonl(val);
	memcpy(buf, &val, sizeof(uint32_t));

}
 // keeping track of all the flags
flag_t tcp_flags(const tcp_hdr_t* tcp_header) {

	uint8_t flag = tcp_header->flag;
	uint8_t base = 255;
	
	if ((flag & 2) && (flag & 16))
		return SYNACK;
	else if (flag & 1)
		return FIN;
	else if(flag & 2)
		return SYN;
	else if(flag & 4)
		return RST;
	else if(flag & 8)
		return PSH;
	else if(flag & 16)
		return ACK;
	else if(flag & 32)
		return URG;
	
}


void node_updatetracker (struct packet_t* packet, const uint8_t* frame, struct pcap_pkthdr* metadata) {
	
	const ethernet_hdr_t* ether_header;
	const ip_hdr_t* ip_header;
	const tcp_hdr_t* tcp_header; 

	ether_header = (const ethernet_hdr_t*) frame; //get pointer to ethernet header
	ip_header = (const ip_hdr_t*)ether_header->data; // get pointer to ip_header
	tcp_header = (const tcp_hdr_t*)ip_header->data;

	packet->src_ip = unpack_uint32(ip_header->src_ip);
	packet->dst_ip = unpack_uint32(ip_header->dst_ip);
	packet->src_port = unpack_uint16(tcp_header->src_port);
	packet->dst_port = unpack_uint16(tcp_header->dst_port);
	packet->flag = tcp_flags(tcp_header);
	packet->protocol = ip_header->protocol;
	packet->ts = metadata->ts;

}

int hash_proc(uint32_t src_ip) {
	uint32_t value;
	int hash;
	
	value = src_ip;
	hash = 0;

	do {
		hash ^= value;
	} while((value >>= HASH_LOG));

	return (hash & (MAX_Hashsize - 1));

}


uint16_t heatscore_calc(uint16_t dst_port) {

	if ( dst_port == 11 || dst_port == 12 || dst_port == 13 || dst_port == 2000)
		return 10;
	else if (dst_port < 1024)
		return 3;
	else
		return 1;

}


void hash_update(struct packet_t* packet) {

	struct timeval ts;
	int hash_key;
	int flag = 0;



	portscan_node* trans;
	hash_key = hash_proc(packet->src_ip);

	if (portscan_hash[hash_key] == NULL) {
		
		struct portscan_node* curr = malloc(sizeof(struct portscan_node));
		
		if(curr == NULL){
			printf("Heap memory not allocated\n\n\n");
			exit(1);
		}

		curr->dst_port = packet->dst_port;
		curr->src_ip = packet->src_ip;
		curr->ts = packet->ts;
		curr->heat_score = heatscore_calc(packet->dst_port);
		curr->next = NULL;
		portscan_hash[hash_key] = curr;

	}
	else {
				trans = portscan_hash[hash_key];
				
				while(trans->next) {
					
					if(trans->src_ip == packet->src_ip){
						break;

					}	
					trans = trans->next;
				
				}

                //keeping track of 300ms
				if(trans->src_ip == packet->src_ip) {
					timersub(&(packet->ts), &(trans->ts), &ts);
					if (ts.tv_sec < 1 && ts.tv_usec <= 300000){
						trans->heat_score += heatscore_calc(packet->dst_port);
						printf("Transmission score after update%d\n", trans->heat_score);
						if(trans->heat_score >= 21) {
							printf("Port Scan\n");
							flag = 1;
							
							port_scan_stats_t port_scanner;
							port_scanner.detection_time = trans->ts;
							port_scanner.detection_score = trans->heat_score;
							pack_uint32(packet->src_ip, port_scanner.src_address);

							report_port_scan(port_scanner);		

							trans->heat_score = 0;
							trans->ts = packet->ts;
						}
					}					
						
			
				}
				else {
						
						struct portscan_node* curr = malloc(sizeof(struct portscan_node));
						
						if(curr == NULL){
							printf("Heap memory not allocated\n\n");
							exit(1);
						}

						curr->dst_port = packet->dst_port;
						curr->src_ip = packet->src_ip;
						curr->ts = packet->ts;
						curr->heat_score = heatscore_calc(packet->dst_port);
						curr->next = NULL;
						trans->next = curr;
				}

	}
	printf("End of Hash update\n");
	
}

void finalhash_update(struct packet_t* packet) {

	int hash_key;
	int destination_found = 0;
	
	hash_key = hash_proc(packet->dst_ip + packet->dst_port);


	if(dst_hash[hash_key] == NULL) {
		
		struct destination* curr = malloc(sizeof(struct destination));
		
		if(curr == NULL){
			printf("heap memory allocation failed\n");
			exit(1);
		}

		curr->dst_ip = packet->dst_ip;
		curr->dst_next = NULL;
		curr->conn_next = NULL;
		curr->complete_tcp_handshakes = 0;
		curr->half_conn = 0;
		curr->reset_conn = 0;
		curr->wrong_fins = 0;
		
		dst_hash[hash_key] = curr;
		
		if (packet->flag == SYN) {

				connection* conn_curr = malloc(sizeof(struct connection));
				
				if(conn_curr == NULL){
					printf("heap memory allocation failed\n");
					exit(1);
				}

				conn_curr->src_port = packet->src_port;
				conn_curr->dst_port = packet->dst_port;
				conn_curr->src_ip = packet->src_ip;
				conn_curr->dst_ip = packet->dst_ip;
				conn_curr->state = SYN_REC;
				conn_curr->next = NULL;
				
				curr->conn_next = conn_curr;

		
		}
		else if(packet->flag == RST) {

			curr->wrong_fins += 1;

		}
		else if(packet->flag == FIN) {

			curr->wrong_fins += 1;
		}

	

	}
	else {
		
		destination* destination_trans = dst_hash[hash_key];

		while(packet->dst_ip != destination_trans->dst_ip && destination_trans->dst_next != NULL) {

				destination_trans = destination_trans->dst_next;
		}
		
		if(destination_trans->dst_next == NULL) {

			//add the destination and connection node
		}
		else { 

				
				destination* local_destination = destination_trans;
 
				connection* conn_trans = local_destination->conn_next;	

				connection* new_connection = NULL;
						
				while(conn_trans != NULL && (conn_trans->src_ip != packet->src_ip) && (conn_trans->src_port != packet->src_ip) && (conn_trans->dst_port != packet->dst_port) ) {

					if(conn_trans->state == CLOSED)
						return 0;
					 else if (packet->flag == SYNACK) {

						if(conn_trans->state == SYN_REC)
							conn_trans->state = SYNACK_REC;
						
					else if ( packet->flag == RST ) {
						
					}
                }
							
			}

		}

	}
	
}

void run_detector(pcap_t* handle) {

	const uint8_t* frame = NULL;
	struct pcap_pkthdr* header = NULL;
	int result;
	packet_stats_t packet_stats;
	int tcp_packets_count = 0;
	int udp_packets_count = 0;
	
	while(1) {
		
		struct packet_t packet;

		result = pcap_next_ex(handle, &header, &frame);
		if (result == -2) 
			break;

		node_updatetracker(&packet, frame, header);
		printf("*******************************\n");
		printf("Packet Statistics\n\n");
        printf("Protocol : %d and Flag : %d\n", packet.protocol, packet.flag);	
		if (packet.protocol == 6)
			tcp_packets_count++;

		if (packet.protocol == 11)
			udp_packets_count++;

		if(packet.protocol == 6 && packet.flag == SYN)
		hash_update(&packet);

		finalhash_update(&packet);

	}

	packet_stats.tcp_packets = tcp_packets_count;
	packet_stats.udp_packets = udp_packets_count;
	report_total_packets(packet_stats);	
}

