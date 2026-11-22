/**
 * @file lab.h
 * @brief A packet capture decoder, in three layers.
 *
 * 1. The pcap reader opens a capture that is already in memory and hands out
 *    one record at a time. It never touches a file.
 * 2. The header parsers turn bytes into structs for Ethernet, ARP, IPv4, TCP
 *    and UDP, and hold the Internet checksum and the text formatting of
 *    addresses and flags. Nothing in this layer does I/O or allocates.
 * 3. Decoding and reporting walks one frame down the stack, keeps a flow
 *    table, and runs a whole capture, writing the report to a FILE *.
 *
 * Every function that reads bytes takes a pointer and a length, and never
 * reads past that length. Multi-byte values are assembled a byte at a time,
 * so the code does not depend on the byte order of the machine it runs on.
 */
#ifndef LAB_H
#define LAB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* ======================================================================== */
/* Layer 1: the pcap reader                                                 */
/* ======================================================================== */

/** Size of the pcap file header, in bytes. */
#define PCAP_FILE_HEADER_LEN 24

/** Size of the header in front of every pcap record, in bytes. */
#define PCAP_RECORD_HEADER_LEN 16

/** The pcap magic number, as read in the byte order of the file's writer. */
#define PCAP_MAGIC 0xa1b2c3d4u

/** The first four bytes of every pcapng file, the format people save by mistake. */
#define PCAPNG_MAGIC 0x0a0d0d0au

/** The only pcap major version this reader accepts. */
#define PCAP_VERSION_MAJOR 2

/** The pcap link type for Ethernet, the only one this reader accepts. */
#define PCAP_LINKTYPE_ETHERNET 1

/**
 * @brief The result of opening a capture or reading the next record.
 */
typedef enum {
  PCAP_OK = 0,            /**< The file header was accepted, or a record was returned */
  PCAP_END,               /**< No more records: the file ended exactly after the last one */
  PCAP_ERR_ARGS,          /**< A required pointer argument was NULL */
  PCAP_ERR_SHORT,         /**< The file is shorter than the 24 byte file header */
  PCAP_ERR_PCAPNG,        /**< The file is pcapng, not pcap */
  PCAP_ERR_MAGIC,         /**< The magic number is wrong in both byte orders */
  PCAP_ERR_VERSION,       /**< The major version is not 2 */
  PCAP_ERR_LINKTYPE,      /**< The link type is not 1 (Ethernet) */
  PCAP_ERR_RECORD_HEADER, /**< A record header runs past the end of the file */
  PCAP_ERR_RECORD_DATA,   /**< A record's data runs past the end of the file */
  PCAP_ERR_CAPLEN         /**< A record claims more captured bytes than were on the wire */
} pcap_status;

/**
 * @brief A capture opened in memory. Filled in by pcap_open().
 *
 * The reader does not own the bytes. The caller keeps them alive, unchanged,
 * for as long as the reader and any record it returned are in use.
 */
typedef struct {
  const uint8_t *data;    /**< The whole file */
  size_t len;             /**< Number of bytes in data */
  size_t pos;             /**< Offset of the next record header */
  bool big_endian;        /**< Byte order of the pcap headers (never of the frames) */
  uint16_t version_major; /**< Major version from the file header, always 2 */
  uint16_t version_minor; /**< Minor version from the file header, not checked */
  uint32_t snaplen;       /**< The most bytes kept of any one frame */
  uint32_t linktype;      /**< Link type from the file header, always 1 */
} pcap_reader;

/**
 * @brief One record of a capture, as returned by pcap_next().
 */
typedef struct {
  uint32_t ts_sec;     /**< Timestamp, seconds since the epoch */
  uint32_t ts_usec;    /**< Timestamp, microseconds */
  uint32_t caplen;     /**< Captured length: the number of bytes at data */
  uint32_t origlen;    /**< Original length: the frame's length on the wire */
  const uint8_t *data; /**< The frame's captured bytes, inside the reader's buffer */
} pcap_record;

/**
 * @brief Opens a capture held in memory and checks its file header.
 *
 * Reads the magic number in both byte orders to decide the order of every
 * pcap header that follows. The reader is left at the first record.
 *
 * @param r    The reader to fill in
 * @param data The whole capture file, kept alive by the caller
 * @param len  Number of bytes in data
 * @return PCAP_OK on success, or the reason the file header was rejected:
 *         PCAP_ERR_ARGS if r is NULL or data is NULL with a nonzero len,
 *         PCAP_ERR_SHORT, PCAP_ERR_PCAPNG, PCAP_ERR_MAGIC, PCAP_ERR_VERSION
 *         or PCAP_ERR_LINKTYPE
 */
pcap_status pcap_open(pcap_reader *r, const uint8_t *data, size_t len);

/**
 * @brief Hands out the next record of an open capture.
 *
 * Checks that the record header and all of the record's data are present
 * before returning anything. On an error the reader does not move, so the
 * same error is returned again.
 *
 * @param r   A reader that pcap_open() accepted
 * @param rec Receives the record on PCAP_OK; untouched otherwise
 * @return PCAP_OK with a record, PCAP_END at a clean end of file,
 *         PCAP_ERR_ARGS if r or rec is NULL, or PCAP_ERR_RECORD_HEADER,
 *         PCAP_ERR_CAPLEN or PCAP_ERR_RECORD_DATA for a broken record
 */
pcap_status pcap_next(pcap_reader *r, pcap_record *rec);

/**
 * @brief Describes a pcap_status in words, for error messages.
 *
 * @param s The status to describe
 * @return A static string. Never NULL, even for a value outside the enum
 */
const char *pcap_strerror(pcap_status s);

/* ======================================================================== */
/* Layer 2: the header parsers                                              */
/* ======================================================================== */

/** Length of an Ethernet header: two MAC addresses and the EtherType. */
#define ETH_HEADER_LEN 14

/** Length of an ARP message for IPv4 over Ethernet. */
#define ARP_LEN 28

/** Length of an IPv4 header without options. */
#define IPV4_MIN_HEADER_LEN 20

/** Length of a TCP header without options. */
#define TCP_MIN_HEADER_LEN 20

/** Length of a UDP header. */
#define UDP_HEADER_LEN 8

/** EtherType for IPv4. */
#define ETHERTYPE_IPV4 0x0800

/** EtherType for ARP. */
#define ETHERTYPE_ARP 0x0806

/** ARP hardware type for Ethernet. */
#define ARP_HTYPE_ETHERNET 1

/** ARP opcode for a request. */
#define ARP_OP_REQUEST 1

/** ARP opcode for a reply. */
#define ARP_OP_REPLY 2

/** IPv4 protocol number for TCP. */
#define PROTO_TCP 6

/** IPv4 protocol number for UDP. */
#define PROTO_UDP 17

/** TCP flag bit: no more data from the sender. */
#define TCP_FIN 0x01
/** TCP flag bit: synchronize sequence numbers. */
#define TCP_SYN 0x02
/** TCP flag bit: reset the connection. */
#define TCP_RST 0x04
/** TCP flag bit: push the data to the application. */
#define TCP_PSH 0x08
/** TCP flag bit: the acknowledgment field is valid. */
#define TCP_ACK 0x10
/** TCP flag bit: the urgent pointer is valid. */
#define TCP_URG 0x20
/** TCP flag bit: ECN echo. */
#define TCP_ECE 0x40
/** TCP flag bit: congestion window reduced. */
#define TCP_CWR 0x80

/** Buffer size that holds any MAC address as text, with its terminator. */
#define MAC_STR_SIZE 18

/** Buffer size that holds any IPv4 address as text, with its terminator. */
#define IPV4_STR_SIZE 16

/** Buffer size that holds any TCP flags text, with its terminator. */
#define TCP_FLAGS_STR_SIZE 9

/**
 * @brief The result of parsing one header.
 */
typedef enum {
  PARSE_OK = 0,  /**< The header fits and is legal; the struct is filled in */
  PARSE_SHORT,   /**< The header does not fit in the bytes given */
  PARSE_ILLEGAL, /**< The header fits but breaks a rule of its format */
  PARSE_ARGS     /**< A required pointer argument was NULL */
} parse_status;

/**
 * @brief A 48-bit Ethernet (MAC) address, in wire order.
 */
typedef struct {
  uint8_t b[6]; /**< The six bytes, first byte first */
} mac_addr;

/**
 * @brief A parsed Ethernet header.
 */
typedef struct {
  mac_addr dst;           /**< Destination MAC address */
  mac_addr src;           /**< Source MAC address */
  uint16_t ethertype;     /**< What the payload is: ETHERTYPE_IPV4, ETHERTYPE_ARP, ... */
  const uint8_t *payload; /**< First byte after the header */
  size_t payload_len;     /**< Bytes from payload to the end of the frame, padding included */
} eth_header;

/**
 * @brief A parsed ARP message (IPv4 over Ethernet only).
 */
typedef struct {
  uint16_t htype; /**< Hardware type, always 1 */
  uint16_t ptype; /**< Protocol type, always 0x0800 */
  uint8_t hlen;   /**< Hardware address length, always 6 */
  uint8_t plen;   /**< Protocol address length, always 4 */
  uint16_t op;    /**< Opcode: ARP_OP_REQUEST, ARP_OP_REPLY, or anything else */
  mac_addr sha;   /**< Sender hardware address */
  uint32_t spa;   /**< Sender IPv4 address */
  mac_addr tha;   /**< Target hardware address */
  uint32_t tpa;   /**< Target IPv4 address */
} arp_packet;

/**
 * @brief A parsed IPv4 header.
 */
typedef struct {
  uint8_t version;        /**< Always 4 */
  uint8_t ihl;            /**< Header length in 4 byte words, 5 to 15 */
  uint8_t tos;            /**< Type of service */
  uint16_t total_len;     /**< Total length of the datagram, header included */
  uint16_t id;            /**< Identification */
  bool dont_fragment;     /**< The DF flag */
  bool more_fragments;    /**< The MF flag */
  uint16_t frag_offset;   /**< Fragment offset, in 8 byte units */
  uint8_t ttl;            /**< Time to live */
  uint8_t protocol;       /**< Protocol of the payload: PROTO_TCP, PROTO_UDP, ... */
  uint16_t checksum;      /**< Header checksum as sent */
  bool checksum_ok;       /**< Whether the header checksum verifies */
  uint32_t src;           /**< Source address */
  uint32_t dst;           /**< Destination address */
  size_t header_len;      /**< ihl * 4: where the payload starts */
  const uint8_t *payload; /**< First byte after the header, options included */
  size_t payload_len;     /**< Payload length according to the header: total_len - header_len */
  size_t payload_avail;   /**< Payload bytes actually present, never more than payload_len */
} ipv4_header;

/**
 * @brief A parsed TCP header.
 */
typedef struct {
  uint16_t src_port;    /**< Source port */
  uint16_t dst_port;    /**< Destination port */
  uint32_t seq;         /**< Raw sequence number */
  uint32_t ack;         /**< Raw acknowledgment number */
  uint8_t data_offset;  /**< Header length in 4 byte words, 5 to 15 */
  uint8_t flags;        /**< The eight flag bits, TCP_FIN to TCP_CWR */
  uint16_t window;      /**< Raw receive window, unscaled */
  uint16_t checksum;    /**< Checksum as sent */
  uint16_t urgent;      /**< Urgent pointer */
  size_t header_len;    /**< data_offset * 4: where the payload starts */
} tcp_header;

/**
 * @brief A parsed UDP header.
 */
typedef struct {
  uint16_t src_port; /**< Source port */
  uint16_t dst_port; /**< Destination port */
  uint16_t length;   /**< Length of header and payload, at least 8 */
  uint16_t checksum; /**< Checksum as sent; 0 means the sender did not compute one */
} udp_header;

/**
 * @brief Parses an Ethernet header.
 *
 * @param p   The frame's first byte
 * @param len Number of bytes at p
 * @param out Receives the header on PARSE_OK; untouched otherwise
 * @return PARSE_OK, PARSE_SHORT if len is under 14, or PARSE_ARGS if p or
 *         out is NULL
 */
parse_status eth_parse(const uint8_t *p, size_t len, eth_header *out);

/**
 * @brief Parses an ARP message for IPv4 over Ethernet.
 *
 * Bytes past the first 28 (Ethernet padding) are ignored.
 *
 * @param p   The message's first byte
 * @param len Number of bytes at p
 * @param out Receives the message on PARSE_OK; untouched otherwise
 * @return PARSE_OK, PARSE_SHORT if len is under 28, PARSE_ILLEGAL if it is
 *         not hardware type 1, protocol type 0x0800 and address lengths 6
 *         and 4, or PARSE_ARGS if p or out is NULL
 */
parse_status arp_parse(const uint8_t *p, size_t len, arp_packet *out);

/**
 * @brief Parses an IPv4 header and verifies its header checksum.
 *
 * The checksum result goes in out->checksum_ok and does not make the parse
 * fail. Bytes past the total length are Ethernet padding and are left out of
 * payload_avail.
 *
 * @param p         The datagram's first byte
 * @param len       Number of datagram bytes captured at p
 * @param cut_short True when the capture kept fewer bytes than were on the
 *                  wire (the snaplen), so a total length past len is expected
 * @param out       Receives the header on PARSE_OK; untouched otherwise
 * @return PARSE_OK; PARSE_SHORT if len is under 20, the header runs past
 *         len, or the total length runs past len without cut_short;
 *         PARSE_ILLEGAL for a version other than 4, an IHL under 5 or a total
 *         length shorter than the header; PARSE_ARGS if p or out is NULL
 */
parse_status ipv4_parse(const uint8_t *p, size_t len, bool cut_short, ipv4_header *out);

/**
 * @brief Parses a TCP header.
 *
 * @param p   The segment's first byte
 * @param len Number of segment bytes available at p
 * @param out Receives the header on PARSE_OK; untouched otherwise
 * @return PARSE_OK; PARSE_SHORT if len is under 20 or the header (options
 *         included) runs past len; PARSE_ILLEGAL for a data offset under 5;
 *         PARSE_ARGS if p or out is NULL
 */
parse_status tcp_parse(const uint8_t *p, size_t len, tcp_header *out);

/**
 * @brief Parses a UDP header.
 *
 * @param p            The datagram's first byte
 * @param len          Number of UDP bytes available at p
 * @param datagram_len The IPv4 payload length according to the IPv4 header,
 *                     which the UDP length may not exceed
 * @param out          Receives the header on PARSE_OK; untouched otherwise
 * @return PARSE_OK; PARSE_SHORT if len is under 8; PARSE_ILLEGAL for a UDP
 *         length under 8 or over datagram_len; PARSE_ARGS if p or out is NULL
 */
parse_status udp_parse(const uint8_t *p, size_t len, size_t datagram_len, udp_header *out);

/**
 * @brief Computes the Internet checksum (RFC 1071) of a run of bytes.
 *
 * Adds the bytes as 16-bit big endian words to initial, padding an odd final
 * byte with a zero, folds every carry back in, and returns the complement.
 * Over bytes that include a correct checksum field, the result is 0.
 *
 * @param p       First byte to sum; may be NULL only when len is 0
 * @param len     Number of bytes to sum
 * @param initial A partial sum to start from, such as pseudo_header_sum()
 * @return The 16-bit checksum. Returns the checksum of initial alone when p
 *         is NULL
 */
uint16_t inet_checksum(const uint8_t *p, size_t len, uint32_t initial);

/**
 * @brief Sums the TCP/UDP pseudo header, for use as inet_checksum()'s initial value.
 *
 * @param src      Source IPv4 address
 * @param dst      Destination IPv4 address
 * @param protocol PROTO_TCP or PROTO_UDP
 * @param length   The TCP or UDP length: header plus payload
 * @return The unfolded sum of the pseudo header's 16-bit words
 */
uint32_t pseudo_header_sum(uint32_t src, uint32_t dst, uint8_t protocol, uint16_t length);

/**
 * @brief Formats a MAC address as six lowercase hex pairs joined by colons.
 *
 * @param mac  The address
 * @param buf  Where to write the text; MAC_STR_SIZE bytes is always enough
 * @param size Size of buf; the text is cut short to fit a smaller buffer
 * @return buf, or NULL if buf is NULL or size is 0
 */
const char *format_mac(mac_addr mac, char *buf, size_t size);

/**
 * @brief Formats an IPv4 address as a dotted quad.
 *
 * @param addr The address, most significant byte first
 * @param buf  Where to write the text; IPV4_STR_SIZE bytes is always enough
 * @param size Size of buf; the text is cut short to fit a smaller buffer
 * @return buf, or NULL if buf is NULL or size is 0
 */
const char *format_ipv4(uint32_t addr, char *buf, size_t size);

/**
 * @brief Formats TCP flags as the letters F S R P U E W for each set bit,
 * then a '.' if ACK is set, or "none" when no bit is set.
 *
 * @param flags The TCP flags byte
 * @param buf   Where to write the text; TCP_FLAGS_STR_SIZE bytes is always enough
 * @param size  Size of buf; the text is cut short to fit a smaller buffer
 * @return buf, or NULL if buf is NULL or size is 0
 */
const char *format_tcp_flags(uint8_t flags, char *buf, size_t size);

/* ======================================================================== */
/* Layer 3: decoding and reporting                                          */
/* ======================================================================== */

/** Buffer size that holds any frame description, with its terminator. */
#define FRAME_TEXT_SIZE 192

/** Exit status for a capture read from end to end. */
#define EXIT_CAPTURE_OK 0

/** Exit status for a wrong command line. */
#define EXIT_BAD_USAGE 1

/** Exit status for a file that cannot be read or is not a well formed pcap. */
#define EXIT_BAD_FILE 2

/**
 * @brief The two endpoints and protocol of a TCP or UDP packet.
 *
 * In a frame, side a is the source and side b the destination. In the flow
 * table, side a is the source of the first packet of the flow.
 */
typedef struct {
  uint8_t protocol; /**< PROTO_TCP or PROTO_UDP */
  uint32_t a_addr;  /**< Side a's IPv4 address */
  uint16_t a_port;  /**< Side a's port */
  uint32_t b_addr;  /**< Side b's IPv4 address */
  uint16_t b_port;  /**< Side b's port */
} flow_key;

/**
 * @brief One conversation, both directions together.
 */
typedef struct {
  flow_key key;     /**< Protocol and endpoints, side a first seen as the source */
  uint64_t packets; /**< Frames that printed a TCP or UDP line for this flow */
  uint64_t bytes;   /**< Sum of those frames' original lengths */
} flow;

/** A growable table of flows, in the order they were first seen. Opaque. */
typedef struct flow_table flow_table;

/**
 * @brief What one frame decodes to.
 */
typedef struct {
  char text[FRAME_TEXT_SIZE]; /**< The description, without frame number or time */
  bool has_flow;              /**< True when the frame printed a TCP or UDP line */
  flow_key key;               /**< The frame's endpoints, valid when has_flow */
} frame_info;

/**
 * @brief Walks one frame down the stack and describes it.
 *
 * Checks Ethernet, ARP, IPv4, the IPv4 header checksum, fragments, the
 * protocol, TCP and UDP in that order, and reports the first problem it finds
 * as a "malformed" description. A broken frame is never an error.
 *
 * @param frame   The captured bytes
 * @param caplen  Number of bytes at frame
 * @param origlen The frame's length on the wire. A caplen below this means
 *                the capture was cut short by its snaplen
 * @param out     Receives the description
 * @return true on success, false if frame (with a nonzero caplen) or out is NULL
 */
bool decode_frame(const uint8_t *frame, size_t caplen, uint32_t origlen, frame_info *out);

/**
 * @brief Creates an empty flow table.
 *
 * @return The table, which the caller frees with flow_table_destroy(), or
 *         NULL when memory runs out
 */
flow_table *flow_table_create(void);

/**
 * @brief Frees a flow table and everything in it.
 *
 * @param t The table; NULL is allowed and does nothing
 */
void flow_table_destroy(flow_table *t);

/**
 * @brief Counts one packet against its flow, adding the flow if it is new.
 *
 * A packet from b to a belongs to the same flow as one from a to b. A new
 * flow keeps key's orientation, so its side a is this packet's source.
 *
 * @param t     The table
 * @param key   The packet's protocol and endpoints, source as side a
 * @param bytes The packet's original length
 * @return true on success, false if t or key is NULL or memory ran out (the
 *         table is unchanged then)
 */
bool flow_table_add(flow_table *t, const flow_key *key, uint32_t bytes);

/**
 * @brief Counts the flows in a table.
 *
 * @param t The table
 * @return The number of flows, or 0 if t is NULL
 */
size_t flow_table_count(const flow_table *t);

/**
 * @brief Returns one flow, in first seen order.
 *
 * @param t The table
 * @param i Index, from 0 to flow_table_count() - 1
 * @return The flow, owned by the table and valid until the next
 *         flow_table_add() or flow_table_destroy(); NULL if t is NULL or i is
 *         out of range
 */
const flow *flow_table_get(const flow_table *t, size_t i);

/**
 * @brief Formats one flow as its summary line, without a newline.
 *
 * @param f    The flow
 * @param buf  Where to write the text; FRAME_TEXT_SIZE bytes is always enough
 * @param size Size of buf; the text is cut short to fit a smaller buffer
 * @return buf, or NULL if f or buf is NULL or size is 0
 */
const char *format_flow(const flow *f, char *buf, size_t size);

/**
 * @brief Formats the time between two timestamps as seconds with six decimals.
 *
 * Works in whole microseconds, so no rounding is involved. A later timestamp
 * that is earlier than the first prints with a minus sign.
 *
 * @param sec   Seconds of this frame's timestamp
 * @param usec  Microseconds of this frame's timestamp
 * @param sec0  Seconds of the first frame's timestamp
 * @param usec0 Microseconds of the first frame's timestamp
 * @param buf   Where to write the text; 32 bytes is always enough
 * @param size  Size of buf; the text is cut short to fit a smaller buffer
 * @return buf, or NULL if buf is NULL or size is 0
 */
const char *format_elapsed(uint32_t sec, uint32_t usec, uint32_t sec0, uint32_t usec0,
                           char *buf, size_t size);

/**
 * @brief Decodes a whole capture held in memory and writes the report.
 *
 * Prints one line per frame, then a blank line and the flow summary. With
 * summary_only, prints only the flow lines. If the file is not well formed,
 * prints every frame before the problem, writes a message naming the problem
 * and the frame to err, and skips the summary.
 *
 * @param data         The whole capture file
 * @param len          Number of bytes in data
 * @param name         The file's name, used in error messages; NULL is allowed
 * @param summary_only True for the -s option
 * @param out          Where the report goes
 * @param err          Where error messages go
 * @return EXIT_CAPTURE_OK when the whole capture was read, or EXIT_BAD_FILE
 *         when it is not a well formed pcap file, data is NULL with a nonzero
 *         len, out or err is NULL, or memory ran out
 */
int report_capture(const uint8_t *data, size_t len, const char *name, bool summary_only,
                   FILE *out, FILE *err);

#endif /* LAB_H */
