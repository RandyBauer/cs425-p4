/**
 * @file decode.c
 * @brief Layer 3: walks each frame down the stack, keeps the flow table, and
 * runs a whole capture into a report.
 */
#include "lab.h"
#include <inttypes.h>
#include <stdlib.h>

/** Flows the table makes room for on its first add; it doubles after that. */
#define FLOW_TABLE_INITIAL 8

/** Size of the buffer that format_elapsed() writes into here. */
#define ELAPSED_STR_SIZE 32

struct flow_table {
  flow *flows;     /* first seen order */
  size_t count;    /* flows in use */
  size_t capacity; /* flows allocated */
};

static void describe_tcp(const ipv4_header *ip, const char *src, const char *dst, frame_info *out)
{
  tcp_header tcp;
  if (tcp_parse(ip->payload, ip->payload_avail, &tcp) != PARSE_OK) {
    snprintf(out->text, sizeof out->text, "malformed TCP");
    return;
  }
  /* The segment is what the IPv4 header says it is, never the frame:
   * anything past the total length is Ethernet padding. */
  size_t segment_len = ip->payload_len;
  const char *cksum;
  if (ip->payload_avail < segment_len) {
    cksum = "partial";
  } else {
    uint32_t pseudo = pseudo_header_sum(ip->src, ip->dst, PROTO_TCP, (uint16_t)segment_len);
    cksum = inet_checksum(ip->payload, segment_len, pseudo) == 0 ? "ok" : "bad";
  }

  char flags[TCP_FLAGS_STR_SIZE];
  snprintf(out->text, sizeof out->text,
           "TCP %s:%u > %s:%u [%s] seq=%" PRIu32 " ack=%" PRIu32 " win=%u len=%zu cksum=%s", src,
           (unsigned)tcp.src_port, dst, (unsigned)tcp.dst_port,
           format_tcp_flags(tcp.flags, flags, sizeof flags), tcp.seq, tcp.ack,
           (unsigned)tcp.window, segment_len - tcp.header_len, cksum);
  out->has_flow = true;
  out->key = (flow_key){PROTO_TCP, ip->src, tcp.src_port, ip->dst, tcp.dst_port};
}

static void describe_udp(const ipv4_header *ip, const char *src, const char *dst, frame_info *out)
{
  udp_header udp;
  if (udp_parse(ip->payload, ip->payload_avail, ip->payload_len, &udp) != PARSE_OK) {
    snprintf(out->text, sizeof out->text, "malformed UDP");
    return;
  }
  const char *cksum;
  if (udp.checksum == 0) {
    cksum = "none";
  } else if (ip->payload_avail < udp.length) {
    cksum = "partial";
  } else {
    uint32_t pseudo = pseudo_header_sum(ip->src, ip->dst, PROTO_UDP, udp.length);
    cksum = inet_checksum(ip->payload, udp.length, pseudo) == 0 ? "ok" : "bad";
  }

  snprintf(out->text, sizeof out->text, "UDP %s:%u > %s:%u len=%u cksum=%s", src,
           (unsigned)udp.src_port, dst, (unsigned)udp.dst_port,
           (unsigned)udp.length - UDP_HEADER_LEN, cksum);
  out->has_flow = true;
  out->key = (flow_key){PROTO_UDP, ip->src, udp.src_port, ip->dst, udp.dst_port};
}

static void describe_ipv4(const eth_header *eth, bool cut_short, frame_info *out)
{
  ipv4_header ip;
  if (ipv4_parse(eth->payload, eth->payload_len, cut_short, &ip) != PARSE_OK) {
    snprintf(out->text, sizeof out->text, "malformed IPv4");
    return;
  }
  char src[IPV4_STR_SIZE];
  char dst[IPV4_STR_SIZE];
  format_ipv4(ip.src, src, sizeof src);
  format_ipv4(ip.dst, dst, sizeof dst);

  if (!ip.checksum_ok) {
    snprintf(out->text, sizeof out->text, "IPv4 %s > %s proto=%u bad-header-cksum", src, dst,
             (unsigned)ip.protocol);
  } else if (ip.more_fragments || ip.frag_offset != 0) {
    snprintf(out->text, sizeof out->text, "IPv4 %s > %s proto=%u fragment", src, dst,
             (unsigned)ip.protocol);
  } else if (ip.protocol == PROTO_TCP) {
    describe_tcp(&ip, src, dst, out);
  } else if (ip.protocol == PROTO_UDP) {
    describe_udp(&ip, src, dst, out);
  } else {
    snprintf(out->text, sizeof out->text, "IPv4 %s > %s proto=%u", src, dst,
             (unsigned)ip.protocol);
  }
}

static void describe_arp(const eth_header *eth, frame_info *out)
{
  arp_packet arp;
  if (arp_parse(eth->payload, eth->payload_len, &arp) != PARSE_OK) {
    snprintf(out->text, sizeof out->text, "malformed ARP");
    return;
  }
  char sender[IPV4_STR_SIZE];
  char target[IPV4_STR_SIZE];
  char mac[MAC_STR_SIZE];
  format_ipv4(arp.spa, sender, sizeof sender);
  format_ipv4(arp.tpa, target, sizeof target);

  if (arp.op == ARP_OP_REQUEST) {
    snprintf(out->text, sizeof out->text, "ARP request who-has %s tell %s", target, sender);
  } else if (arp.op == ARP_OP_REPLY) {
    snprintf(out->text, sizeof out->text, "ARP reply %s is-at %s", sender,
             format_mac(arp.sha, mac, sizeof mac));
  } else {
    snprintf(out->text, sizeof out->text, "ARP op=%u", (unsigned)arp.op);
  }
}

bool decode_frame(const uint8_t *frame, size_t caplen, uint32_t origlen, frame_info *out)
{
  if (out == NULL || (frame == NULL && caplen > 0)) {
    return false;
  }
  out->has_flow = false;
  out->text[0] = '\0';

  eth_header eth;
  if (eth_parse(frame, caplen, &eth) != PARSE_OK) {
    snprintf(out->text, sizeof out->text, "malformed Ethernet");
    return true;
  }
  if (eth.ethertype == ETHERTYPE_ARP) {
    describe_arp(&eth, out);
  } else if (eth.ethertype == ETHERTYPE_IPV4) {
    describe_ipv4(&eth, caplen < origlen, out);
  } else {
    snprintf(out->text, sizeof out->text, "Ethernet type=0x%04x", (unsigned)eth.ethertype);
  }
  return true;
}

flow_table *flow_table_create(void)
{
  /* Starts empty; the first flow_table_add() allocates the array. */
  return calloc(1, sizeof(flow_table));
}

void flow_table_destroy(flow_table *t)
{
  if (t == NULL) {
    return;
  }
  free(t->flows);
  free(t);
}

/* True when k is the same conversation as f, in either direction. */
static bool same_flow(const flow_key *f, const flow_key *k)
{
  if (f->protocol != k->protocol) {
    return false;
  }
  bool forward = f->a_addr == k->a_addr && f->a_port == k->a_port && f->b_addr == k->b_addr &&
                 f->b_port == k->b_port;
  bool reverse = f->a_addr == k->b_addr && f->a_port == k->b_port && f->b_addr == k->a_addr &&
                 f->b_port == k->a_port;
  return forward || reverse;
}

bool flow_table_add(flow_table *t, const flow_key *key, uint32_t bytes)
{
  if (t == NULL || key == NULL) {
    return false;
  }
  for (size_t i = 0; i < t->count; i++) {
    if (same_flow(&t->flows[i].key, key)) {
      t->flows[i].packets++;
      t->flows[i].bytes += bytes;
      return true;
    }
  }
  if (t->count == t->capacity) {
    size_t capacity = t->capacity == 0 ? FLOW_TABLE_INITIAL : t->capacity * 2;
    /* realloc into a temporary, so a failure leaves the table as it was. */
    flow *grown = realloc(t->flows, capacity * sizeof *grown);
    if (grown == NULL) { // GCOVR_EXCL_START
      return false;
    } // GCOVR_EXCL_STOP
    t->flows = grown;
    t->capacity = capacity;
  }
  t->flows[t->count++] = (flow){*key, 1, bytes};
  return true;
}

size_t flow_table_count(const flow_table *t)
{
  return t == NULL ? 0 : t->count;
}

const flow *flow_table_get(const flow_table *t, size_t i)
{
  if (t == NULL || i >= t->count) {
    return NULL;
  }
  return &t->flows[i];
}

const char *format_flow(const flow *f, char *buf, size_t size)
{
  if (f == NULL || buf == NULL || size == 0) {
    return NULL;
  }
  const char *proto = "IP";
  if (f->key.protocol == PROTO_TCP) {
    proto = "TCP";
  } else if (f->key.protocol == PROTO_UDP) {
    proto = "UDP";
  }
  char a[IPV4_STR_SIZE];
  char b[IPV4_STR_SIZE];
  snprintf(buf, size, "%s %s:%u <> %s:%u packets=%" PRIu64 " bytes=%" PRIu64, proto,
           format_ipv4(f->key.a_addr, a, sizeof a), (unsigned)f->key.a_port,
           format_ipv4(f->key.b_addr, b, sizeof b), (unsigned)f->key.b_port, f->packets,
           f->bytes);
  return buf;
}

const char *format_elapsed(uint32_t sec, uint32_t usec, uint32_t sec0, uint32_t usec0,
                           char *buf, size_t size)
{
  if (buf == NULL || size == 0) {
    return NULL;
  }
  /* Whole microseconds in 64 bits: exact, and 2^32 seconds still fits. */
  int64_t us = ((int64_t)sec - (int64_t)sec0) * 1000000 + ((int64_t)usec - (int64_t)usec0);
  const char *sign = "";
  if (us < 0) {
    sign = "-";
    us = -us;
  }
  snprintf(buf, size, "%s%" PRId64 ".%06" PRId64, sign, us / 1000000, us % 1000000);
  return buf;
}

int report_capture(const uint8_t *data, size_t len, const char *name, bool summary_only,
                   FILE *out, FILE *err)
{
  if (out == NULL || err == NULL) {
    return EXIT_BAD_FILE;
  }
  const char *label = name == NULL ? "capture" : name;

  pcap_reader reader;
  pcap_status st = pcap_open(&reader, data, len);
  if (st != PCAP_OK) {
    fprintf(err, "myapp: %s: %s\n", label, pcap_strerror(st));
    return EXIT_BAD_FILE;
  }
  flow_table *flows = flow_table_create();
  if (flows == NULL) { // GCOVR_EXCL_START
    fprintf(err, "myapp: out of memory\n");
    return EXIT_BAD_FILE;
  } // GCOVR_EXCL_STOP

  pcap_record rec;
  uint64_t frame_no = 0;
  uint32_t sec0 = 0;
  uint32_t usec0 = 0;
  while ((st = pcap_next(&reader, &rec)) == PCAP_OK) {
    frame_no++;
    if (frame_no == 1) {
      sec0 = rec.ts_sec;
      usec0 = rec.ts_usec;
    }
    frame_info info;
    decode_frame(rec.data, rec.caplen, rec.origlen, &info);
    if (info.has_flow && !flow_table_add(flows, &info.key, rec.origlen)) { // GCOVR_EXCL_START
      fprintf(err, "myapp: out of memory\n");
      flow_table_destroy(flows);
      return EXIT_BAD_FILE;
    } // GCOVR_EXCL_STOP
    if (!summary_only) {
      char elapsed[ELAPSED_STR_SIZE];
      fprintf(out, "%" PRIu64 " %s %s\n", frame_no,
              format_elapsed(rec.ts_sec, rec.ts_usec, sec0, usec0, elapsed, sizeof elapsed),
              info.text);
    }
  }
  if (st != PCAP_END) {
    fprintf(err, "myapp: %s: frame %" PRIu64 ": %s\n", label, frame_no + 1, pcap_strerror(st));
    flow_table_destroy(flows);
    return EXIT_BAD_FILE;
  }

  if (!summary_only) {
    fputc('\n', out);
  }
  for (size_t i = 0; i < flow_table_count(flows); i++) {
    char line[FRAME_TEXT_SIZE];
    fprintf(out, "%s\n", format_flow(flow_table_get(flows, i), line, sizeof line));
  }
  flow_table_destroy(flows);
  return EXIT_CAPTURE_OK;
}
