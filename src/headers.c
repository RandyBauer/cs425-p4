/**
 * @file headers.c
 * @brief Layer 2: the header parsers, the Internet checksum, and the
 * formatting of addresses and flags. No I/O and no allocation.
 */
#include "lab.h"

/*
 * Frame contents are always in network order (big endian). Each byte is
 * widened before it is shifted so that nothing is shifted as a signed int.
 */
static uint16_t be16(const uint8_t *p)
{
  return (uint16_t)((unsigned)p[0] << 8 | (unsigned)p[1]);
}

static uint32_t be32(const uint8_t *p)
{
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

static mac_addr get_mac(const uint8_t *p)
{
  mac_addr m;
  for (size_t i = 0; i < sizeof m.b; i++) {
    m.b[i] = p[i];
  }
  return m;
}

parse_status eth_parse(const uint8_t *p, size_t len, eth_header *out)
{
  if (p == NULL || out == NULL) {
    return PARSE_ARGS;
  }
  if (len < ETH_HEADER_LEN) {
    return PARSE_SHORT;
  }
  out->dst = get_mac(p);
  out->src = get_mac(p + 6);
  out->ethertype = be16(p + 12);
  out->payload = p + ETH_HEADER_LEN;
  out->payload_len = len - ETH_HEADER_LEN;
  return PARSE_OK;
}

parse_status arp_parse(const uint8_t *p, size_t len, arp_packet *out)
{
  if (p == NULL || out == NULL) {
    return PARSE_ARGS;
  }
  if (len < ARP_LEN) {
    return PARSE_SHORT;
  }
  uint16_t htype = be16(p);
  uint16_t ptype = be16(p + 2);
  if (htype != ARP_HTYPE_ETHERNET || ptype != ETHERTYPE_IPV4 || p[4] != 6 || p[5] != 4) {
    return PARSE_ILLEGAL;
  }
  out->htype = htype;
  out->ptype = ptype;
  out->hlen = p[4];
  out->plen = p[5];
  out->op = be16(p + 6);
  out->sha = get_mac(p + 8);
  out->spa = be32(p + 14);
  out->tha = get_mac(p + 18);
  out->tpa = be32(p + 24);
  return PARSE_OK;
}

parse_status ipv4_parse(const uint8_t *p, size_t len, bool cut_short, ipv4_header *out)
{
  if (p == NULL || out == NULL) {
    return PARSE_ARGS;
  }
  if (len < IPV4_MIN_HEADER_LEN) {
    return PARSE_SHORT;
  }
  uint8_t version = (uint8_t)(p[0] >> 4);
  uint8_t ihl = (uint8_t)(p[0] & 0x0f);
  if (version != 4 || ihl < 5) {
    return PARSE_ILLEGAL;
  }
  size_t header_len = (size_t)ihl * 4;
  if (header_len > len) {
    return PARSE_SHORT;
  }
  uint16_t total_len = be16(p + 2);
  if (total_len < header_len) {
    return PARSE_ILLEGAL;
  }
  if (total_len > len && !cut_short) {
    return PARSE_SHORT;
  }

  uint16_t frag = be16(p + 6);
  out->version = version;
  out->ihl = ihl;
  out->tos = p[1];
  out->total_len = total_len;
  out->id = be16(p + 4);
  out->dont_fragment = (frag & 0x4000) != 0;
  out->more_fragments = (frag & 0x2000) != 0;
  out->frag_offset = (uint16_t)(frag & 0x1fff);
  out->ttl = p[8];
  out->protocol = p[9];
  out->checksum = be16(p + 10);
  out->checksum_ok = inet_checksum(p, header_len, 0) == 0;
  out->src = be32(p + 12);
  out->dst = be32(p + 16);
  out->header_len = header_len;
  out->payload = p + header_len;
  out->payload_len = total_len - header_len;
  /* Whichever ends first: the datagram (anything after it is padding) or
   * the captured bytes (the snaplen cut it short). */
  size_t end = total_len < len ? total_len : len;
  out->payload_avail = end - header_len;
  return PARSE_OK;
}

parse_status tcp_parse(const uint8_t *p, size_t len, tcp_header *out)
{
  if (p == NULL || out == NULL) {
    return PARSE_ARGS;
  }
  if (len < TCP_MIN_HEADER_LEN) {
    return PARSE_SHORT;
  }
  uint8_t data_offset = (uint8_t)(p[12] >> 4);
  if (data_offset < 5) {
    return PARSE_ILLEGAL;
  }
  size_t header_len = (size_t)data_offset * 4;
  if (header_len > len) {
    return PARSE_SHORT;
  }
  out->src_port = be16(p);
  out->dst_port = be16(p + 2);
  out->seq = be32(p + 4);
  out->ack = be32(p + 8);
  out->data_offset = data_offset;
  out->flags = p[13];
  out->window = be16(p + 14);
  out->checksum = be16(p + 16);
  out->urgent = be16(p + 18);
  out->header_len = header_len;
  return PARSE_OK;
}

parse_status udp_parse(const uint8_t *p, size_t len, size_t datagram_len, udp_header *out)
{
  if (p == NULL || out == NULL) {
    return PARSE_ARGS;
  }
  if (len < UDP_HEADER_LEN) {
    return PARSE_SHORT;
  }
  uint16_t length = be16(p + 4);
  if (length < UDP_HEADER_LEN || length > datagram_len) {
    return PARSE_ILLEGAL;
  }
  out->src_port = be16(p);
  out->dst_port = be16(p + 2);
  out->length = length;
  out->checksum = be16(p + 6);
  return PARSE_OK;
}

uint16_t inet_checksum(const uint8_t *p, size_t len, uint32_t initial)
{
  /* 64 bits so no realistic length can overflow before the fold. */
  uint64_t sum = initial;
  if (p != NULL) {
    size_t i = 0;
    for (; i + 1 < len; i += 2) {
      sum += be16(p + i);
    }
    if (i < len) {
      /* An odd final byte is the high half of a word padded with zero. */
      sum += (uint64_t)p[i] << 8;
    }
  }
  /* One fold can carry again (0x1ffff becomes 0x10000), so loop. */
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return (uint16_t)~sum;
}

uint32_t pseudo_header_sum(uint32_t src, uint32_t dst, uint8_t protocol, uint16_t length)
{
  return (src >> 16) + (src & 0xffff) + (dst >> 16) + (dst & 0xffff) + protocol + length;
}

const char *format_mac(mac_addr mac, char *buf, size_t size)
{
  if (buf == NULL || size == 0) {
    return NULL;
  }
  snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned)mac.b[0], (unsigned)mac.b[1],
           (unsigned)mac.b[2], (unsigned)mac.b[3], (unsigned)mac.b[4], (unsigned)mac.b[5]);
  return buf;
}

const char *format_ipv4(uint32_t addr, char *buf, size_t size)
{
  if (buf == NULL || size == 0) {
    return NULL;
  }
  snprintf(buf, size, "%u.%u.%u.%u", addr >> 24, (addr >> 16) & 0xffu, (addr >> 8) & 0xffu,
           addr & 0xffu);
  return buf;
}

const char *format_tcp_flags(uint8_t flags, char *buf, size_t size)
{
  /* Letters in output order, with the bit each one stands for. */
  static const struct {
    uint8_t bit;
    char letter;
  } order[] = {
    {TCP_FIN, 'F'}, {TCP_SYN, 'S'}, {TCP_RST, 'R'}, {TCP_PSH, 'P'},
    {TCP_URG, 'U'}, {TCP_ECE, 'E'}, {TCP_CWR, 'W'}, {TCP_ACK, '.'},
  };

  if (buf == NULL || size == 0) {
    return NULL;
  }
  if (flags == 0) {
    snprintf(buf, size, "none");
    return buf;
  }
  size_t n = 0;
  for (size_t i = 0; i < sizeof order / sizeof order[0]; i++) {
    if ((flags & order[i].bit) && n + 1 < size) {
      buf[n++] = order[i].letter;
    }
  }
  buf[n] = '\0';
  return buf;
}
