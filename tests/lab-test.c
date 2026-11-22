/**
 * @file lab-test.c
 * @brief Unity tests for every function declared in src/lab.h.
 *
 * Most inputs are byte arrays: real frames copied out of day-in-the-life.pcap
 * (whose checksums tshark verifies), and synthetic frames built here and then
 * broken one field at a time. The last group runs the real captures from the
 * repository root, which is where make check runs.
 */
#include <stdlib.h>
#include <string.h>
#include "harness/unity.h"
#include "../src/lab.h"

void setUp(void)
{
}

void tearDown(void)
{
}

/* ======================================================================== */
/* Fixtures: real frames from day-in-the-life.pcap                          */
/* ======================================================================== */

/* Frame 6: ARP request, 42 bytes, sent by the laptop so not padded. */
static const uint8_t FRAME_ARP_REQUEST[] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x16, 0x3e, 0x1a, 0x2b, 0x3c,
  0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x16,
  0x3e, 0x1a, 0x2b, 0x3c, 0x44, 0x55, 0x02, 0x65, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x44, 0x55, 0x02, 0x01,
};

/* Frame 7: ARP reply, received, so padded to 60 bytes. */
static const uint8_t FRAME_ARP_REPLY[] = {
  0x00, 0x16, 0x3e, 0x1a, 0x2b, 0x3c, 0x00, 0x22, 0x5f, 0x4d, 0x5e, 0x6f,
  0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x00, 0x22,
  0x5f, 0x4d, 0x5e, 0x6f, 0x44, 0x55, 0x02, 0x01, 0x00, 0x16, 0x3e, 0x1a,
  0x2b, 0x3c, 0x44, 0x55, 0x02, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* Frame 8: the DNS query, UDP with a checksum. */
static const uint8_t FRAME_DNS_QUERY[] = {
  0x00, 0x22, 0x5f, 0x4d, 0x5e, 0x6f, 0x00, 0x16, 0x3e, 0x1a, 0x2b, 0x3c,
  0x08, 0x00, 0x45, 0x00, 0x00, 0x3c, 0x2c, 0x01, 0x00, 0x00, 0x40, 0x11,
  0x7b, 0xbd, 0x44, 0x55, 0x02, 0x65, 0x44, 0x57, 0x47, 0xe2, 0xc8, 0x86,
  0x00, 0x35, 0x00, 0x28, 0x6a, 0x18, 0x6b, 0x2f, 0x01, 0x00, 0x00, 0x01,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x06, 0x67,
  0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
  0x00, 0x01,
};

/* Frame 12: the handshake's final ACK, 54 bytes, no padding. */
static const uint8_t FRAME_TCP_ACK[] = {
  0x00, 0x22, 0x5f, 0x4d, 0x5e, 0x6f, 0x00, 0x16, 0x3e, 0x1a, 0x2b, 0x3c,
  0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x8a, 0x3f, 0x40, 0x00, 0x40, 0x06,
  0x7f, 0x84, 0x44, 0x55, 0x02, 0x65, 0x40, 0xe9, 0xa9, 0x69, 0xc0, 0x00,
  0x00, 0x50, 0xba, 0x6f, 0x38, 0x0d, 0x84, 0x0d, 0x58, 0xe2, 0x50, 0x10,
  0x01, 0xf6, 0xed, 0x14, 0x00, 0x00,
};

/* Frame 14: a received ACK, padded from 54 to 60 bytes. */
static const uint8_t FRAME_TCP_PADDED[] = {
  0x00, 0x16, 0x3e, 0x1a, 0x2b, 0x3c, 0x00, 0x22, 0x5f, 0x4d, 0x5e, 0x6f,
  0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x1f, 0x02, 0x40, 0x00, 0x76, 0x06,
  0xb4, 0xc1, 0x40, 0xe9, 0xa9, 0x69, 0x44, 0x55, 0x02, 0x65, 0x00, 0x50,
  0xc0, 0x00, 0x84, 0x0d, 0x58, 0xe2, 0xba, 0x6f, 0x38, 0x5a, 0x50, 0x10,
  0x04, 0x1a, 0xea, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* Frame 23: the traceroute probe, IPv4 with an 8 byte record route option. */
static const uint8_t FRAME_IP_OPTIONS[] = {
  0x00, 0x22, 0x5f, 0x4d, 0x5e, 0x6f, 0x00, 0x16, 0x3e, 0x1a, 0x2b, 0x3c,
  0x08, 0x00, 0x47, 0x00, 0x00, 0x44, 0x41, 0xaa, 0x00, 0x00, 0x01, 0x11,
  0x39, 0xec, 0x44, 0x55, 0x02, 0x65, 0x40, 0xe9, 0xa9, 0x69, 0x07, 0x07,
  0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa1, 0x79, 0x82, 0x9a, 0x00, 0x28,
  0xb5, 0x78, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
  0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
  0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
};

/* Frame 24: the router's ICMP time exceeded reply. */
static const uint8_t FRAME_ICMP[] = {
  0x00, 0x16, 0x3e, 0x1a, 0x2b, 0x3c, 0x00, 0x22, 0x5f, 0x4d, 0x5e, 0x6f,
  0x08, 0x00, 0x45, 0x00, 0x00, 0x40, 0x51, 0xb9, 0x00, 0x00, 0x40, 0x01,
  0x9b, 0xf4, 0x44, 0x55, 0x02, 0x01, 0x44, 0x55, 0x02, 0x65, 0x0b, 0x00,
  0x1b, 0x4b, 0x00, 0x00, 0x00, 0x00, 0x47, 0x00, 0x00, 0x44, 0x41, 0xaa,
  0x00, 0x00, 0x01, 0x11, 0x39, 0xec, 0x44, 0x55, 0x02, 0x65, 0x40, 0xe9,
  0xa9, 0x69, 0x07, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa1, 0x79,
  0x82, 0x9a, 0x00, 0x28, 0xb5, 0x78,
};

/* ======================================================================== */
/* Builders for synthetic frames and captures                               */
/* ======================================================================== */

/* 10.0.0.1 and 10.0.0.2, the addresses malformed.pcap uses. */
#define IP_A 0x0a000001u
#define IP_B 0x0a000002u

/* Room for any frame these tests build. */
#define FRAME_MAX 1600

static void put16(uint8_t *p, uint16_t v)
{
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)v;
}

static void put32(uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

static uint16_t get16(const uint8_t *p)
{
  return (uint16_t)((unsigned)p[0] << 8 | (unsigned)p[1]);
}

/* Writes a 32-bit pcap header field in the chosen byte order. */
static void put32_order(uint8_t *p, uint32_t v, bool big)
{
  if (big) {
    put32(p, v);
  } else {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
  }
}

static void put16_order(uint8_t *p, uint16_t v, bool big)
{
  if (big) {
    put16(p, v);
  } else {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
  }
}

/* Fills in the IPv4 header checksum of an Ethernet + IPv4 frame. */
static void fix_ip_checksum(uint8_t *f)
{
  uint8_t *ip = f + ETH_HEADER_LEN;
  size_t hl = (size_t)(ip[0] & 0x0f) * 4;
  put16(ip + 10, 0);
  put16(ip + 10, inet_checksum(ip, hl, 0));
}

/* Fills in the TCP or UDP checksum of an Ethernet + IPv4 frame. */
static void fix_l4_checksum(uint8_t *f)
{
  uint8_t *ip = f + ETH_HEADER_LEN;
  size_t hl = (size_t)(ip[0] & 0x0f) * 4;
  uint8_t *l4 = ip + hl;
  bool tcp = ip[9] == PROTO_TCP;
  uint16_t len = tcp ? (uint16_t)(get16(ip + 2) - hl) : get16(l4 + 4);
  uint8_t *field = l4 + (tcp ? 16 : 6);
  put16(field, 0);
  uint32_t src = (uint32_t)get16(ip + 12) << 16 | get16(ip + 14);
  uint32_t dst = (uint32_t)get16(ip + 16) << 16 | get16(ip + 18);
  uint16_t c = inet_checksum(l4, len, pseudo_header_sum(src, dst, ip[9], len));
  put16(field, (!tcp && c == 0) ? 0xffff : c);
}

/* Writes Ethernet + IPv4 (with opt_len bytes of NOP options) + l4, and the
 * IPv4 checksum. Returns the frame length. */
static size_t build_ipv4(uint8_t *f, uint8_t proto, size_t opt_len, const uint8_t *l4,
                         size_t l4_len)
{
  memset(f, 0, ETH_HEADER_LEN);
  f[0] = 0x02;
  f[5] = 0x02;
  f[6] = 0x02;
  f[11] = 0x01;
  put16(f + 12, ETHERTYPE_IPV4);
  uint8_t *ip = f + ETH_HEADER_LEN;
  size_t hl = IPV4_MIN_HEADER_LEN + opt_len;
  memset(ip, 0, hl);
  ip[0] = (uint8_t)(0x40 | (hl / 4));
  put16(ip + 2, (uint16_t)(hl + l4_len));
  put16(ip + 4, 0x1234);
  ip[8] = 64;
  ip[9] = proto;
  put32(ip + 12, IP_A);
  put32(ip + 16, IP_B);
  memset(ip + IPV4_MIN_HEADER_LEN, 0x01, opt_len);
  memcpy(ip + hl, l4, l4_len);
  fix_ip_checksum(f);
  return ETH_HEADER_LEN + hl + l4_len;
}

/* A TCP frame from 10.0.0.1:5000 to 10.0.0.2:80 with a correct checksum. */
static size_t build_tcp(uint8_t *f, uint8_t flags, size_t data_offset, size_t payload_len)
{
  uint8_t seg[FRAME_MAX];
  size_t hl = data_offset * 4;
  memset(seg, 0, hl);
  put16(seg, 5000);
  put16(seg + 2, 80);
  put32(seg + 4, 1);
  put32(seg + 8, 0);
  seg[12] = (uint8_t)(data_offset << 4);
  seg[13] = flags;
  put16(seg + 14, 1024);
  memset(seg + TCP_MIN_HEADER_LEN, 0x01, hl - TCP_MIN_HEADER_LEN);
  for (size_t i = 0; i < payload_len; i++) {
    seg[hl + i] = (uint8_t)('a' + i % 26);
  }
  size_t n = build_ipv4(f, PROTO_TCP, 0, seg, hl + payload_len);
  fix_l4_checksum(f);
  return n;
}

/* A UDP frame from 10.0.0.1:5000 to 10.0.0.2:6000 with a correct checksum. */
static size_t build_udp(uint8_t *f, size_t opt_len, size_t payload_len)
{
  uint8_t dg[FRAME_MAX];
  put16(dg, 5000);
  put16(dg + 2, 6000);
  put16(dg + 4, (uint16_t)(UDP_HEADER_LEN + payload_len));
  put16(dg + 6, 0);
  for (size_t i = 0; i < payload_len; i++) {
    dg[UDP_HEADER_LEN + i] = (uint8_t)('A' + i % 26);
  }
  size_t n = build_ipv4(f, PROTO_UDP, opt_len, dg, UDP_HEADER_LEN + payload_len);
  fix_l4_checksum(f);
  return n;
}

/* Writes a pcap file header. Returns 24. */
static size_t build_pcap_header(uint8_t *buf, bool big, uint32_t magic, uint16_t major,
                                uint32_t linktype)
{
  put32_order(buf, magic, big);
  put16_order(buf + 4, major, big);
  put16_order(buf + 6, 4, big);
  put32_order(buf + 8, 0, big);
  put32_order(buf + 12, 0, big);
  put32_order(buf + 16, 262144, big);
  put32_order(buf + 20, linktype, big);
  return PCAP_FILE_HEADER_LEN;
}

/* Appends a record at pos and returns the new end of the file. */
static size_t add_record(uint8_t *buf, size_t pos, bool big, uint32_t sec, uint32_t usec,
                         const uint8_t *frame, uint32_t caplen, uint32_t origlen)
{
  put32_order(buf + pos, sec, big);
  put32_order(buf + pos + 4, usec, big);
  put32_order(buf + pos + 8, caplen, big);
  put32_order(buf + pos + 12, origlen, big);
  memcpy(buf + pos + PCAP_RECORD_HEADER_LEN, frame, caplen);
  return pos + PCAP_RECORD_HEADER_LEN + caplen;
}

/* A three frame capture: ARP request, the TCP ACK, then the padded ACK
 * coming back, so one flow is seen in both directions. */
static size_t build_small_capture(uint8_t *buf, bool big)
{
  size_t n = build_pcap_header(buf, big, PCAP_MAGIC, 2, 1);
  n = add_record(buf, n, big, 1000, 999000, FRAME_ARP_REQUEST, sizeof FRAME_ARP_REQUEST,
                 sizeof FRAME_ARP_REQUEST);
  n = add_record(buf, n, big, 1001, 500, FRAME_TCP_ACK, sizeof FRAME_TCP_ACK,
                 sizeof FRAME_TCP_ACK);
  n = add_record(buf, n, big, 1001, 2500, FRAME_TCP_PADDED, sizeof FRAME_TCP_PADDED,
                 sizeof FRAME_TCP_PADDED);
  return n;
}

static const char *SMALL_CAPTURE_REPORT =
  "1 0.000000 ARP request who-has 68.85.2.1 tell 68.85.2.101\n"
  "2 0.001500 TCP 68.85.2.101:49152 > 64.233.169.105:80 [.] seq=3127851021 ack=2215467234 "
  "win=502 len=0 cksum=ok\n"
  "3 0.003500 TCP 64.233.169.105:80 > 68.85.2.101:49152 [.] seq=2215467234 ack=3127851098 "
  "win=1050 len=0 cksum=ok\n"
  "\n"
  "TCP 68.85.2.101:49152 <> 64.233.169.105:80 packets=2 bytes=114\n";

/* Reads everything written to a tmpfile() back as a string; closes it. */
static char *drain(FILE *f)
{
  long size = ftell(f);
  TEST_ASSERT_TRUE(size >= 0);
  rewind(f);
  char *text = calloc((size_t)size + 1, 1);
  TEST_ASSERT_NOT_NULL(text);
  TEST_ASSERT_EQUAL_size_t((size_t)size, fread(text, 1, (size_t)size, f));
  fclose(f);
  return text;
}

/* Runs report_capture() into tmpfiles and returns what it printed. */
static int run_report(const uint8_t *data, size_t len, bool summary_only, char **out_text,
                      char **err_text)
{
  FILE *out = tmpfile();
  FILE *err = tmpfile();
  TEST_ASSERT_NOT_NULL(out);
  TEST_ASSERT_NOT_NULL(err);
  int status = report_capture(data, len, "test.pcap", summary_only, out, err);
  *out_text = drain(out);
  *err_text = drain(err);
  return status;
}

/* Reads a file from the repository root into memory. */
static uint8_t *slurp(const char *path, size_t *len)
{
  FILE *f = fopen(path, "rb");
  TEST_ASSERT_NOT_NULL_MESSAGE(f, path);
  TEST_ASSERT_EQUAL_INT(0, fseek(f, 0, SEEK_END));
  long size = ftell(f);
  TEST_ASSERT_TRUE(size >= 0);
  rewind(f);
  uint8_t *data = malloc((size_t)size + 1);
  TEST_ASSERT_NOT_NULL(data);
  TEST_ASSERT_EQUAL_size_t((size_t)size, fread(data, 1, (size_t)size, f));
  data[size] = 0;
  fclose(f);
  *len = (size_t)size;
  return data;
}

/* Decodes a frame and checks its description. */
static void assert_decodes(const uint8_t *f, size_t caplen, uint32_t origlen, const char *want)
{
  frame_info info;
  TEST_ASSERT_TRUE(decode_frame(f, caplen, origlen, &info));
  TEST_ASSERT_EQUAL_STRING(want, info.text);
}

/* ======================================================================== */
/* Layer 1: pcap_open, pcap_next, pcap_strerror                             */
/* ======================================================================== */

void test_pcap_open_little_endian(void)
{
  uint8_t buf[PCAP_FILE_HEADER_LEN];
  build_pcap_header(buf, false, PCAP_MAGIC, 2, 1);
  TEST_ASSERT_EQUAL_HEX8(0xd4, buf[0]);
  pcap_reader r;
  TEST_ASSERT_EQUAL_INT(PCAP_OK, pcap_open(&r, buf, sizeof buf));
  TEST_ASSERT_FALSE(r.big_endian);
  TEST_ASSERT_EQUAL_UINT16(2, r.version_major);
  TEST_ASSERT_EQUAL_UINT16(4, r.version_minor);
  TEST_ASSERT_EQUAL_UINT32(262144, r.snaplen);
  TEST_ASSERT_EQUAL_UINT32(1, r.linktype);
  TEST_ASSERT_EQUAL_size_t(PCAP_FILE_HEADER_LEN, r.pos);
}

void test_pcap_open_big_endian(void)
{
  uint8_t buf[PCAP_FILE_HEADER_LEN];
  build_pcap_header(buf, true, PCAP_MAGIC, 2, 1);
  TEST_ASSERT_EQUAL_HEX8(0xa1, buf[0]);
  pcap_reader r;
  TEST_ASSERT_EQUAL_INT(PCAP_OK, pcap_open(&r, buf, sizeof buf));
  TEST_ASSERT_TRUE(r.big_endian);
  TEST_ASSERT_EQUAL_UINT16(2, r.version_major);
  TEST_ASSERT_EQUAL_UINT32(262144, r.snaplen);
  TEST_ASSERT_EQUAL_UINT32(1, r.linktype);
}

void test_pcap_open_null_arguments(void)
{
  uint8_t buf[PCAP_FILE_HEADER_LEN];
  build_pcap_header(buf, false, PCAP_MAGIC, 2, 1);
  pcap_reader r;
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_ARGS, pcap_open(NULL, buf, sizeof buf));
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_ARGS, pcap_open(&r, NULL, sizeof buf));
  /* No bytes at all is a short file, not a missing argument. */
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_SHORT, pcap_open(&r, NULL, 0));
}

void test_pcap_open_cut_inside_file_header(void)
{
  uint8_t buf[PCAP_FILE_HEADER_LEN];
  build_pcap_header(buf, false, PCAP_MAGIC, 2, 1);
  pcap_reader r;
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_SHORT, pcap_open(&r, buf, 0));
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_SHORT, pcap_open(&r, buf, 7));
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_SHORT, pcap_open(&r, buf, PCAP_FILE_HEADER_LEN - 1));
}

void test_pcap_open_pcapng(void)
{
  uint8_t buf[PCAP_FILE_HEADER_LEN] = {0x0a, 0x0d, 0x0d, 0x0a, 0x1c, 0x00, 0x00, 0x00,
                                       0x4d, 0x3c, 0x2b, 0x1a};
  pcap_reader r;
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_PCAPNG, pcap_open(&r, buf, sizeof buf));
}

void test_pcap_open_bad_magic(void)
{
  uint8_t buf[PCAP_FILE_HEADER_LEN];
  pcap_reader r;
  build_pcap_header(buf, false, 0x12345678u, 2, 1);
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_MAGIC, pcap_open(&r, buf, sizeof buf));
  /* The nanosecond pcap variant is "anything else" too. */
  build_pcap_header(buf, false, 0xa1b23c4du, 2, 1);
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_MAGIC, pcap_open(&r, buf, sizeof buf));
  memset(buf, 0, sizeof buf);
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_MAGIC, pcap_open(&r, buf, sizeof buf));
}

void test_pcap_open_major_version(void)
{
  uint8_t buf[PCAP_FILE_HEADER_LEN];
  pcap_reader r;
  build_pcap_header(buf, false, PCAP_MAGIC, 3, 1);
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_VERSION, pcap_open(&r, buf, sizeof buf));
  build_pcap_header(buf, true, PCAP_MAGIC, 1, 1);
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_VERSION, pcap_open(&r, buf, sizeof buf));
  /* The minor version is not checked. */
  build_pcap_header(buf, false, PCAP_MAGIC, 2, 1);
  put16_order(buf + 6, 99, false);
  TEST_ASSERT_EQUAL_INT(PCAP_OK, pcap_open(&r, buf, sizeof buf));
  TEST_ASSERT_EQUAL_UINT16(99, r.version_minor);
}

void test_pcap_open_link_type(void)
{
  uint8_t buf[PCAP_FILE_HEADER_LEN];
  pcap_reader r;
  build_pcap_header(buf, false, PCAP_MAGIC, 2, 101);
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_LINKTYPE, pcap_open(&r, buf, sizeof buf));
  build_pcap_header(buf, true, PCAP_MAGIC, 2, 0);
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_LINKTYPE, pcap_open(&r, buf, sizeof buf));
  /* A big endian 1 read as little endian would be 0x01000000. */
  build_pcap_header(buf, true, PCAP_MAGIC, 2, 0x01000000u);
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_LINKTYPE, pcap_open(&r, buf, sizeof buf));
}

/* Reads the three records of build_small_capture() in one byte order. */
static void check_small_capture_records(bool big)
{
  uint8_t buf[512];
  size_t n = build_small_capture(buf, big);
  pcap_reader r;
  pcap_record rec;
  TEST_ASSERT_EQUAL_INT(PCAP_OK, pcap_open(&r, buf, n));
  TEST_ASSERT_EQUAL(big, r.big_endian);

  TEST_ASSERT_EQUAL_INT(PCAP_OK, pcap_next(&r, &rec));
  TEST_ASSERT_EQUAL_UINT32(1000, rec.ts_sec);
  TEST_ASSERT_EQUAL_UINT32(999000, rec.ts_usec);
  TEST_ASSERT_EQUAL_UINT32(sizeof FRAME_ARP_REQUEST, rec.caplen);
  TEST_ASSERT_EQUAL_UINT32(sizeof FRAME_ARP_REQUEST, rec.origlen);
  TEST_ASSERT_EQUAL_PTR(buf + PCAP_FILE_HEADER_LEN + PCAP_RECORD_HEADER_LEN, rec.data);
  TEST_ASSERT_EQUAL_MEMORY(FRAME_ARP_REQUEST, rec.data, rec.caplen);

  TEST_ASSERT_EQUAL_INT(PCAP_OK, pcap_next(&r, &rec));
  TEST_ASSERT_EQUAL_UINT32(1001, rec.ts_sec);
  TEST_ASSERT_EQUAL_MEMORY(FRAME_TCP_ACK, rec.data, rec.caplen);
  TEST_ASSERT_EQUAL_INT(PCAP_OK, pcap_next(&r, &rec));
  TEST_ASSERT_EQUAL_UINT32(2500, rec.ts_usec);
  TEST_ASSERT_EQUAL_UINT32(60, rec.caplen);

  TEST_ASSERT_EQUAL_INT(PCAP_END, pcap_next(&r, &rec));
  TEST_ASSERT_EQUAL_INT(PCAP_END, pcap_next(&r, &rec));
}

void test_pcap_next_little_endian_records(void)
{
  check_small_capture_records(false);
}

void test_pcap_next_big_endian_records(void)
{
  check_small_capture_records(true);
}

void test_pcap_next_header_only_file(void)
{
  uint8_t buf[PCAP_FILE_HEADER_LEN];
  build_pcap_header(buf, false, PCAP_MAGIC, 2, 1);
  pcap_reader r;
  pcap_record rec;
  TEST_ASSERT_EQUAL_INT(PCAP_OK, pcap_open(&r, buf, sizeof buf));
  TEST_ASSERT_EQUAL_INT(PCAP_END, pcap_next(&r, &rec));
}

void test_pcap_next_cut_inside_record_header(void)
{
  uint8_t buf[512];
  size_t n = build_small_capture(buf, false);
  pcap_reader r;
  pcap_record rec;
  /* Keep the first record whole and 10 bytes of the second record header. */
  size_t cut = PCAP_FILE_HEADER_LEN + PCAP_RECORD_HEADER_LEN + sizeof FRAME_ARP_REQUEST + 10;
  TEST_ASSERT_TRUE(cut < n);
  TEST_ASSERT_EQUAL_INT(PCAP_OK, pcap_open(&r, buf, cut));
  TEST_ASSERT_EQUAL_INT(PCAP_OK, pcap_next(&r, &rec));
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_RECORD_HEADER, pcap_next(&r, &rec));
  /* The reader did not move, so it says the same thing again. */
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_RECORD_HEADER, pcap_next(&r, &rec));
  /* One byte of record header is still a broken record header. */
  TEST_ASSERT_EQUAL_INT(PCAP_OK, pcap_open(&r, buf, PCAP_FILE_HEADER_LEN + 1));
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_RECORD_HEADER, pcap_next(&r, &rec));
}

void test_pcap_next_cut_inside_record_data(void)
{
  uint8_t buf[512];
  build_small_capture(buf, true);
  pcap_reader r;
  pcap_record rec;
  memset(&rec, 0xab, sizeof rec);
  pcap_record sentinel = rec;
  size_t cut = PCAP_FILE_HEADER_LEN + PCAP_RECORD_HEADER_LEN + sizeof FRAME_ARP_REQUEST - 1;
  TEST_ASSERT_EQUAL_INT(PCAP_OK, pcap_open(&r, buf, cut));
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_RECORD_DATA, pcap_next(&r, &rec));
  TEST_ASSERT_EQUAL_MEMORY(&sentinel, &rec, sizeof rec);
}

void test_pcap_next_caplen_over_origlen(void)
{
  uint8_t buf[256];
  size_t n = build_pcap_header(buf, false, PCAP_MAGIC, 2, 1);
  n = add_record(buf, n, false, 1, 2, FRAME_TCP_ACK, sizeof FRAME_TCP_ACK, 50);
  pcap_reader r;
  pcap_record rec;
  TEST_ASSERT_EQUAL_INT(PCAP_OK, pcap_open(&r, buf, n));
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_CAPLEN, pcap_next(&r, &rec));
}

void test_pcap_next_huge_caplen_does_not_wrap(void)
{
  uint8_t buf[64];
  size_t n = build_pcap_header(buf, false, PCAP_MAGIC, 2, 1);
  put32_order(buf + n, 0, false);
  put32_order(buf + n + 4, 0, false);
  put32_order(buf + n + 8, 0xffffffffu, false);
  put32_order(buf + n + 12, 0xffffffffu, false);
  n += PCAP_RECORD_HEADER_LEN;
  pcap_reader r;
  pcap_record rec;
  TEST_ASSERT_EQUAL_INT(PCAP_OK, pcap_open(&r, buf, n));
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_RECORD_DATA, pcap_next(&r, &rec));
}

void test_pcap_next_empty_record(void)
{
  uint8_t buf[64];
  size_t n = build_pcap_header(buf, false, PCAP_MAGIC, 2, 1);
  n = add_record(buf, n, false, 5, 6, FRAME_TCP_ACK, 0, 60);
  pcap_reader r;
  pcap_record rec;
  TEST_ASSERT_EQUAL_INT(PCAP_OK, pcap_open(&r, buf, n));
  TEST_ASSERT_EQUAL_INT(PCAP_OK, pcap_next(&r, &rec));
  TEST_ASSERT_EQUAL_UINT32(0, rec.caplen);
  TEST_ASSERT_EQUAL_UINT32(60, rec.origlen);
  TEST_ASSERT_EQUAL_INT(PCAP_END, pcap_next(&r, &rec));
}

void test_pcap_next_null_arguments(void)
{
  uint8_t buf[PCAP_FILE_HEADER_LEN];
  build_pcap_header(buf, false, PCAP_MAGIC, 2, 1);
  pcap_reader r;
  pcap_record rec;
  TEST_ASSERT_EQUAL_INT(PCAP_OK, pcap_open(&r, buf, sizeof buf));
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_ARGS, pcap_next(NULL, &rec));
  TEST_ASSERT_EQUAL_INT(PCAP_ERR_ARGS, pcap_next(&r, NULL));
}

void test_pcap_strerror(void)
{
  const pcap_status all[] = {
    PCAP_OK,         PCAP_END,          PCAP_ERR_ARGS,          PCAP_ERR_SHORT,
    PCAP_ERR_PCAPNG, PCAP_ERR_MAGIC,    PCAP_ERR_VERSION,       PCAP_ERR_LINKTYPE,
    PCAP_ERR_RECORD_HEADER, PCAP_ERR_RECORD_DATA, PCAP_ERR_CAPLEN,
  };
  const size_t count = sizeof all / sizeof all[0];
  for (size_t i = 0; i < count; i++) {
    const char *msg = pcap_strerror(all[i]);
    TEST_ASSERT_NOT_NULL(msg);
    TEST_ASSERT_TRUE(strlen(msg) > 0);
    TEST_ASSERT_NOT_EQUAL(0, strcmp(msg, "unknown error"));
    for (size_t j = 0; j < i; j++) {
      TEST_ASSERT_NOT_EQUAL(0, strcmp(msg, pcap_strerror(all[j])));
    }
  }
  TEST_ASSERT_NOT_NULL(strstr(pcap_strerror(PCAP_ERR_PCAPNG), "pcapng"));
  TEST_ASSERT_EQUAL_STRING("unknown error", pcap_strerror((pcap_status)99));
}

/* ======================================================================== */
/* Layer 2: parsers                                                         */
/* ======================================================================== */

void test_eth_parse_arp_request(void)
{
  eth_header eth;
  TEST_ASSERT_EQUAL_INT(PARSE_OK, eth_parse(FRAME_ARP_REQUEST, sizeof FRAME_ARP_REQUEST, &eth));
  const uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  const uint8_t laptop[6] = {0x00, 0x16, 0x3e, 0x1a, 0x2b, 0x3c};
  TEST_ASSERT_EQUAL_MEMORY(broadcast, eth.dst.b, 6);
  TEST_ASSERT_EQUAL_MEMORY(laptop, eth.src.b, 6);
  TEST_ASSERT_EQUAL_HEX16(ETHERTYPE_ARP, eth.ethertype);
  TEST_ASSERT_EQUAL_PTR(FRAME_ARP_REQUEST + ETH_HEADER_LEN, eth.payload);
  TEST_ASSERT_EQUAL_size_t(ARP_LEN, eth.payload_len);
}

void test_eth_parse_padded_frame_keeps_padding(void)
{
  eth_header eth;
  TEST_ASSERT_EQUAL_INT(PARSE_OK, eth_parse(FRAME_TCP_PADDED, sizeof FRAME_TCP_PADDED, &eth));
  TEST_ASSERT_EQUAL_HEX16(ETHERTYPE_IPV4, eth.ethertype);
  /* Ethernet cannot tell padding from payload; IPv4's total length can. */
  TEST_ASSERT_EQUAL_size_t(46, eth.payload_len);
}

void test_eth_parse_short(void)
{
  eth_header eth;
  memset(&eth, 0x5a, sizeof eth);
  eth_header sentinel = eth;
  TEST_ASSERT_EQUAL_INT(PARSE_SHORT, eth_parse(FRAME_TCP_ACK, ETH_HEADER_LEN - 1, &eth));
  TEST_ASSERT_EQUAL_INT(PARSE_SHORT, eth_parse(FRAME_TCP_ACK, 0, &eth));
  TEST_ASSERT_EQUAL_MEMORY(&sentinel, &eth, sizeof eth);
  /* Exactly a header and nothing else is fine. */
  TEST_ASSERT_EQUAL_INT(PARSE_OK, eth_parse(FRAME_TCP_ACK, ETH_HEADER_LEN, &eth));
  TEST_ASSERT_EQUAL_size_t(0, eth.payload_len);
}

void test_eth_parse_null_arguments(void)
{
  eth_header eth;
  TEST_ASSERT_EQUAL_INT(PARSE_ARGS, eth_parse(NULL, 60, &eth));
  TEST_ASSERT_EQUAL_INT(PARSE_ARGS, eth_parse(FRAME_TCP_ACK, sizeof FRAME_TCP_ACK, NULL));
}

void test_arp_parse_request(void)
{
  arp_packet arp;
  const uint8_t *p = FRAME_ARP_REQUEST + ETH_HEADER_LEN;
  TEST_ASSERT_EQUAL_INT(PARSE_OK, arp_parse(p, ARP_LEN, &arp));
  TEST_ASSERT_EQUAL_UINT16(1, arp.htype);
  TEST_ASSERT_EQUAL_HEX16(0x0800, arp.ptype);
  TEST_ASSERT_EQUAL_UINT8(6, arp.hlen);
  TEST_ASSERT_EQUAL_UINT8(4, arp.plen);
  TEST_ASSERT_EQUAL_UINT16(ARP_OP_REQUEST, arp.op);
  TEST_ASSERT_EQUAL_HEX32(0x44550265, arp.spa); /* 68.85.2.101 */
  TEST_ASSERT_EQUAL_HEX32(0x44550201, arp.tpa); /* 68.85.2.1 */
  TEST_ASSERT_EQUAL_HEX8(0x3c, arp.sha.b[5]);
  TEST_ASSERT_EQUAL_HEX8(0x00, arp.tha.b[0]);
}

void test_arp_parse_reply_ignores_padding(void)
{
  arp_packet arp;
  const uint8_t *p = FRAME_ARP_REPLY + ETH_HEADER_LEN;
  TEST_ASSERT_EQUAL_INT(PARSE_OK, arp_parse(p, sizeof FRAME_ARP_REPLY - ETH_HEADER_LEN, &arp));
  TEST_ASSERT_EQUAL_UINT16(ARP_OP_REPLY, arp.op);
  const uint8_t router[6] = {0x00, 0x22, 0x5f, 0x4d, 0x5e, 0x6f};
  TEST_ASSERT_EQUAL_MEMORY(router, arp.sha.b, 6);
  TEST_ASSERT_EQUAL_HEX32(0x44550201, arp.spa);
}

void test_arp_parse_short(void)
{
  arp_packet arp;
  memset(&arp, 0x77, sizeof arp);
  arp_packet sentinel = arp;
  const uint8_t *p = FRAME_ARP_REQUEST + ETH_HEADER_LEN;
  TEST_ASSERT_EQUAL_INT(PARSE_SHORT, arp_parse(p, ARP_LEN - 1, &arp));
  TEST_ASSERT_EQUAL_MEMORY(&sentinel, &arp, sizeof arp);
}

void test_arp_parse_not_ipv4_over_ethernet(void)
{
  arp_packet arp;
  uint8_t p[ARP_LEN];

  memcpy(p, FRAME_ARP_REQUEST + ETH_HEADER_LEN, ARP_LEN);
  put16(p, 6); /* hardware type IEEE 802 */
  TEST_ASSERT_EQUAL_INT(PARSE_ILLEGAL, arp_parse(p, ARP_LEN, &arp));

  memcpy(p, FRAME_ARP_REQUEST + ETH_HEADER_LEN, ARP_LEN);
  put16(p + 2, 0x86dd); /* protocol type IPv6 */
  TEST_ASSERT_EQUAL_INT(PARSE_ILLEGAL, arp_parse(p, ARP_LEN, &arp));

  memcpy(p, FRAME_ARP_REQUEST + ETH_HEADER_LEN, ARP_LEN);
  p[4] = 8; /* hardware address length */
  TEST_ASSERT_EQUAL_INT(PARSE_ILLEGAL, arp_parse(p, ARP_LEN, &arp));

  memcpy(p, FRAME_ARP_REQUEST + ETH_HEADER_LEN, ARP_LEN);
  p[5] = 16; /* protocol address length */
  TEST_ASSERT_EQUAL_INT(PARSE_ILLEGAL, arp_parse(p, ARP_LEN, &arp));
}

void test_arp_parse_null_arguments(void)
{
  arp_packet arp;
  TEST_ASSERT_EQUAL_INT(PARSE_ARGS, arp_parse(NULL, ARP_LEN, &arp));
  TEST_ASSERT_EQUAL_INT(PARSE_ARGS, arp_parse(FRAME_ARP_REQUEST + ETH_HEADER_LEN, ARP_LEN, NULL));
}

void test_ipv4_parse_real_header(void)
{
  ipv4_header ip;
  const uint8_t *p = FRAME_TCP_ACK + ETH_HEADER_LEN;
  TEST_ASSERT_EQUAL_INT(PARSE_OK, ipv4_parse(p, sizeof FRAME_TCP_ACK - ETH_HEADER_LEN, false, &ip));
  TEST_ASSERT_EQUAL_UINT8(4, ip.version);
  TEST_ASSERT_EQUAL_UINT8(5, ip.ihl);
  TEST_ASSERT_EQUAL_UINT16(40, ip.total_len);
  TEST_ASSERT_EQUAL_HEX16(0x8a3f, ip.id);
  TEST_ASSERT_TRUE(ip.dont_fragment);
  TEST_ASSERT_FALSE(ip.more_fragments);
  TEST_ASSERT_EQUAL_UINT16(0, ip.frag_offset);
  TEST_ASSERT_EQUAL_UINT8(64, ip.ttl);
  TEST_ASSERT_EQUAL_UINT8(PROTO_TCP, ip.protocol);
  TEST_ASSERT_EQUAL_HEX16(0x7f84, ip.checksum);
  TEST_ASSERT_TRUE(ip.checksum_ok);
  TEST_ASSERT_EQUAL_HEX32(0x44550265, ip.src);
  TEST_ASSERT_EQUAL_HEX32(0x40e9a969, ip.dst);
  TEST_ASSERT_EQUAL_size_t(20, ip.header_len);
  TEST_ASSERT_EQUAL_PTR(p + 20, ip.payload);
  TEST_ASSERT_EQUAL_size_t(20, ip.payload_len);
  TEST_ASSERT_EQUAL_size_t(20, ip.payload_avail);
}

void test_ipv4_parse_ignores_ethernet_padding(void)
{
  ipv4_header ip;
  const uint8_t *p = FRAME_TCP_PADDED + ETH_HEADER_LEN;
  TEST_ASSERT_EQUAL_INT(PARSE_OK,
                        ipv4_parse(p, sizeof FRAME_TCP_PADDED - ETH_HEADER_LEN, false, &ip));
  TEST_ASSERT_EQUAL_UINT16(40, ip.total_len);
  /* 46 bytes followed Ethernet, but only 40 are the datagram. */
  TEST_ASSERT_EQUAL_size_t(20, ip.payload_len);
  TEST_ASSERT_EQUAL_size_t(20, ip.payload_avail);
}

void test_ipv4_parse_with_options(void)
{
  ipv4_header ip;
  const uint8_t *p = FRAME_IP_OPTIONS + ETH_HEADER_LEN;
  TEST_ASSERT_EQUAL_INT(PARSE_OK,
                        ipv4_parse(p, sizeof FRAME_IP_OPTIONS - ETH_HEADER_LEN, false, &ip));
  TEST_ASSERT_EQUAL_UINT8(7, ip.ihl);
  TEST_ASSERT_EQUAL_size_t(28, ip.header_len);
  TEST_ASSERT_TRUE(ip.checksum_ok);
  TEST_ASSERT_EQUAL_UINT8(1, ip.ttl);
  TEST_ASSERT_EQUAL_UINT8(PROTO_UDP, ip.protocol);
  /* The UDP header starts after the option, not at byte 20. */
  TEST_ASSERT_EQUAL_PTR(p + 28, ip.payload);
  TEST_ASSERT_EQUAL_size_t(40, ip.payload_len);
}

void test_ipv4_parse_short(void)
{
  ipv4_header ip;
  memset(&ip, 0x33, sizeof ip);
  ipv4_header sentinel = ip;
  const uint8_t *p = FRAME_TCP_ACK + ETH_HEADER_LEN;
  TEST_ASSERT_EQUAL_INT(PARSE_SHORT, ipv4_parse(p, IPV4_MIN_HEADER_LEN - 1, false, &ip));
  TEST_ASSERT_EQUAL_INT(PARSE_SHORT, ipv4_parse(p, 0, true, &ip));
  TEST_ASSERT_EQUAL_MEMORY(&sentinel, &ip, sizeof ip);
}

void test_ipv4_parse_version_not_4(void)
{
  ipv4_header ip;
  uint8_t p[40];
  memcpy(p, FRAME_TCP_ACK + ETH_HEADER_LEN, sizeof p);
  p[0] = 0x65;
  TEST_ASSERT_EQUAL_INT(PARSE_ILLEGAL, ipv4_parse(p, sizeof p, false, &ip));
}

void test_ipv4_parse_ihl_under_5(void)
{
  ipv4_header ip;
  uint8_t p[40];
  memcpy(p, FRAME_TCP_ACK + ETH_HEADER_LEN, sizeof p);
  p[0] = 0x44;
  TEST_ASSERT_EQUAL_INT(PARSE_ILLEGAL, ipv4_parse(p, sizeof p, false, &ip));
}

void test_ipv4_parse_ihl_past_captured_bytes(void)
{
  ipv4_header ip;
  uint8_t p[40];
  memcpy(p, FRAME_TCP_ACK + ETH_HEADER_LEN, sizeof p);
  p[0] = 0x4f; /* 60 byte header in 40 bytes */
  TEST_ASSERT_EQUAL_INT(PARSE_SHORT, ipv4_parse(p, sizeof p, false, &ip));
  /* A snaplen cut does not excuse a header that is not there. */
  TEST_ASSERT_EQUAL_INT(PARSE_SHORT, ipv4_parse(p, sizeof p, true, &ip));
}

void test_ipv4_parse_total_length_shorter_than_header(void)
{
  ipv4_header ip;
  uint8_t p[40];
  memcpy(p, FRAME_TCP_ACK + ETH_HEADER_LEN, sizeof p);
  put16(p + 2, 19);
  TEST_ASSERT_EQUAL_INT(PARSE_ILLEGAL, ipv4_parse(p, sizeof p, false, &ip));
}

void test_ipv4_parse_total_length_past_captured_bytes(void)
{
  ipv4_header ip;
  uint8_t p[40];
  memcpy(p, FRAME_TCP_ACK + ETH_HEADER_LEN, sizeof p);
  put16(p + 2, 1500);
  TEST_ASSERT_EQUAL_INT(PARSE_SHORT, ipv4_parse(p, sizeof p, false, &ip));
  /* Cut short by the snaplen, it is fine: decode what is there. */
  TEST_ASSERT_EQUAL_INT(PARSE_OK, ipv4_parse(p, sizeof p, true, &ip));
  TEST_ASSERT_EQUAL_size_t(1480, ip.payload_len);
  TEST_ASSERT_EQUAL_size_t(20, ip.payload_avail);
}

void test_ipv4_parse_reports_bad_header_checksum(void)
{
  ipv4_header ip;
  uint8_t p[40];
  memcpy(p, FRAME_TCP_ACK + ETH_HEADER_LEN, sizeof p);
  p[8] = 63; /* change the TTL without fixing the checksum */
  TEST_ASSERT_EQUAL_INT(PARSE_OK, ipv4_parse(p, sizeof p, false, &ip));
  TEST_ASSERT_FALSE(ip.checksum_ok);
}

void test_ipv4_parse_fragment_fields(void)
{
  ipv4_header ip;
  uint8_t p[40];
  memcpy(p, FRAME_TCP_ACK + ETH_HEADER_LEN, sizeof p);
  put16(p + 6, 0x2000 | 185); /* MF set, offset 185 */
  TEST_ASSERT_EQUAL_INT(PARSE_OK, ipv4_parse(p, sizeof p, false, &ip));
  TEST_ASSERT_TRUE(ip.more_fragments);
  TEST_ASSERT_FALSE(ip.dont_fragment);
  TEST_ASSERT_EQUAL_UINT16(185, ip.frag_offset);
}

void test_ipv4_parse_null_arguments(void)
{
  ipv4_header ip;
  TEST_ASSERT_EQUAL_INT(PARSE_ARGS, ipv4_parse(NULL, 40, false, &ip));
  TEST_ASSERT_EQUAL_INT(PARSE_ARGS, ipv4_parse(FRAME_TCP_ACK + ETH_HEADER_LEN, 40, false, NULL));
}

void test_tcp_parse_real_header(void)
{
  tcp_header tcp;
  const uint8_t *p = FRAME_TCP_ACK + ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
  TEST_ASSERT_EQUAL_INT(PARSE_OK, tcp_parse(p, TCP_MIN_HEADER_LEN, &tcp));
  TEST_ASSERT_EQUAL_UINT16(49152, tcp.src_port);
  TEST_ASSERT_EQUAL_UINT16(80, tcp.dst_port);
  TEST_ASSERT_EQUAL_UINT32(3127851021u, tcp.seq);
  TEST_ASSERT_EQUAL_UINT32(2215467234u, tcp.ack);
  TEST_ASSERT_EQUAL_UINT8(5, tcp.data_offset);
  TEST_ASSERT_EQUAL_HEX8(TCP_ACK, tcp.flags);
  TEST_ASSERT_EQUAL_UINT16(502, tcp.window);
  TEST_ASSERT_EQUAL_HEX16(0xed14, tcp.checksum);
  TEST_ASSERT_EQUAL_UINT16(0, tcp.urgent);
  TEST_ASSERT_EQUAL_size_t(20, tcp.header_len);
}

void test_tcp_parse_options(void)
{
  uint8_t f[FRAME_MAX];
  build_tcp(f, TCP_SYN, 8, 0);
  tcp_header tcp;
  TEST_ASSERT_EQUAL_INT(PARSE_OK, tcp_parse(f + 34, 32, &tcp));
  TEST_ASSERT_EQUAL_UINT8(8, tcp.data_offset);
  TEST_ASSERT_EQUAL_size_t(32, tcp.header_len);
  /* The same header with 31 bytes available does not fit. */
  TEST_ASSERT_EQUAL_INT(PARSE_SHORT, tcp_parse(f + 34, 31, &tcp));
}

void test_tcp_parse_short_and_illegal(void)
{
  tcp_header tcp;
  memset(&tcp, 0x44, sizeof tcp);
  tcp_header sentinel = tcp;
  uint8_t p[TCP_MIN_HEADER_LEN];
  memcpy(p, FRAME_TCP_ACK + 34, sizeof p);
  TEST_ASSERT_EQUAL_INT(PARSE_SHORT, tcp_parse(p, TCP_MIN_HEADER_LEN - 1, &tcp));
  p[12] = 0x40; /* data offset 4 */
  TEST_ASSERT_EQUAL_INT(PARSE_ILLEGAL, tcp_parse(p, sizeof p, &tcp));
  p[12] = 0x60; /* data offset 6: 24 bytes in 20 */
  TEST_ASSERT_EQUAL_INT(PARSE_SHORT, tcp_parse(p, sizeof p, &tcp));
  TEST_ASSERT_EQUAL_MEMORY(&sentinel, &tcp, sizeof tcp);
}

void test_tcp_parse_null_arguments(void)
{
  tcp_header tcp;
  TEST_ASSERT_EQUAL_INT(PARSE_ARGS, tcp_parse(NULL, 20, &tcp));
  TEST_ASSERT_EQUAL_INT(PARSE_ARGS, tcp_parse(FRAME_TCP_ACK + 34, 20, NULL));
}

void test_udp_parse_real_header(void)
{
  udp_header udp;
  const uint8_t *p = FRAME_DNS_QUERY + 34;
  TEST_ASSERT_EQUAL_INT(PARSE_OK, udp_parse(p, 40, 40, &udp));
  TEST_ASSERT_EQUAL_UINT16(51334, udp.src_port);
  TEST_ASSERT_EQUAL_UINT16(53, udp.dst_port);
  TEST_ASSERT_EQUAL_UINT16(40, udp.length);
  TEST_ASSERT_EQUAL_HEX16(0x6a18, udp.checksum);
}

void test_udp_parse_short_and_illegal(void)
{
  udp_header udp;
  memset(&udp, 0x66, sizeof udp);
  udp_header sentinel = udp;
  uint8_t p[UDP_HEADER_LEN];
  memcpy(p, FRAME_DNS_QUERY + 34, sizeof p);
  TEST_ASSERT_EQUAL_INT(PARSE_SHORT, udp_parse(p, UDP_HEADER_LEN - 1, 40, &udp));
  /* A UDP length longer than the IPv4 payload. */
  TEST_ASSERT_EQUAL_INT(PARSE_ILLEGAL, udp_parse(p, sizeof p, 39, &udp));
  put16(p + 4, 7); /* UDP length under 8 */
  TEST_ASSERT_EQUAL_INT(PARSE_ILLEGAL, udp_parse(p, sizeof p, 40, &udp));
  TEST_ASSERT_EQUAL_MEMORY(&sentinel, &udp, sizeof udp);
}

void test_udp_parse_length_past_captured_bytes_is_legal(void)
{
  /* Under a snaplen, only 8 of the 40 UDP bytes may have been kept. */
  udp_header udp;
  TEST_ASSERT_EQUAL_INT(PARSE_OK, udp_parse(FRAME_DNS_QUERY + 34, 8, 40, &udp));
  TEST_ASSERT_EQUAL_UINT16(40, udp.length);
}

void test_udp_parse_null_arguments(void)
{
  udp_header udp;
  TEST_ASSERT_EQUAL_INT(PARSE_ARGS, udp_parse(NULL, 8, 8, &udp));
  TEST_ASSERT_EQUAL_INT(PARSE_ARGS, udp_parse(FRAME_DNS_QUERY + 34, 40, 40, NULL));
}

void test_inet_checksum_rfc1071_example(void)
{
  /* RFC 1071 section 3: these words sum to 0xddf2. */
  const uint8_t words[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
  TEST_ASSERT_EQUAL_HEX16((uint16_t)~0xddf2u, inet_checksum(words, sizeof words, 0));
}

void test_inet_checksum_odd_length(void)
{
  /* 0x0102 + 0x0300: the odd byte is the high half of the last word. */
  const uint8_t bytes[] = {0x01, 0x02, 0x03};
  TEST_ASSERT_EQUAL_HEX16((uint16_t)~0x0402u, inet_checksum(bytes, sizeof bytes, 0));
  const uint8_t one[] = {0xab};
  TEST_ASSERT_EQUAL_HEX16((uint16_t)~0xab00u, inet_checksum(one, 1, 0));
}

void test_inet_checksum_carries_more_than_once(void)
{
  /* 0xffff + 0xffff + 0x0001 = 0x1ffff. One fold gives 0x10000, which
   * carries again; the true ones' complement sum is 0x0001. */
  const uint8_t bytes[] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x01};
  TEST_ASSERT_EQUAL_HEX16(0xfffe, inet_checksum(bytes, sizeof bytes, 0));
  /* The same thing coming from the initial value. */
  TEST_ASSERT_EQUAL_HEX16(0xfffe, inet_checksum(NULL, 0, 0x1ffffu));
  TEST_ASSERT_EQUAL_HEX16(0x0000, inet_checksum(NULL, 0, 0xffffffffu));
}

void test_inet_checksum_verifies_real_headers(void)
{
  TEST_ASSERT_EQUAL_HEX16(0, inet_checksum(FRAME_TCP_ACK + ETH_HEADER_LEN, 20, 0));
  /* A header with options: the checksum covers all 28 bytes. */
  TEST_ASSERT_EQUAL_HEX16(0, inet_checksum(FRAME_IP_OPTIONS + ETH_HEADER_LEN, 28, 0));
  TEST_ASSERT_NOT_EQUAL(0, inet_checksum(FRAME_IP_OPTIONS + ETH_HEADER_LEN, 20, 0));
}

void test_inet_checksum_null_and_empty(void)
{
  TEST_ASSERT_EQUAL_HEX16(0xffff, inet_checksum(NULL, 0, 0));
  TEST_ASSERT_EQUAL_HEX16(0xffff, inet_checksum(FRAME_TCP_ACK, 0, 0));
  TEST_ASSERT_EQUAL_HEX16((uint16_t)~0x1234u, inet_checksum(NULL, 10, 0x1234));
}

void test_pseudo_header_sum_verifies_real_segments(void)
{
  /* Frame 12: TCP from 68.85.2.101 to 64.233.169.105, 20 bytes. */
  uint32_t tcp = pseudo_header_sum(0x44550265, 0x40e9a969, PROTO_TCP, 20);
  TEST_ASSERT_EQUAL_HEX16(0, inet_checksum(FRAME_TCP_ACK + 34, 20, tcp));
  /* Frame 8: UDP from 68.85.2.101 to 68.87.71.226, 40 bytes. */
  uint32_t udp = pseudo_header_sum(0x44550265, 0x445747e2, PROTO_UDP, 40);
  TEST_ASSERT_EQUAL_HEX16(0, inet_checksum(FRAME_DNS_QUERY + 34, 40, udp));
  /* The pseudo header is part of the sum: the wrong protocol fails. */
  uint32_t wrong = pseudo_header_sum(0x44550265, 0x445747e2, PROTO_TCP, 40);
  TEST_ASSERT_NOT_EQUAL(0, inet_checksum(FRAME_DNS_QUERY + 34, 40, wrong));
}

void test_pseudo_header_sum_value(void)
{
  /* 0x0a00 + 0x0001 + 0x0a00 + 0x0002 + 17 + 8 */
  TEST_ASSERT_EQUAL_HEX32(0x141cu, pseudo_header_sum(IP_A, IP_B, PROTO_UDP, 8));
  /* Unfolded: the top halves of 255.255.255.255 twice already carry. */
  TEST_ASSERT_EQUAL_HEX32(0x3fffcu + 6u + 0xffffu,
                          pseudo_header_sum(0xffffffffu, 0xffffffffu, PROTO_TCP, 0xffff));
}

void test_format_mac(void)
{
  char buf[MAC_STR_SIZE];
  mac_addr router = {{0x00, 0x22, 0x5f, 0x4d, 0x5e, 0x6f}};
  TEST_ASSERT_EQUAL_PTR(buf, format_mac(router, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("00:22:5f:4d:5e:6f", buf);
  mac_addr all = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
  TEST_ASSERT_EQUAL_STRING("ff:ff:ff:ff:ff:ff", format_mac(all, buf, sizeof buf));
  mac_addr upper = {{0xab, 0xcd, 0xef, 0x0a, 0x0b, 0x0c}};
  TEST_ASSERT_EQUAL_STRING("ab:cd:ef:0a:0b:0c", format_mac(upper, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("00:2", format_mac(router, buf, 5));
  TEST_ASSERT_NULL(format_mac(router, NULL, 18));
  TEST_ASSERT_NULL(format_mac(router, buf, 0));
}

void test_format_ipv4(void)
{
  char buf[IPV4_STR_SIZE];
  TEST_ASSERT_EQUAL_PTR(buf, format_ipv4(0x44550265, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("68.85.2.101", buf);
  TEST_ASSERT_EQUAL_STRING("0.0.0.0", format_ipv4(0, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("255.255.255.255", format_ipv4(0xffffffffu, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("68.8", format_ipv4(0x44550265, buf, 5));
  TEST_ASSERT_NULL(format_ipv4(1, NULL, 16));
  TEST_ASSERT_NULL(format_ipv4(1, buf, 0));
}

void test_format_tcp_flags(void)
{
  char buf[TCP_FLAGS_STR_SIZE];
  TEST_ASSERT_EQUAL_PTR(buf, format_tcp_flags(0, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("none", buf);
  TEST_ASSERT_EQUAL_STRING("F", format_tcp_flags(TCP_FIN, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("S", format_tcp_flags(TCP_SYN, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("R", format_tcp_flags(TCP_RST, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("P", format_tcp_flags(TCP_PSH, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING(".", format_tcp_flags(TCP_ACK, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("U", format_tcp_flags(TCP_URG, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("E", format_tcp_flags(TCP_ECE, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("W", format_tcp_flags(TCP_CWR, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("S.", format_tcp_flags(TCP_SYN | TCP_ACK, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("P.", format_tcp_flags(TCP_PSH | TCP_ACK, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("F.", format_tcp_flags(TCP_FIN | TCP_ACK, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("FSRPUEW.", format_tcp_flags(0xff, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("FS", format_tcp_flags(0xff, buf, 3));
  TEST_ASSERT_EQUAL_STRING("no", format_tcp_flags(0, buf, 3));
  TEST_ASSERT_NULL(format_tcp_flags(TCP_SYN, NULL, 9));
  TEST_ASSERT_NULL(format_tcp_flags(TCP_SYN, buf, 0));
}

/* ======================================================================== */
/* Layer 3: decode_frame                                                    */
/* ======================================================================== */

void test_decode_arp_request_and_reply(void)
{
  assert_decodes(FRAME_ARP_REQUEST, sizeof FRAME_ARP_REQUEST, sizeof FRAME_ARP_REQUEST,
                 "ARP request who-has 68.85.2.1 tell 68.85.2.101");
  assert_decodes(FRAME_ARP_REPLY, sizeof FRAME_ARP_REPLY, sizeof FRAME_ARP_REPLY,
                 "ARP reply 68.85.2.1 is-at 00:22:5f:4d:5e:6f");
}

void test_decode_arp_other_opcode_and_malformed(void)
{
  uint8_t f[sizeof FRAME_ARP_REQUEST];
  memcpy(f, FRAME_ARP_REQUEST, sizeof f);
  put16(f + 20, 3);
  assert_decodes(f, sizeof f, sizeof f, "ARP op=3");
  /* 27 bytes of ARP */
  assert_decodes(FRAME_ARP_REQUEST, sizeof FRAME_ARP_REQUEST - 1, sizeof FRAME_ARP_REQUEST,
                 "malformed ARP");
  memcpy(f, FRAME_ARP_REQUEST, sizeof f);
  f[18] = 8;
  assert_decodes(f, sizeof f, sizeof f, "malformed ARP");
}

void test_decode_malformed_ethernet(void)
{
  assert_decodes(FRAME_TCP_ACK, ETH_HEADER_LEN - 1, 60, "malformed Ethernet");
  assert_decodes(NULL, 0, 0, "malformed Ethernet");
  frame_info info;
  TEST_ASSERT_TRUE(decode_frame(FRAME_TCP_ACK, 0, 0, &info));
  TEST_ASSERT_FALSE(info.has_flow);
}

void test_decode_other_ethertype(void)
{
  uint8_t f[60] = {0};
  put16(f + 12, 0x86dd);
  assert_decodes(f, sizeof f, sizeof f, "Ethernet type=0x86dd");
  put16(f + 12, 0x0026);
  assert_decodes(f, ETH_HEADER_LEN, ETH_HEADER_LEN, "Ethernet type=0x0026");
}

void test_decode_real_tcp_frame(void)
{
  frame_info info;
  TEST_ASSERT_TRUE(decode_frame(FRAME_TCP_ACK, sizeof FRAME_TCP_ACK, sizeof FRAME_TCP_ACK, &info));
  TEST_ASSERT_EQUAL_STRING("TCP 68.85.2.101:49152 > 64.233.169.105:80 [.] seq=3127851021 "
                           "ack=2215467234 win=502 len=0 cksum=ok",
                           info.text);
  TEST_ASSERT_TRUE(info.has_flow);
  TEST_ASSERT_EQUAL_UINT8(PROTO_TCP, info.key.protocol);
  TEST_ASSERT_EQUAL_HEX32(0x44550265, info.key.a_addr);
  TEST_ASSERT_EQUAL_UINT16(49152, info.key.a_port);
  TEST_ASSERT_EQUAL_HEX32(0x40e9a969, info.key.b_addr);
  TEST_ASSERT_EQUAL_UINT16(80, info.key.b_port);
}

void test_decode_padded_frame_has_no_payload(void)
{
  /* A length from the frame would say 6, and the checksum would include
   * the padding. Both come from the headers instead. */
  assert_decodes(FRAME_TCP_PADDED, sizeof FRAME_TCP_PADDED, sizeof FRAME_TCP_PADDED,
                 "TCP 64.233.169.105:80 > 68.85.2.101:49152 [.] seq=2215467234 ack=3127851098 "
                 "win=1050 len=0 cksum=ok");
}

void test_decode_real_udp_frame(void)
{
  frame_info info;
  TEST_ASSERT_TRUE(
    decode_frame(FRAME_DNS_QUERY, sizeof FRAME_DNS_QUERY, sizeof FRAME_DNS_QUERY, &info));
  TEST_ASSERT_EQUAL_STRING("UDP 68.85.2.101:51334 > 68.87.71.226:53 len=32 cksum=ok", info.text);
  TEST_ASSERT_TRUE(info.has_flow);
  TEST_ASSERT_EQUAL_UINT8(PROTO_UDP, info.key.protocol);
  TEST_ASSERT_EQUAL_UINT16(53, info.key.b_port);
}

void test_decode_udp_after_ipv4_options(void)
{
  assert_decodes(FRAME_IP_OPTIONS, sizeof FRAME_IP_OPTIONS, sizeof FRAME_IP_OPTIONS,
                 "UDP 68.85.2.101:41337 > 64.233.169.105:33434 len=32 cksum=ok");
  /* A synthetic one, with 12 bytes of NOP options. */
  uint8_t f[FRAME_MAX];
  size_t n = build_udp(f, 12, 5);
  assert_decodes(f, n, (uint32_t)n, "UDP 10.0.0.1:5000 > 10.0.0.2:6000 len=5 cksum=ok");
}

void test_decode_other_protocol(void)
{
  frame_info info;
  TEST_ASSERT_TRUE(decode_frame(FRAME_ICMP, sizeof FRAME_ICMP, sizeof FRAME_ICMP, &info));
  TEST_ASSERT_EQUAL_STRING("IPv4 68.85.2.1 > 68.85.2.101 proto=1", info.text);
  TEST_ASSERT_FALSE(info.has_flow);
  uint8_t f[FRAME_MAX];
  uint8_t gre[4] = {0};
  size_t n = build_ipv4(f, 47, 0, gre, sizeof gre);
  assert_decodes(f, n, (uint32_t)n, "IPv4 10.0.0.1 > 10.0.0.2 proto=47");
}

void test_decode_bad_header_checksum(void)
{
  uint8_t f[sizeof FRAME_TCP_ACK];
  memcpy(f, FRAME_TCP_ACK, sizeof f);
  f[22] = 63;
  frame_info info;
  TEST_ASSERT_TRUE(decode_frame(f, sizeof f, sizeof f, &info));
  TEST_ASSERT_EQUAL_STRING("IPv4 68.85.2.101 > 64.233.169.105 proto=6 bad-header-cksum",
                           info.text);
  TEST_ASSERT_FALSE(info.has_flow);
}

void test_decode_fragments(void)
{
  uint8_t f[FRAME_MAX];
  size_t n = build_udp(f, 0, 20);
  put16(f + 20, 0x2000); /* more fragments, offset 0: the first fragment */
  fix_ip_checksum(f);
  assert_decodes(f, n, (uint32_t)n, "IPv4 10.0.0.1 > 10.0.0.2 proto=17 fragment");
  put16(f + 20, 3); /* last fragment, offset 3 */
  fix_ip_checksum(f);
  assert_decodes(f, n, (uint32_t)n, "IPv4 10.0.0.1 > 10.0.0.2 proto=17 fragment");
  /* DF alone is not a fragment. */
  put16(f + 20, 0x4000);
  fix_ip_checksum(f);
  assert_decodes(f, n, (uint32_t)n, "UDP 10.0.0.1:5000 > 10.0.0.2:6000 len=20 cksum=ok");
}

void test_decode_bad_checksum_beats_fragment(void)
{
  uint8_t f[FRAME_MAX];
  size_t n = build_udp(f, 0, 20);
  put16(f + 20, 0x2000); /* fragment, checksum left stale */
  assert_decodes(f, n, (uint32_t)n, "IPv4 10.0.0.1 > 10.0.0.2 proto=17 bad-header-cksum");
}

void test_decode_malformed_ipv4_cases(void)
{
  uint8_t f[FRAME_MAX];
  size_t n = build_tcp(f, TCP_SYN, 5, 0);

  /* Fewer than 20 bytes after Ethernet. */
  assert_decodes(f, ETH_HEADER_LEN + 19, (uint32_t)n, "malformed IPv4");

  n = build_tcp(f, TCP_SYN, 5, 0);
  f[14] = 0x65; /* version 6 */
  fix_ip_checksum(f);
  assert_decodes(f, n, (uint32_t)n, "malformed IPv4");

  n = build_tcp(f, TCP_SYN, 5, 0);
  f[14] = 0x44; /* IHL 4 */
  assert_decodes(f, n, (uint32_t)n, "malformed IPv4");

  n = build_tcp(f, TCP_SYN, 5, 0);
  f[14] = 0x4f; /* 60 byte header in 40 bytes */
  assert_decodes(f, n, (uint32_t)n, "malformed IPv4");

  n = build_tcp(f, TCP_SYN, 5, 0);
  put16(f + 16, 16); /* total length under the header */
  fix_ip_checksum(f);
  assert_decodes(f, n, (uint32_t)n, "malformed IPv4");

  n = build_tcp(f, TCP_SYN, 5, 0);
  put16(f + 16, 100); /* total length past the captured bytes, not cut short */
  fix_ip_checksum(f);
  assert_decodes(f, n, (uint32_t)n, "malformed IPv4");
}

void test_decode_snaplen_cut_gives_partial(void)
{
  uint8_t f[FRAME_MAX];
  size_t n = build_tcp(f, TCP_PSH | TCP_ACK, 5, 100);
  /* Keep 80 of 154 bytes: the headers fit, the payload does not. */
  assert_decodes(f, 80, (uint32_t)n,
                 "TCP 10.0.0.1:5000 > 10.0.0.2:80 [P.] seq=1 ack=0 win=1024 len=100 "
                 "cksum=partial");
  /* The same cut without the snaplen excuse is a broken datagram. */
  assert_decodes(f, 80, 80, "malformed IPv4");

  n = build_udp(f, 0, 100);
  assert_decodes(f, 60, (uint32_t)n, "UDP 10.0.0.1:5000 > 10.0.0.2:6000 len=100 cksum=partial");
}

void test_decode_bad_transport_checksums(void)
{
  uint8_t f[FRAME_MAX];
  size_t n = build_tcp(f, TCP_ACK, 5, 10);
  f[n - 1] ^= 0x01; /* one bit of payload */
  assert_decodes(f, n, (uint32_t)n,
                 "TCP 10.0.0.1:5000 > 10.0.0.2:80 [.] seq=1 ack=0 win=1024 len=10 cksum=bad");
  n = build_udp(f, 0, 10);
  f[n - 1] ^= 0x80;
  assert_decodes(f, n, (uint32_t)n, "UDP 10.0.0.1:5000 > 10.0.0.2:6000 len=10 cksum=bad");
}

void test_decode_odd_length_segments_verify(void)
{
  uint8_t f[FRAME_MAX];
  size_t n = build_tcp(f, TCP_PSH | TCP_ACK, 5, 77);
  assert_decodes(f, n, (uint32_t)n,
                 "TCP 10.0.0.1:5000 > 10.0.0.2:80 [P.] seq=1 ack=0 win=1024 len=77 cksum=ok");
  n = build_udp(f, 0, 33);
  assert_decodes(f, n, (uint32_t)n, "UDP 10.0.0.1:5000 > 10.0.0.2:6000 len=33 cksum=ok");
}

void test_decode_udp_without_checksum(void)
{
  uint8_t f[FRAME_MAX];
  size_t n = build_udp(f, 0, 5);
  put16(f + 40, 0);
  assert_decodes(f, n, (uint32_t)n, "UDP 10.0.0.1:5000 > 10.0.0.2:6000 len=5 cksum=none");
  /* No checksum beats partial: there is nothing to check either way. */
  assert_decodes(f, 44, (uint32_t)n, "UDP 10.0.0.1:5000 > 10.0.0.2:6000 len=5 cksum=none");
}

void test_decode_tcp_options_not_counted_as_payload(void)
{
  uint8_t f[FRAME_MAX];
  size_t n = build_tcp(f, TCP_SYN, 8, 0);
  assert_decodes(f, n, (uint32_t)n,
                 "TCP 10.0.0.1:5000 > 10.0.0.2:80 [S] seq=1 ack=0 win=1024 len=0 cksum=ok");
}

void test_decode_tcp_no_flags(void)
{
  uint8_t f[FRAME_MAX];
  size_t n = build_tcp(f, 0, 5, 0);
  assert_decodes(f, n, (uint32_t)n,
                 "TCP 10.0.0.1:5000 > 10.0.0.2:80 [none] seq=1 ack=0 win=1024 len=0 cksum=ok");
}

void test_decode_malformed_tcp_cases(void)
{
  uint8_t f[FRAME_MAX];
  /* 19 bytes of TCP according to the IPv4 total length. */
  size_t n = build_tcp(f, TCP_SYN, 5, 0);
  put16(f + 16, 39);
  fix_ip_checksum(f);
  assert_decodes(f, n, (uint32_t)n, "malformed TCP");

  /* Same, but the frame is padded: padding is not TCP header. */
  uint8_t padded[60] = {0};
  memcpy(padded, f, n);
  assert_decodes(padded, sizeof padded, sizeof padded, "malformed TCP");

  /* Data offset under 5. */
  n = build_tcp(f, TCP_SYN, 5, 0);
  f[46] = 0x40;
  assert_decodes(f, n, (uint32_t)n, "malformed TCP");

  /* Data offset 8 (32 bytes) in a 20 byte segment. */
  n = build_tcp(f, TCP_SYN, 5, 0);
  f[46] = 0x80;
  assert_decodes(f, n, (uint32_t)n, "malformed TCP");

  /* Cut short by the snaplen inside the TCP header. */
  n = build_tcp(f, TCP_SYN, 5, 100);
  assert_decodes(f, 50, (uint32_t)n, "malformed TCP");
}

void test_decode_malformed_udp_cases(void)
{
  uint8_t f[FRAME_MAX];
  /* 7 bytes of UDP according to the IPv4 total length. */
  size_t n = build_udp(f, 0, 0);
  put16(f + 16, 27);
  fix_ip_checksum(f);
  assert_decodes(f, n, (uint32_t)n, "malformed UDP");

  /* UDP length under 8. */
  n = build_udp(f, 0, 4);
  put16(f + 38, 7);
  assert_decodes(f, n, (uint32_t)n, "malformed UDP");

  /* UDP length longer than the IPv4 payload. */
  n = build_udp(f, 0, 4);
  put16(f + 38, 13);
  assert_decodes(f, n, (uint32_t)n, "malformed UDP");
}

void test_decode_frame_null_arguments(void)
{
  frame_info info;
  TEST_ASSERT_FALSE(decode_frame(FRAME_TCP_ACK, sizeof FRAME_TCP_ACK, 54, NULL));
  TEST_ASSERT_FALSE(decode_frame(NULL, 54, 54, &info));
}

/* ======================================================================== */
/* Layer 3: the flow table and formatting                                   */
/* ======================================================================== */

void test_flow_table_both_directions(void)
{
  flow_table *t = flow_table_create();
  TEST_ASSERT_NOT_NULL(t);
  TEST_ASSERT_EQUAL_size_t(0, flow_table_count(t));

  flow_key ab = {PROTO_TCP, IP_A, 5000, IP_B, 80};
  flow_key ba = {PROTO_TCP, IP_B, 80, IP_A, 5000};
  TEST_ASSERT_TRUE(flow_table_add(t, &ab, 60));
  TEST_ASSERT_TRUE(flow_table_add(t, &ba, 1514));
  TEST_ASSERT_TRUE(flow_table_add(t, &ab, 54));
  TEST_ASSERT_EQUAL_size_t(1, flow_table_count(t));

  const flow *f = flow_table_get(t, 0);
  TEST_ASSERT_NOT_NULL(f);
  TEST_ASSERT_EQUAL_UINT64(3, f->packets);
  TEST_ASSERT_EQUAL_UINT64(1628, f->bytes);
  /* Side a is the source of the first packet seen. */
  TEST_ASSERT_EQUAL_HEX32(IP_A, f->key.a_addr);
  TEST_ASSERT_EQUAL_UINT16(5000, f->key.a_port);
  flow_table_destroy(t);
}

void test_flow_table_distinct_flows_in_first_seen_order(void)
{
  flow_table *t = flow_table_create();
  flow_key tcp = {PROTO_TCP, IP_A, 5000, IP_B, 80};
  flow_key udp = {PROTO_UDP, IP_A, 5000, IP_B, 80}; /* same endpoints, other protocol */
  flow_key port = {PROTO_TCP, IP_A, 5001, IP_B, 80};
  flow_key half = {PROTO_TCP, IP_B, 5000, IP_A, 80}; /* addresses swapped, ports not */
  TEST_ASSERT_TRUE(flow_table_add(t, &udp, 1));
  TEST_ASSERT_TRUE(flow_table_add(t, &tcp, 2));
  TEST_ASSERT_TRUE(flow_table_add(t, &port, 3));
  TEST_ASSERT_TRUE(flow_table_add(t, &half, 4));
  TEST_ASSERT_EQUAL_size_t(4, flow_table_count(t));
  TEST_ASSERT_EQUAL_UINT8(PROTO_UDP, flow_table_get(t, 0)->key.protocol);
  TEST_ASSERT_EQUAL_UINT64(2, flow_table_get(t, 1)->bytes);
  TEST_ASSERT_EQUAL_UINT16(5001, flow_table_get(t, 2)->key.a_port);
  TEST_ASSERT_EQUAL_HEX32(IP_B, flow_table_get(t, 3)->key.a_addr);
  flow_table_destroy(t);
}

void test_flow_table_grows(void)
{
  flow_table *t = flow_table_create();
  for (uint16_t i = 0; i < 100; i++) {
    flow_key k = {PROTO_UDP, IP_A, (uint16_t)(1000 + i), IP_B, 53};
    TEST_ASSERT_TRUE(flow_table_add(t, &k, i));
  }
  for (uint16_t i = 0; i < 100; i++) {
    flow_key back = {PROTO_UDP, IP_B, 53, IP_A, (uint16_t)(1000 + i)};
    TEST_ASSERT_TRUE(flow_table_add(t, &back, 1));
  }
  TEST_ASSERT_EQUAL_size_t(100, flow_table_count(t));
  for (size_t i = 0; i < 100; i++) {
    const flow *f = flow_table_get(t, i);
    TEST_ASSERT_EQUAL_UINT16(1000 + i, f->key.a_port);
    TEST_ASSERT_EQUAL_UINT64(2, f->packets);
    TEST_ASSERT_EQUAL_UINT64(i + 1, f->bytes);
  }
  flow_table_destroy(t);
}

void test_flow_table_null_and_range(void)
{
  flow_key k = {PROTO_TCP, IP_A, 1, IP_B, 2};
  flow_table *t = flow_table_create();
  TEST_ASSERT_FALSE(flow_table_add(NULL, &k, 1));
  TEST_ASSERT_FALSE(flow_table_add(t, NULL, 1));
  TEST_ASSERT_EQUAL_size_t(0, flow_table_count(NULL));
  TEST_ASSERT_NULL(flow_table_get(NULL, 0));
  TEST_ASSERT_NULL(flow_table_get(t, 0));
  TEST_ASSERT_TRUE(flow_table_add(t, &k, 1));
  TEST_ASSERT_NOT_NULL(flow_table_get(t, 0));
  TEST_ASSERT_NULL(flow_table_get(t, 1));
  flow_table_destroy(t);
  flow_table_destroy(NULL);
}

void test_flow_table_bytes_do_not_overflow_32_bits(void)
{
  flow_table *t = flow_table_create();
  flow_key k = {PROTO_TCP, IP_A, 1, IP_B, 2};
  TEST_ASSERT_TRUE(flow_table_add(t, &k, 0xffffffffu));
  TEST_ASSERT_TRUE(flow_table_add(t, &k, 0xffffffffu));
  TEST_ASSERT_EQUAL_UINT64(0x1fffffffeull, flow_table_get(t, 0)->bytes);
  flow_table_destroy(t);
}

void test_format_flow(void)
{
  char buf[FRAME_TEXT_SIZE];
  flow f = {{PROTO_TCP, 0x44550265, 49152, 0x40e9a969, 80}, 13, 4403};
  TEST_ASSERT_EQUAL_PTR(buf, format_flow(&f, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("TCP 68.85.2.101:49152 <> 64.233.169.105:80 packets=13 bytes=4403", buf);
  f.key.protocol = PROTO_UDP;
  TEST_ASSERT_EQUAL_STRING("UDP 68.85.2.101:49152 <> 64.233.169.105:80 packets=13 bytes=4403",
                           format_flow(&f, buf, sizeof buf));
  f.key.protocol = 1;
  TEST_ASSERT_EQUAL_STRING("IP 68.85.2.101:49152 <> 64.233.169.105:80 packets=13 bytes=4403",
                           format_flow(&f, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("IP 6", format_flow(&f, buf, 5));
  TEST_ASSERT_NULL(format_flow(NULL, buf, sizeof buf));
  TEST_ASSERT_NULL(format_flow(&f, NULL, sizeof buf));
  TEST_ASSERT_NULL(format_flow(&f, buf, 0));
}

void test_format_elapsed(void)
{
  char buf[32];
  TEST_ASSERT_EQUAL_PTR(buf, format_elapsed(1000, 5, 1000, 5, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("0.000000", buf);
  TEST_ASSERT_EQUAL_STRING("0.068790", format_elapsed(1000, 68790, 1000, 0, buf, sizeof buf));
  /* Across a second boundary: the later microseconds are smaller. */
  TEST_ASSERT_EQUAL_STRING("1.204511", format_elapsed(1001, 225061, 1000, 20550, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("0.000500", format_elapsed(1001, 200, 1000, 999700, buf, sizeof buf));
  /* A timestamp before the first one. */
  TEST_ASSERT_EQUAL_STRING("-0.000500", format_elapsed(1000, 999700, 1001, 200, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("-2.000000", format_elapsed(1, 0, 3, 0, buf, sizeof buf));
  /* The extremes of the fields still fit and stay exact. */
  TEST_ASSERT_EQUAL_STRING("4294967295.000000", format_elapsed(0xffffffffu, 0, 0, 0, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("4294.967295", format_elapsed(0, 0xffffffffu, 0, 0, buf, sizeof buf));
  TEST_ASSERT_EQUAL_STRING("0.0", format_elapsed(0, 0, 0, 0, buf, 4));
  TEST_ASSERT_NULL(format_elapsed(0, 0, 0, 0, NULL, 32));
  TEST_ASSERT_NULL(format_elapsed(0, 0, 0, 0, buf, 0));
}

/* ======================================================================== */
/* Layer 3: report_capture                                                  */
/* ======================================================================== */

void test_report_small_capture_both_byte_orders(void)
{
  uint8_t buf[512];
  char *out;
  char *err;
  size_t n = build_small_capture(buf, false);
  TEST_ASSERT_EQUAL_INT(EXIT_CAPTURE_OK, run_report(buf, n, false, &out, &err));
  TEST_ASSERT_EQUAL_STRING(SMALL_CAPTURE_REPORT, out);
  TEST_ASSERT_EQUAL_STRING("", err);
  free(out);
  free(err);

  n = build_small_capture(buf, true);
  TEST_ASSERT_EQUAL_INT(EXIT_CAPTURE_OK, run_report(buf, n, false, &out, &err));
  TEST_ASSERT_EQUAL_STRING(SMALL_CAPTURE_REPORT, out);
  free(out);
  free(err);
}

void test_report_summary_only(void)
{
  uint8_t buf[512];
  char *out;
  char *err;
  size_t n = build_small_capture(buf, false);
  TEST_ASSERT_EQUAL_INT(EXIT_CAPTURE_OK, run_report(buf, n, true, &out, &err));
  TEST_ASSERT_EQUAL_STRING("TCP 68.85.2.101:49152 <> 64.233.169.105:80 packets=2 bytes=114\n", out);
  free(out);
  free(err);
}

void test_report_counts_original_lengths(void)
{
  uint8_t buf[512];
  uint8_t f[FRAME_MAX];
  size_t len = build_udp(f, 0, 100);
  size_t n = build_pcap_header(buf, false, PCAP_MAGIC, 2, 1);
  n = add_record(buf, n, false, 7, 0, f, 60, (uint32_t)len); /* snaplen 60 */
  n = add_record(buf, n, false, 7, 10, FRAME_ARP_REQUEST, ETH_HEADER_LEN - 2, 42); /* broken */
  char *out;
  char *err;
  TEST_ASSERT_EQUAL_INT(EXIT_CAPTURE_OK, run_report(buf, n, false, &out, &err));
  TEST_ASSERT_EQUAL_STRING("1 0.000000 UDP 10.0.0.1:5000 > 10.0.0.2:6000 len=100 cksum=partial\n"
                           "2 0.000010 malformed Ethernet\n"
                           "\n"
                           "UDP 10.0.0.1:5000 <> 10.0.0.2:6000 packets=1 bytes=142\n",
                           out);
  free(out);
  free(err);
}

void test_report_header_only_capture(void)
{
  uint8_t buf[PCAP_FILE_HEADER_LEN];
  build_pcap_header(buf, true, PCAP_MAGIC, 2, 1);
  char *out;
  char *err;
  TEST_ASSERT_EQUAL_INT(EXIT_CAPTURE_OK, run_report(buf, sizeof buf, false, &out, &err));
  TEST_ASSERT_EQUAL_STRING("\n", out);
  free(out);
  free(err);
  TEST_ASSERT_EQUAL_INT(EXIT_CAPTURE_OK, run_report(buf, sizeof buf, true, &out, &err));
  TEST_ASSERT_EQUAL_STRING("", out);
  free(out);
  free(err);
}

void test_report_truncated_capture(void)
{
  uint8_t buf[512];
  size_t n = build_small_capture(buf, false);
  char *out;
  char *err;
  /* Cut the file in the middle of the third frame. */
  TEST_ASSERT_EQUAL_INT(EXIT_BAD_FILE, run_report(buf, n - 20, false, &out, &err));
  TEST_ASSERT_EQUAL_STRING("1 0.000000 ARP request who-has 68.85.2.1 tell 68.85.2.101\n"
                           "2 0.001500 TCP 68.85.2.101:49152 > 64.233.169.105:80 [.] "
                           "seq=3127851021 ack=2215467234 win=502 len=0 cksum=ok\n",
                           out);
  TEST_ASSERT_EQUAL_STRING("myapp: test.pcap: frame 3: record data runs past the end of the file\n",
                           err);
  free(out);
  free(err);

  /* Cut inside the second record header, with -s: nothing on stdout. */
  size_t cut = PCAP_FILE_HEADER_LEN + PCAP_RECORD_HEADER_LEN + sizeof FRAME_ARP_REQUEST + 3;
  TEST_ASSERT_EQUAL_INT(EXIT_BAD_FILE, run_report(buf, cut, true, &out, &err));
  TEST_ASSERT_EQUAL_STRING("", out);
  TEST_ASSERT_EQUAL_STRING(
    "myapp: test.pcap: frame 2: record header runs past the end of the file\n", err);
  free(out);
  free(err);
}

void test_report_rejected_file_headers(void)
{
  uint8_t buf[PCAP_FILE_HEADER_LEN] = {0};
  char *out;
  char *err;
  TEST_ASSERT_EQUAL_INT(EXIT_BAD_FILE, run_report(buf, 7, false, &out, &err));
  TEST_ASSERT_EQUAL_STRING("", out);
  TEST_ASSERT_NOT_NULL(strstr(err, "shorter than the 24 byte"));
  free(out);
  free(err);

  memcpy(buf, "\x0a\x0d\x0d\x0a", 4);
  TEST_ASSERT_EQUAL_INT(EXIT_BAD_FILE, run_report(buf, sizeof buf, false, &out, &err));
  TEST_ASSERT_NOT_NULL(strstr(err, "pcapng"));
  free(out);
  free(err);

  build_pcap_header(buf, false, PCAP_MAGIC, 2, 113);
  TEST_ASSERT_EQUAL_INT(EXIT_BAD_FILE, run_report(buf, sizeof buf, false, &out, &err));
  TEST_ASSERT_NOT_NULL(strstr(err, "link type"));
  free(out);
  free(err);
}

void test_report_caplen_over_origlen(void)
{
  uint8_t buf[256];
  size_t n = build_pcap_header(buf, false, PCAP_MAGIC, 2, 1);
  n = add_record(buf, n, false, 1, 0, FRAME_TCP_ACK, sizeof FRAME_TCP_ACK, sizeof FRAME_TCP_ACK);
  n = add_record(buf, n, false, 1, 1, FRAME_TCP_ACK, sizeof FRAME_TCP_ACK, 40);
  char *out;
  char *err;
  TEST_ASSERT_EQUAL_INT(EXIT_BAD_FILE, run_report(buf, n, false, &out, &err));
  TEST_ASSERT_NOT_NULL(strstr(out, "1 0.000000 TCP"));
  TEST_ASSERT_NULL(strstr(out, "<>"));
  TEST_ASSERT_NOT_NULL(strstr(err, "frame 2: record captured length"));
  free(out);
  free(err);
}

void test_report_null_arguments(void)
{
  uint8_t buf[512];
  size_t n = build_small_capture(buf, false);
  FILE *out = tmpfile();
  FILE *err = tmpfile();
  TEST_ASSERT_EQUAL_INT(EXIT_BAD_FILE, report_capture(buf, n, "x", false, NULL, err));
  TEST_ASSERT_EQUAL_INT(EXIT_BAD_FILE, report_capture(buf, n, "x", false, out, NULL));
  /* A NULL name still gets a readable message. */
  TEST_ASSERT_EQUAL_INT(EXIT_BAD_FILE, report_capture(NULL, n, NULL, false, out, err));
  char *out_text = drain(out);
  char *err_text = drain(err);
  TEST_ASSERT_EQUAL_STRING("", out_text);
  TEST_ASSERT_EQUAL_STRING("myapp: capture: missing argument\n", err_text);
  free(out_text);
  free(err_text);
}

/* ======================================================================== */
/* The real captures, from the repository root                              */
/* ======================================================================== */

void test_capture_malformed_matches_expected_output(void)
{
  size_t len;
  size_t want_len;
  uint8_t *data = slurp("malformed.pcap", &len);
  uint8_t *want = slurp("malformed.txt", &want_len);
  char *out;
  char *err;
  TEST_ASSERT_EQUAL_INT(EXIT_CAPTURE_OK, run_report(data, len, false, &out, &err));
  TEST_ASSERT_EQUAL_STRING((const char *)want, out);
  TEST_ASSERT_EQUAL_STRING("", err);
  free(out);
  free(err);
  free(want);
  free(data);
}

void test_capture_byte_orders_give_identical_reports(void)
{
  size_t le_len;
  size_t be_len;
  uint8_t *le = slurp("day-in-the-life.pcap", &le_len);
  uint8_t *be = slurp("day-in-the-life-be.pcap", &be_len);
  char *le_out;
  char *be_out;
  char *err;
  TEST_ASSERT_EQUAL_INT(EXIT_CAPTURE_OK, run_report(le, le_len, false, &le_out, &err));
  free(err);
  TEST_ASSERT_EQUAL_INT(EXIT_CAPTURE_OK, run_report(be, be_len, false, &be_out, &err));
  free(err);
  TEST_ASSERT_EQUAL_STRING(le_out, be_out);
  /* The handout's example lines. */
  TEST_ASSERT_NOT_NULL(strstr(le_out, "7 0.021101 ARP reply 68.85.2.1 is-at 00:22:5f:4d:5e:6f\n"));
  TEST_ASSERT_NOT_NULL(strstr(le_out, "\n13 0.068790 TCP 68.85.2.101:49152 > 64.233.169.105:80 [P.] "
                                      "seq=3127851021 ack=2215467234 win=502 len=77 cksum=ok\n"));
  TEST_ASSERT_NOT_NULL(
    strstr(le_out, "\nTCP 68.85.2.101:49152 <> 64.233.169.105:80 packets=13 bytes=4403\n"));
  free(le_out);
  free(be_out);
  free(le);
  free(be);
}

void test_capture_truncated_prints_twelve_frames(void)
{
  size_t len;
  uint8_t *data = slurp("truncated.pcap", &len);
  char *out;
  char *err;
  TEST_ASSERT_EQUAL_INT(EXIT_BAD_FILE, run_report(data, len, false, &out, &err));
  size_t lines = 0;
  for (const char *c = out; *c != '\0'; c++) {
    lines += *c == '\n';
  }
  TEST_ASSERT_EQUAL_size_t(12, lines);
  TEST_ASSERT_NOT_NULL(strstr(err, "frame 13"));
  TEST_ASSERT_NULL(strstr(out, "<>"));
  free(out);
  free(err);
  free(data);
}

void test_capture_snaplen_marks_partial(void)
{
  size_t len;
  uint8_t *data = slurp("snaplen.pcap", &len);
  char *out;
  char *err;
  TEST_ASSERT_EQUAL_INT(EXIT_CAPTURE_OK, run_report(data, len, false, &out, &err));
  TEST_ASSERT_NOT_NULL(strstr(out, "\n13 0.068790 TCP 68.85.2.101:49152 > 64.233.169.105:80 [P.] "
                                   "seq=3127851021 ack=2215467234 win=502 len=77 cksum=partial\n"));
  /* Same flows and bytes as the full capture: bytes are original lengths. */
  TEST_ASSERT_NOT_NULL(
    strstr(out, "\nTCP 68.85.2.101:49152 <> 64.233.169.105:80 packets=13 bytes=4403\n"));
  free(out);
  free(err);
  free(data);
}

int main(void)
{
  UNITY_BEGIN();

  RUN_TEST(test_pcap_open_little_endian);
  RUN_TEST(test_pcap_open_big_endian);
  RUN_TEST(test_pcap_open_null_arguments);
  RUN_TEST(test_pcap_open_cut_inside_file_header);
  RUN_TEST(test_pcap_open_pcapng);
  RUN_TEST(test_pcap_open_bad_magic);
  RUN_TEST(test_pcap_open_major_version);
  RUN_TEST(test_pcap_open_link_type);
  RUN_TEST(test_pcap_next_little_endian_records);
  RUN_TEST(test_pcap_next_big_endian_records);
  RUN_TEST(test_pcap_next_header_only_file);
  RUN_TEST(test_pcap_next_cut_inside_record_header);
  RUN_TEST(test_pcap_next_cut_inside_record_data);
  RUN_TEST(test_pcap_next_caplen_over_origlen);
  RUN_TEST(test_pcap_next_huge_caplen_does_not_wrap);
  RUN_TEST(test_pcap_next_empty_record);
  RUN_TEST(test_pcap_next_null_arguments);
  RUN_TEST(test_pcap_strerror);

  RUN_TEST(test_eth_parse_arp_request);
  RUN_TEST(test_eth_parse_padded_frame_keeps_padding);
  RUN_TEST(test_eth_parse_short);
  RUN_TEST(test_eth_parse_null_arguments);
  RUN_TEST(test_arp_parse_request);
  RUN_TEST(test_arp_parse_reply_ignores_padding);
  RUN_TEST(test_arp_parse_short);
  RUN_TEST(test_arp_parse_not_ipv4_over_ethernet);
  RUN_TEST(test_arp_parse_null_arguments);
  RUN_TEST(test_ipv4_parse_real_header);
  RUN_TEST(test_ipv4_parse_ignores_ethernet_padding);
  RUN_TEST(test_ipv4_parse_with_options);
  RUN_TEST(test_ipv4_parse_short);
  RUN_TEST(test_ipv4_parse_version_not_4);
  RUN_TEST(test_ipv4_parse_ihl_under_5);
  RUN_TEST(test_ipv4_parse_ihl_past_captured_bytes);
  RUN_TEST(test_ipv4_parse_total_length_shorter_than_header);
  RUN_TEST(test_ipv4_parse_total_length_past_captured_bytes);
  RUN_TEST(test_ipv4_parse_reports_bad_header_checksum);
  RUN_TEST(test_ipv4_parse_fragment_fields);
  RUN_TEST(test_ipv4_parse_null_arguments);
  RUN_TEST(test_tcp_parse_real_header);
  RUN_TEST(test_tcp_parse_options);
  RUN_TEST(test_tcp_parse_short_and_illegal);
  RUN_TEST(test_tcp_parse_null_arguments);
  RUN_TEST(test_udp_parse_real_header);
  RUN_TEST(test_udp_parse_short_and_illegal);
  RUN_TEST(test_udp_parse_length_past_captured_bytes_is_legal);
  RUN_TEST(test_udp_parse_null_arguments);
  RUN_TEST(test_inet_checksum_rfc1071_example);
  RUN_TEST(test_inet_checksum_odd_length);
  RUN_TEST(test_inet_checksum_carries_more_than_once);
  RUN_TEST(test_inet_checksum_verifies_real_headers);
  RUN_TEST(test_inet_checksum_null_and_empty);
  RUN_TEST(test_pseudo_header_sum_verifies_real_segments);
  RUN_TEST(test_pseudo_header_sum_value);
  RUN_TEST(test_format_mac);
  RUN_TEST(test_format_ipv4);
  RUN_TEST(test_format_tcp_flags);

  RUN_TEST(test_decode_arp_request_and_reply);
  RUN_TEST(test_decode_arp_other_opcode_and_malformed);
  RUN_TEST(test_decode_malformed_ethernet);
  RUN_TEST(test_decode_other_ethertype);
  RUN_TEST(test_decode_real_tcp_frame);
  RUN_TEST(test_decode_padded_frame_has_no_payload);
  RUN_TEST(test_decode_real_udp_frame);
  RUN_TEST(test_decode_udp_after_ipv4_options);
  RUN_TEST(test_decode_other_protocol);
  RUN_TEST(test_decode_bad_header_checksum);
  RUN_TEST(test_decode_fragments);
  RUN_TEST(test_decode_bad_checksum_beats_fragment);
  RUN_TEST(test_decode_malformed_ipv4_cases);
  RUN_TEST(test_decode_snaplen_cut_gives_partial);
  RUN_TEST(test_decode_bad_transport_checksums);
  RUN_TEST(test_decode_odd_length_segments_verify);
  RUN_TEST(test_decode_udp_without_checksum);
  RUN_TEST(test_decode_tcp_options_not_counted_as_payload);
  RUN_TEST(test_decode_tcp_no_flags);
  RUN_TEST(test_decode_malformed_tcp_cases);
  RUN_TEST(test_decode_malformed_udp_cases);
  RUN_TEST(test_decode_frame_null_arguments);

  RUN_TEST(test_flow_table_both_directions);
  RUN_TEST(test_flow_table_distinct_flows_in_first_seen_order);
  RUN_TEST(test_flow_table_grows);
  RUN_TEST(test_flow_table_null_and_range);
  RUN_TEST(test_flow_table_bytes_do_not_overflow_32_bits);
  RUN_TEST(test_format_flow);
  RUN_TEST(test_format_elapsed);

  RUN_TEST(test_report_small_capture_both_byte_orders);
  RUN_TEST(test_report_summary_only);
  RUN_TEST(test_report_counts_original_lengths);
  RUN_TEST(test_report_header_only_capture);
  RUN_TEST(test_report_truncated_capture);
  RUN_TEST(test_report_rejected_file_headers);
  RUN_TEST(test_report_caplen_over_origlen);
  RUN_TEST(test_report_null_arguments);

  RUN_TEST(test_capture_malformed_matches_expected_output);
  RUN_TEST(test_capture_byte_orders_give_identical_reports);
  RUN_TEST(test_capture_truncated_prints_twelve_frames);
  RUN_TEST(test_capture_snaplen_marks_partial);

  return UNITY_END();
}
