/**
 * @file pcap.c
 * @brief Layer 1: the pcap reader. Works on bytes already in memory and
 * never touches a file.
 */
#include "lab.h"

/*
 * Reads 16 and 32-bit values in the byte order of the file's writer. Each
 * byte is widened to the result type before it is shifted, because a
 * uint8_t promotes to int and (int)0xd4 << 24 overflows an int.
 */
static uint16_t get16(const uint8_t *p, bool big_endian)
{
  if (big_endian) {
    return (uint16_t)((unsigned)p[0] << 8 | (unsigned)p[1]);
  }
  return (uint16_t)((unsigned)p[1] << 8 | (unsigned)p[0]);
}

static uint32_t get32(const uint8_t *p, bool big_endian)
{
  if (big_endian) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3];
  }
  return (uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | (uint32_t)p[0];
}

pcap_status pcap_open(pcap_reader *r, const uint8_t *data, size_t len)
{
  if (r == NULL || (data == NULL && len > 0)) {
    return PCAP_ERR_ARGS;
  }
  if (len < PCAP_FILE_HEADER_LEN) {
    return PCAP_ERR_SHORT;
  }

  bool big_endian;
  if (get32(data, false) == PCAP_MAGIC) {
    big_endian = false;
  } else if (get32(data, true) == PCAP_MAGIC) {
    big_endian = true;
  } else if (get32(data, true) == PCAPNG_MAGIC) {
    /* The pcapng block type reads the same in both byte orders. */
    return PCAP_ERR_PCAPNG;
  } else {
    return PCAP_ERR_MAGIC;
  }

  uint16_t major = get16(data + 4, big_endian);
  if (major != PCAP_VERSION_MAJOR) {
    return PCAP_ERR_VERSION;
  }
  uint32_t linktype = get32(data + 20, big_endian);
  if (linktype != PCAP_LINKTYPE_ETHERNET) {
    return PCAP_ERR_LINKTYPE;
  }

  r->data = data;
  r->len = len;
  r->pos = PCAP_FILE_HEADER_LEN;
  r->big_endian = big_endian;
  r->version_major = major;
  r->version_minor = get16(data + 6, big_endian);
  r->snaplen = get32(data + 16, big_endian);
  r->linktype = linktype;
  return PCAP_OK;
}

pcap_status pcap_next(pcap_reader *r, pcap_record *rec)
{
  if (r == NULL || rec == NULL) {
    return PCAP_ERR_ARGS;
  }
  /* pos never passes len, so this subtraction cannot wrap. */
  size_t left = r->len - r->pos;
  if (left == 0) {
    return PCAP_END;
  }
  if (left < PCAP_RECORD_HEADER_LEN) {
    return PCAP_ERR_RECORD_HEADER;
  }

  const uint8_t *h = r->data + r->pos;
  uint32_t caplen = get32(h + 8, r->big_endian);
  uint32_t origlen = get32(h + 12, r->big_endian);
  if (caplen > origlen) {
    return PCAP_ERR_CAPLEN;
  }
  /* Compare against what is left rather than adding to pos, so a huge
   * caplen from a hostile file cannot overflow the arithmetic. */
  if (caplen > left - PCAP_RECORD_HEADER_LEN) {
    return PCAP_ERR_RECORD_DATA;
  }

  rec->ts_sec = get32(h, r->big_endian);
  rec->ts_usec = get32(h + 4, r->big_endian);
  rec->caplen = caplen;
  rec->origlen = origlen;
  rec->data = h + PCAP_RECORD_HEADER_LEN;
  r->pos += PCAP_RECORD_HEADER_LEN + (size_t)caplen;
  return PCAP_OK;
}

const char *pcap_strerror(pcap_status s)
{
  switch (s) {
  case PCAP_OK:
    return "no error";
  case PCAP_END:
    return "end of capture";
  case PCAP_ERR_ARGS:
    return "missing argument";
  case PCAP_ERR_SHORT:
    return "file is shorter than the 24 byte pcap file header";
  case PCAP_ERR_PCAPNG:
    return "file is pcapng, not pcap (save it as Wireshark/tcpdump - pcap)";
  case PCAP_ERR_MAGIC:
    return "not a pcap file (bad magic number)";
  case PCAP_ERR_VERSION:
    return "unsupported pcap major version (expected 2)";
  case PCAP_ERR_LINKTYPE:
    return "unsupported link type (expected 1, Ethernet)";
  case PCAP_ERR_RECORD_HEADER:
    return "record header runs past the end of the file";
  case PCAP_ERR_RECORD_DATA:
    return "record data runs past the end of the file";
  case PCAP_ERR_CAPLEN:
    return "record captured length is larger than its original length";
  }
  return "unknown error";
}
