/**
 * @file main.c
 * @brief Reads a capture into memory, parses the command line, and calls
 * report_capture(). Nothing else happens here.
 */
#include "lab.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef TEST
#define main main_exclude
#endif

/** Bytes to allocate for the first read; the buffer doubles after that. */
#define READ_CHUNK 65536

static void usage(FILE *to)
{
  fprintf(to, "Usage: myapp [-s] <capture>\n"
              "\n"
              "  -s         print only the flow summary\n"
              "  <capture>  a pcap file of Ethernet frames\n");
}

/*
 * Reads a whole file into a malloc'd buffer. Reads until end of file rather
 * than trusting a size from fseek/ftell, so it works on pipes too. Returns
 * false with errno set when the file cannot be opened or read.
 */
static bool read_file(const char *path, uint8_t **data, size_t *len)
{
  FILE *f = fopen(path, "rb");
  if (f == NULL) {
    return false;
  }
  uint8_t *buf = NULL;
  size_t cap = 0;
  size_t used = 0;
  for (;;) {
    if (used == cap) {
      size_t grown_cap = cap == 0 ? READ_CHUNK : cap * 2;
      uint8_t *grown = realloc(buf, grown_cap);
      if (grown == NULL) {
        free(buf);
        fclose(f);
        errno = ENOMEM;
        return false;
      }
      buf = grown;
      cap = grown_cap;
    }
    size_t got = fread(buf + used, 1, cap - used, f);
    used += got;
    if (got == 0) {
      break;
    }
  }
  int failed = ferror(f);
  int saved_errno = errno;
  fclose(f);
  if (failed) {
    free(buf);
    errno = saved_errno != 0 ? saved_errno : EIO;
    return false;
  }
  *data = buf;
  *len = used;
  return true;
}

int main(int argc, char *argv[])
{
  if (argc <= 1) {
    usage(stdout);
    return EXIT_CAPTURE_OK;
  }

  bool summary_only = false;
  int opt;
  while ((opt = getopt(argc, argv, "s")) != -1) {
    if (opt == 's') {
      summary_only = true;
    } else {
      usage(stderr);
      return EXIT_BAD_USAGE;
    }
  }
  if (argc - optind != 1) {
    usage(stderr);
    return EXIT_BAD_USAGE;
  }

  const char *path = argv[optind];
  uint8_t *data = NULL;
  size_t len = 0;
  errno = 0;
  if (!read_file(path, &data, &len)) {
    fprintf(stderr, "myapp: %s: %s\n", path, strerror(errno));
    return EXIT_BAD_FILE;
  }
  int status = report_capture(data, len, path, summary_only, stdout, stderr);
  free(data);
  return status;
}
