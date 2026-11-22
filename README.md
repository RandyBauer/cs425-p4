# Project 4 - Packet Capture and Analysis

- Name: Randy Bauer
- Email: randybauer@u.boisestate.edu
- Class: CS425-001

A pcap decoder in C. For every frame in a capture, it walks down the stack (Ethernet, then ARP or
IPv4, then TCP or UDP) and prints one line. Then it prints a summary of every TCP and UDP flow.
The main capture is the textbook's "day in the life of a web page request" (Kurose 9th edition,
section 6.7).

## Building and running

```bash
make all && make check
./build/release/myapp day-in-the-life.pcap
./build/release/myapp -s day-in-the-life.pcap        # flow summary only
./build/release/myapp malformed.pcap | diff - malformed.txt
```

The five captures and `malformed.txt` from `p4-captures.zip` are in the repository root.

| Exit code | Meaning |
| --- | --- |
| 0 | The whole capture was read, or there were no arguments at all (prints usage). A broken frame is reported on its line and is not an error |
| 1 | Bad command line: an unknown option, no capture, or more than one |
| 2 | The file cannot be read, or is not a well formed pcap file |

On exit 2, the program prints every frame before the problem. Then it writes a message on stderr
that names the problem and the frame, for example
`myapp: truncated.pcap: frame 13: record data runs past the end of the file`, and it skips the
summary. A pcapng file gets a message that says it is pcapng.

## Design

The program has three layers. Each one is a section of `src/lab.h` and has its own source file.

| Layer | File | Job | Functions |
| --- | --- | --- | --- |
| 1. The pcap reader | `src/pcap.c` | Opens a capture that is already in memory, checks the file header, and hands out one record at a time | `pcap_open`, `pcap_next`, `pcap_strerror` |
| 2. The header parsers | `src/headers.c` | Turns bytes into structs, verifies checksums, formats addresses and flags. No I/O and no allocation | `eth_parse`, `arp_parse`, `ipv4_parse`, `tcp_parse`, `udp_parse`, `inet_checksum`, `pseudo_header_sum`, `format_mac`, `format_ipv4`, `format_tcp_flags` |
| 3. Decoding and reporting | `src/decode.c` | Walks one frame down the stack, keeps the flow table, and runs a whole capture into a `FILE *` | `decode_frame`, `flow_table_create`, `flow_table_destroy`, `flow_table_add`, `flow_table_count`, `flow_table_get`, `format_flow`, `format_elapsed`, `report_capture` |
| The program | `src/main.c` | Reads the file into memory, parses the command line with `getopt`, and calls `report_capture` | none public |

Layers 1 and 2 don't use each other. Layer 3 uses both. Nothing below `main.c` opens a file.
`report_capture` writes to the `FILE *` pointers it is given, so a test can point it at
`tmpfile()` and read back what it wrote.

### Never read a byte you have not checked

Every function that reads bytes takes a pointer and a length. A parser checks the length before it
reads each field. When the header doesn't fit it returns `PARSE_SHORT`, and when the header fits
but breaks a rule it returns `PARSE_ILLEGAL`. On any failure it leaves its output struct
untouched. The pcap reader compares a record's captured length with the bytes left in the file
instead of adding it to the current position. That way a hostile length like `0xffffffff` can't
wrap the arithmetic around.

### Byte order

The pcap headers are in the byte order of the machine that wrote the file. `pcap_open` reads the
magic number both ways, and whichever way gives `0xa1b2c3d4` sets the order for every pcap header
after it. The frames themselves are always big endian. Every multi-byte value is built a byte at a
time with shifts, and each byte is widened to an unsigned type first. A `uint8_t` promotes to
`int`, and `0xd4 << 24` overflows an `int`. That overflow is undefined behavior, and the compiler
gives no warning for it.

### Four lengths

| Length | Comes from | Used for |
| --- | --- | --- |
| Captured length | The pcap record header | How many bytes may be read. `cksum=partial` when the segment isn't all there |
| Original length | The pcap record header | The flow summary's `bytes=`, and telling whether the snaplen cut the frame short |
| IPv4 total length | The IPv4 header | Where the datagram ends. Anything after it is Ethernet padding |
| UDP length | The UDP header | UDP `len=`, and how much the UDP checksum covers |

TCP `len` is the total length minus IHL × 4 minus the data offset × 4. UDP `len` is the UDP length
minus 8. Neither comes from the frame length. Frames 14 and 21 are padded to 60 bytes, so a
length taken from the frame would say 6 where the right answer is 0. The checksum covers the
segment as the headers define it, so the padding is never summed.

### Checking in order

`decode_frame` follows the handout's eight steps and stops at the first problem: Ethernet, ARP,
IPv4, the IPv4 header checksum, fragments, the protocol, then TCP or UDP. The IPv4 total length
may run past the captured bytes only when the frame's original length is longer than its captured
length, which means the snaplen cut it. The TCP and UDP checks measure against the IPv4 payload:
the smaller of the total length and the captured bytes, minus the header. The header is IHL × 4
bytes, so options are skipped, and padding can't make a short TCP header look complete.

### Checksums

`inet_checksum` adds the bytes as 16-bit big endian words in a 64-bit sum, padding an odd last
byte with a zero. It folds the carries back in until there are none left, because a single fold
can carry again (`0x1ffff` becomes `0x10000`). Then it returns the complement. To verify a
segment, it sums the segment, checksum field included, starting from `pseudo_header_sum` (the
addresses, the protocol and the length). A correct segment gives 0. A UDP checksum field of 0
means the sender didn't compute one, and prints `none`.

### The flow table

A flow is a protocol and two endpoints, in either direction. `flow_table_add` looks for the key
both ways round. A new flow keeps the orientation of its first packet, so side A is the source of
the first packet seen. The flows are kept in an array, in the order they were first seen. The
array starts at 8 and doubles, with `realloc` into a temporary pointer so a failure leaves the
table as it was. Each lookup is a linear search, which is plenty for captures this size.

### Time

`format_elapsed` works in whole microseconds in an `int64_t`. A timestamp's seconds field is
32 bits, and 2^32 seconds times a million still fits. There is no floating point, so there is no
rounding.

## Testing

`tests/lab-test.c` has 98 Unity tests and covers every function declared in `src/lab.h`.
`make report` gives 100% line coverage of `pcap.c`, `headers.c` and `decode.c` (391 of 391
lines). The only exclusions are the branches for `malloc` and `realloc` returning NULL.

- **Byte arrays:** real frames copied out of `day-in-the-life.pcap`, plus synthetic frames built in
  the test and broken one field at a time. They cover every malformed case in the handout's list,
  an IPv4 header with options, a padded frame, frames cut short by the snaplen, odd-length
  segments, a checksum that carries twice, and the RFC 1071 example.
- **pcap files** in both byte orders, cut off inside the file header (after 7 bytes), inside a
  record header and inside a record's data. A record whose captured length is larger than its
  original length, and one whose length is `0xffffffff`.
- **The flow table:** a flow seen in both directions, the same endpoints over TCP and UDP, and
  growth to 100 flows.
- **`report_capture`** writes into `tmpfile()`, and the test reads the text back.
- **The real captures:** the last four tests run the captures from the repository root.
  `malformed.pcap` must match `malformed.txt`, and the big endian file must print exactly what the
  little endian one does. `truncated.pcap` must print 12 frames and exit 2, and `snaplen.pcap`
  must show `partial`.

Checks outside the unit tests (not submitted):

- The output on each capture was compared, field by field, with `tshark` (Wireshark's command-line
  version, 4.2.2 in WSL and 4.6.10 on Windows). It is identical on `day-in-the-life.pcap` and
  `snaplen.pcap`.
- The program was built with `-fsanitize=address,undefined` and run on 3000 randomly mutated
  captures (flipped bytes, cut files, extreme length fields). There were no sanitizer reports, and
  every run exited 0 or 2.
- The command line was checked separately: no arguments, a bad option, `-s` alone, two files, a
  missing file, a directory, an empty file, a text file, a pcapng file, and a capture read from a
  pipe.

## Wireshark

Checked in Wireshark 4.6.10 on Windows, with `day-in-the-life.pcap`.

### Statistics → Conversations

| Flow | My packets | My bytes | Wireshark packets | Wireshark bytes |
| --- | --- | --- | --- | --- |
| UDP 0.0.0.0:68 <> 255.255.255.255:67 | 2 | 684 | 2 | 684 |
| UDP 68.85.2.1:67 <> 255.255.255.255:68 | 2 | 684 | 2 | 684 |
| UDP 68.85.2.101:51334 <> 68.87.71.226:53 | 2 | 164 | 2 | 164 |
| TCP 68.85.2.101:49152 <> 64.233.169.105:80 | 13 | 4403 | 13 | 4403 |
| UDP 68.85.2.101:41337 <> 64.233.169.105:33434 | 1 | 82 | 1 | 82 |

- **Checksums:** with *Validate the TCP checksum* and *Validate the UDP checksum* turned on,
  Wireshark flags one frame, frame 15. That's the one my program prints as `cksum=bad`.
- **Raw sequence numbers:** with *Relative sequence numbers* turned off, frames 10 to 13 show the
  same seq, ack and window as my output: `3127851020/0`, `2215467233/3127851021`,
  `3127851021/2215467234` twice.
- **`snaplen.pcap` frame 15:** Wireshark says "1514 bytes on wire, 96 bytes captured" and marks it
  *Packet size limited during capture*. It leaves the TCP checksum `[unverified]`, even with
  validation on, because the bytes aren't there. My program prints `cksum=partial` for the same
  reason.

### Disagreements

None of the numbers disagreed. Two things looked like disagreements at first but are display
choices:

- **Window.** Wireshark shows `Win=64256` for frame 12, and my program prints `win=502`. The SYN in
  frame 10 negotiated a window scale of 128, and 502 × 128 = 64256. Wireshark shows the scaled
  window, and the handout asks for the raw field.
- **Sequence numbers.** By default Wireshark shows them relative to the start of the connection
  (frame 12 is `Seq=1`). My program prints the raw 32-bit value, `3127851021`.

The DHCP exchange is two conversations in both tools, not one. The client sends from
`0.0.0.0:68` to port 67, and the server replies from `68.85.2.1:67` to port 68. Those are
different pairs of endpoints.

### Questions

**Why do the first DHCP messages come from `0.0.0.0` and go to `255.255.255.255`?** Frames 1 and
3 are the DHCP Discover and Request. The laptop has no IP address yet, so the only source address
it can use is `0.0.0.0`, which means "this host, address unknown". It also doesn't know where a
DHCP server is, so it sends to the limited broadcast address, `255.255.255.255`. Every host on the
subnet receives that, and routers don't forward it. The server's Offer and ACK (frames 2 and 4)
come from `68.85.2.1`, but they also go to `255.255.255.255`, because the laptop isn't using its
new address yet.

**The ARP request is 42 bytes and the reply is 60. Why?** The capture was taken on the laptop.
Frame 6 is the request the laptop sent: 14 bytes of Ethernet header plus 28 bytes of ARP is 42.
Outgoing frames are captured before the network card pads them to Ethernet's 60 byte minimum
(64 with the frame check sequence, which captures don't include). Frame 7 is the reply the laptop
received, so it arrived already padded to 60, and its last 18 bytes are zeros. The same padding is
why frames 14 and 21 are 60 bytes long but carry no data.

**Which frame has a bad checksum, and what did TCP do about it?** Frame 15. It's the first 1460
byte segment of the HTTP response, `seq=2215467234`. The laptop's TCP drops a segment whose
checksum fails. Frame 16, the next segment (`seq=2215468694`, 656 bytes), arrived fine but out of
order. So the laptop sent frame 17, a duplicate ACK that still asks for `2215467234`. Wireshark
labels it *TCP Dup ACK 12#1*, and it carries a SACK block for the 656 bytes the laptop does have.
The server resent the missing segment as frame 18, 230 ms after frame 15 (0.326880 − 0.097004).
One duplicate ACK is not the three that fast retransmit waits for, so this looks like the
retransmission timer firing. Frame 19 then acknowledges `2215469350`, which covers frames 18 and
16 at once: 2215467234 + 1460 + 656.

**What is frame 24, and what made the router send it?** It's an ICMP time exceeded message (type
11, code 0) from the router `68.85.2.1` to the laptop. Frame 23 is a traceroute probe: a UDP
datagram to port 33434 with a TTL of 1. The router decremented the TTL to 0, discarded the
datagram, and sent back ICMP time exceeded. The message quotes the probe's IPv4 header (record
route option included) and the first 8 bytes of its UDP header, which is how traceroute matches the
reply to its probe and learns the first hop. My program prints it as
`IPv4 68.85.2.1 > 68.85.2.101 proto=1`, because decoding ICMP isn't part of the project.

## Known Bugs or Issues

None known. These are my readings of things the handout leaves open:

- A wrong command line prints the usage on stderr. With no arguments at all, it goes to stdout and
  the exit status is 0.
- A capture with a file header and no records prints only the blank line before the (empty)
  summary, and exits 0.
- A timestamp earlier than the first frame's prints as a negative time.
- IPv6, ICMP, DHCP and DNS contents are not decoded. Only the headers the handout lists are.

## AI Usage

All of `src/` and `tests/`, and this README except the Experience section, were written by an AI
assistant (Claude) at my request. The captures and `malformed.txt` come from the course. The
assistant ran the builds, tests, coverage and leak checks, the `tshark` comparison and the fuzzing
in my WSL environment.

## Experience

TODO
