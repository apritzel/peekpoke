// SPDX-License-Identifier: GPL-2.0+

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/mman.h>
#include "mapping.h"

/* Used with printf "%.*s" to indent output. */
#define JUST_SPACES "                                                                                                                                                                                                                                               "

static int lenspec_to_bytes(char c)
{
	switch(c) {
	case 'b': return 1;
	case 'h': return 2;
	case 'w':
	case 'l': return 4;
	case 'q': return 8;
	}

	return 0;
}

static void usage(FILE *stream, const char *progname, bool verbose)
{
	fprintf(stream,
		"usage: %s [-h] [-H] [-n] [-b <base address>] <cmd> [<cmd> ...]\n",
		progname);
	fprintf(stream, "\t<cmd>: [rwvcsdD][.][bhlwq] <offset> [<data>]\n");
	fprintf(stream, "\t-h: %shelp screen\n", verbose ? "this " : "");
	if (!verbose)
		return;
	fprintf(stream, "\t-H: default to hexadecimal numbers, allows omitting 0x prefix\n");
	fprintf(stream, "\t-n: dry-run, don't actually poke memory\n");
	fprintf(stream, "\t-b <addr>: base address to add to addresses specified in commands\n");
	fprintf(stream, "commands:\n");
	fprintf(stream, "\tr: read data\n");
	fprintf(stream, "\tw: write data\n");
	fprintf(stream, "\tv: write and read (verify) data\n");
	fprintf(stream, "\tc: clear a single bit\n");
	fprintf(stream, "\ts: set a single bit\n");
	fprintf(stream, "\tB[h:l]: set a range of bits\n");
	fprintf(stream, "\tp: pause for 10ms\n");
	fprintf(stream, "\tP: pause for 100ms\n");
	fprintf(stream, "\td: dump range of words\n");
	fprintf(stream, "length:\n");
	fprintf(stream, "\tb: byte\n");
	fprintf(stream, "\th: halfword (two bytes)\n");
	fprintf(stream, "\tl: long (four bytes)\n");
	fprintf(stream, "\tw: word (four bytes)\n");
	fprintf(stream, "\tq: quadword (eight bytes)\n");
	fprintf(stream, "Examples:\n");
	fprintf(stream,
		"\t%s -b 0x1c28000 w.l 0 0x41 P w.l 0 0x42 r.l 0x7c\n",
		progname);
	fprintf(stream,
	"\t\t(write 'a' to register 0, wait 100ms, write 'b' to register 0,\n"
	"\t\t read register 0x7c)\n");
	fprintf(stream, "\t%s c.l 0x7000010 31\n", progname);
	fprintf(stream, "\t\t(clear bit 31 in register 0x7000010)\n");
	fprintf(stream, "\t%s B[15:8].l 0x3000024 0xa5\n", progname);
	fprintf(stream, "\t\t(write 0xa5 into bits[15:8], preserving the other bits)\n");
	fprintf(stream,
		"\t%s d.l 0x01c20800 9\n", progname);
	fprintf(stream, "\t\t(dump nine 32-bit words starting at 0x01c20800)\n");
}

static void dump_binary(FILE *stream, unsigned long data, char len_spec)
{
	int bit;

	bit = lenspec_to_bytes(len_spec) * 8 - 1;

	for (; bit >=0 ; bit--) {
		if (data & (1UL << bit))
			fputc('1', stream);
		else
			fputc('0', stream);
		if ((bit & 3) == 0 && bit != 0)
			fputc('.', stream);
	}
	fputc('\n', stream);
}

static bool is_valid_num(const char *str, bool hex, off_t *value)
{
	char *endp;
	off_t val = strtoull(str, &endp, hex ? 16 : 0);

	if (endp == str)
		return false;
	if (*endp != 0)
		return false;

	if (value)
		*value = val;

	return true;
}

enum parse_errors {
	ERR_INVALID_CMD = 1,
	ERR_INVALID_LEN,
	ERR_MISSING_OFFSET,
	ERR_INVALID_OFFSET,
	ERR_MISSING_DATA,
	ERR_INVALID_DATA,
	NUMBER_PARSE_ERRORS
};

static const char *error_string[NUMBER_PARSE_ERRORS] = { "",	// no error
	"invalid command character", "invalid length specifier",
	"missing address offset", "invalid address offset",
	"missing data", "invalid data"
};

/* Convert a string in the form "[62:32]" to a bitmask. */
static int parse_range(const char *s, unsigned long *ret_mask, int *ptr)
{
	int i = *ptr;
	int hi = 0, lo = 0;

	if (s[i++] != '[')
		return -1;
	for (; s[i] >= '0' && s[i] <= '9'; i++)
		hi = hi * 10 + s[i] - '0';
	if (s[i++] != ':')
		return -1;
	for (; s[i] >= '0' && s[i] <= '9'; i++)
		lo = lo * 10 + s[i] - '0';
	if (s[i++] != ']')
		return -1;

	*ptr = i;

	if (ret_mask)
		*ret_mask = (1UL << (hi + 1)) - 1 - (1UL << lo) + 1;
	return lo;
}

/* check the command stream for syntax errors */
static int check_commands(int argc, char **argv, bool hex, bool *ro,
			  uintptr_t start_base)
{
	off_t offset;
	bool has_write = false;
	int i;
	char cmd;
	char len_spec;

	for (i = 0; i < argc; i++) {
		int j = 0;

		cmd = argv[i][j++];
		switch (cmd) {
		case 'r': break;
		case 'd': case 'D': break;
		case 'B':
			if (parse_range(argv[i], NULL, &j) < 0)
				return (ERR_MISSING_DATA << 16) | i;
			/* fall-through */
		case 'v':
		case 'w':
		case 's':
		case 'c':
			has_write = true; break;
		case 'p':
		case 'P':
			continue;
		default:
			return (ERR_INVALID_CMD << 16) | i;
		}
		len_spec = argv[i][j++];
		if (len_spec == '.')
			len_spec = argv[i][j++];
		switch (len_spec) {
		case 'b':
		case 'h':
		case '\0':
		case 'w':
		case 'l':
		case 'q':
			break;
		default:
			return (ERR_INVALID_LEN << 16) | i;
		}

		if (++i >= argc)
			return (ERR_MISSING_OFFSET << 16) | i;

		if (!is_valid_num(argv[i], hex, &offset))
			return (ERR_INVALID_OFFSET << 16) | i;
		add_address(start_base + offset);

		if (cmd == 'r')
			continue;

		if (++i >= argc)
			return (ERR_MISSING_DATA << 16) | i;

		if (!is_valid_num(argv[i], hex, NULL))
			return (ERR_INVALID_DATA << 16) | i;
	}

	if (ro)
		*ro = !has_write;

	return 0;
}

static unsigned long read_data(uintptr_t paddr, char len_spec, FILE *binstream)
{
	struct mapping *map;
	unsigned char *vaddr;
	unsigned long data;

	map = get_mapping(paddr);
	if (map == NULL || map->vaddr == NULL) {
		fprintf(stderr, "reading %d bytes from offset 0x%lx: ",
			lenspec_to_bytes(len_spec), (unsigned long)paddr);

		return 0;
	}
	vaddr = (unsigned char *)map->vaddr + (paddr - map->paddr);

	switch (len_spec) {
	case 'b':
		data = *(volatile uint8_t *)vaddr;
		if (binstream)
			fwrite(&data, 1, 1, binstream);
		return data;
	case 'h':
		data = *(volatile uint16_t *)vaddr;
		if (binstream)
			fwrite(&data, 2, 1, binstream);
		return data;
	case 'w':
	case 'l':
		data = *(volatile uint32_t *)vaddr;
		if (binstream)
			fwrite(&data, 4, 1, binstream);
		return data;
	case 'q':
		data = *(volatile uint64_t *)vaddr;
		if (binstream)
			fwrite(&data, 8, 1, binstream);
		return data;
	}

	return -1;
}

static void dump_word(unsigned long word, char len_spec, FILE *stream)
{
	switch(len_spec) {
	case 'b':
		fprintf(stream, " %02lx", word & 0xff);
		break;
	case 'h':
		fprintf(stream, " %02lx %02lx",
			word & 0xff, (word >> 8) & 0xff);
		break;
	case 'w': case 'l': case 'q':
		fprintf(stream, " %02lx %02lx %02lx %02lx",
			word & 0xff, (word >> 8) & 0xff,
			(word >> 16) & 0xff, (word >> 24) & 0xff);
		if (len_spec == 'q' && sizeof(word) > 4)
			dump_word((word >> 16) >> 16, 'l', stream);
		break;
	}
}

static void dump_range(uintptr_t paddr, size_t num, char len_spec, bool bytes)
{
	int i, indent = paddr & 0x0fUL;
	unsigned long data;

	if (indent) {
		/* two characters per byte */
		int spaces = indent * 2;

		if (bytes)
			/* one separating space per byte */
			spaces += indent;
		else
			/* one separating space per word */
			spaces += indent / lenspec_to_bytes(len_spec);

		fprintf(stdout, "%08lx %.*s", paddr & ~0x0fUL,
			spaces, JUST_SPACES);
	}
	if (indent > 8)
		fputc(' ', stdout);

	for (i = 0; i < num; i++) {
		if ((paddr & 0x0fUL) == 0)
			fprintf(stdout, "%08lx", (unsigned long)paddr);
		if ((paddr & 0x07UL) == 0)
			fputc(' ', stdout);
		data = read_data(paddr, len_spec, NULL);
		if (bytes) {
			dump_word(data, len_spec, stdout);
		} else {
			switch(len_spec) {
			case 'b': fprintf(stdout, " %02lx", data); break;
			case 'h': fprintf(stdout, " %04lx", data); break;
			case 'w': case 'l':
				  fprintf(stdout, " %08lx", data); break;
			case 'q': fprintf(stdout, " %016lx", data); break;
			}
		}
		paddr += lenspec_to_bytes(len_spec);
		if ((paddr & 0x0fUL) == 0 && i != num - 1)
			fputc('\n', stdout);
	}
	fputc('\n', stdout);
}

static void write_data(uintptr_t paddr, char len_spec, unsigned long data)
{
	struct mapping *map;
	unsigned char *vaddr;

	map = get_mapping(paddr);
	if (map == NULL || map->vaddr == NULL) {
		fprintf(stderr, "writing %d bytes to 0x%llx: 0x%llx\n",
			lenspec_to_bytes(len_spec),
			(unsigned long long)paddr,
			(unsigned long long)data);
		return;
	}
	vaddr = (unsigned char *)map->vaddr + (paddr - map->paddr);

	switch (len_spec) {
	case 'b':
		*(volatile uint8_t *)vaddr = data;
		break;
	case 'h':
		*(volatile uint16_t *)vaddr = data;
		break;
	case 'w':
	case 'l':
		*(volatile uint32_t *)vaddr = data;
		break;
	case 'q':
		*(volatile uint64_t *)vaddr = data;
		break;
	}
}

static void show_error(int argc, char **argv, int reason, int idx)
{
	int pos = 0, i;

	fprintf(stderr, "invalid command sequence: %s\n", error_string[reason]);
	for (i = 0; i < argc; i++) {
		int len = fprintf(stderr, "%s%s", i ? " " : "", argv[i]);

		if (i < idx)
			pos += len;
	}
	fputc('\n', stderr);
	fprintf(stderr, "%.*s^\n", pos + 1, JUST_SPACES);
	usage(stderr, argv[0], false);
}

int main(int argc, char** argv)
{
	int ch;
	off_t base_addr = 0;
	bool dump = false, verbose = false, hex = false, read_only;
	bool dryrun = false;
	int fd = 0, i;

	while ((ch = getopt(argc, argv, "Hdvb:nh")) != -1) {
		switch (ch) {
		case 'b':
			base_addr = strtoull(optarg, NULL, hex ? 16 : 0);
			break;
		case 'd':
			dump = true;
			break;
		case 'v':
			verbose = true;
			break;
		case 'H':
			hex = true;
			break;
		case 'n':
			dryrun = true;
			break;
		case 'h':
			usage(stdout, argv[0], true);
			return 0;
		}
	}

	if ((i = check_commands(argc - optind, argv + optind, hex,
				&read_only, base_addr))) {
		show_error(argc, argv, i >> 16, optind + (i & 0xffff));
		return -5;
	}

	if (!dryrun) {
		fd = open("/dev/mem", (read_only ? O_RDONLY : O_RDWR) | O_SYNC);
		if (fd < 0) {
			perror("/dev/mem");
			return -errno;
		}

		for (i = 0; i < num_maps; i++) {
			maps[i].vaddr = mmap(NULL, maps[i].length, PROT_READ |
					     (read_only ? 0 : PROT_WRITE),
					     MAP_SHARED, fd, maps[i].paddr);

			if (maps[i].vaddr == MAP_FAILED) {
				perror("mmapping /dev/mem");
				close(fd);
				return -errno;
			}
		}
	}

	for (i = optind; i < argc; i++) {
		off_t offset;
		unsigned long mask = 0;
		int shift = -1;
		unsigned long data = 0;
		char cmd, len_spec;
		int j = 0;

		cmd = argv[i][j++];
		switch (cmd) {
		case 'p': usleep(10000); continue;
		case 'P': usleep(100000); continue;
		default: break;
		}

		if (cmd == 'B') {
			if ((shift = parse_range(argv[i], &mask, &j)) < 0) {
				usage(stderr, argv[0], false);
				break;
			}
		}
		len_spec = argv[i][j++];
		if (len_spec == '.')
			len_spec = argv[i][j++];
		if (len_spec == '\0')
			len_spec = 'l';

		if (++i >= argc) {
			usage(stderr, argv[0], false);
			break;
		}
		offset = strtoull(argv[i], NULL, hex ? 16 : 0);

		if (cmd != 'r') {
			if (++i >= argc) {
				usage(stderr, argv[0], false);
				break;
			}

			data = strtoull(argv[i], NULL, hex ? 16 : 0);
		}

		if (cmd == 'd') {
			dump_range(base_addr + offset, data, len_spec, true);
			continue;
		}

		if (cmd == 'D') {
			dump_range(base_addr + offset, data, len_spec, false);
			continue;
		}

		if (cmd == 's')
			data = (1UL << data) | read_data(base_addr + offset,
							 len_spec, NULL);
		if (cmd == 'c')
			data = ~(1UL << data) & read_data(base_addr + offset,
							  len_spec, NULL);

		if (cmd == 'B')
			data = ((data << shift) & mask) |
				(read_data(base_addr + offset, len_spec, NULL) &
								~mask);

		if (cmd != 'r')
			write_data(base_addr + offset, len_spec, data);

		if (cmd == 'r' || cmd == 'v') {
			data = read_data(base_addr + offset, len_spec,
					 dump ? stdout : NULL);
			if (!verbose) {
				fprintf(stdout, "0x%lx\n", data);
				continue;
			}
			fprintf(stdout, "0x%llx: 0x%lx, =%ld, =0b",
					(unsigned long long)base_addr + offset,
					data, data);
			dump_binary(stdout, data, 4);
		}
	}

	if (!dryrun) {
		for (i = 0; i < num_maps; i++)
			munmap(maps[i].vaddr, maps[i].length);
		free(maps);
		close(fd);
	}

	return 0;
}
