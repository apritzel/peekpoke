#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/mman.h>
#include "mapping.h"

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

static void usage(FILE *stream, const char *progname)
{
	fprintf(stream,
		"usage: %s [-h] [-n] [-b <base address>] <cmd> [<cmd> ...]\n",
		progname);
	fprintf(stream, "\t<cmd>: [rwvcs][.][bhlwq] <offset> [<data>]\n");
	fprintf(stream, "-h: this help screen\n");
	fprintf(stream, "-n: dry-run, don't actually poke memory\n");
	fprintf(stream, "-b <addr>: base address to add to addresses specified in commands\n");
	fprintf(stream, "actions:\n");
	fprintf(stream, "\tr: read data\n");
	fprintf(stream, "\tw: write data\n");
	fprintf(stream, "\tv: write and read (verify) data\n");
	fprintf(stream, "\tc: clear a single bit\n");
	fprintf(stream, "\ts: set a single bit\n");
	fprintf(stream, "\tB[h:l]: set a range of bits\n");
	fprintf(stream, "\tp: pause for 10ms\n");
	fprintf(stream, "\tP: pause for 100ms\n");
	fprintf(stream, "length:\n");
	fprintf(stream, "\tb: byte\n");
	fprintf(stream, "\th: halfword (two bytes)\n");
	fprintf(stream, "\tl: long (four bytes)\n");
	fprintf(stream, "\tw: word (four bytes)\n");
	fprintf(stream, "\tq: quadword (eight bytes)\n");
	fprintf(stream, "Example:\n");
	fprintf(stream,
		"\t%s -b 0x1c28000 w.l 0 0x41 P w.l 0 0x42 r.l r 0x7c\n",
		progname);
	fprintf(stream,
	"\t(write 'a' to register 0, wait 100ms, write 'b' to register 0,\n"
	"\t read register 0x7c)\n");
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

#define ERR_INVALID_CMD		-1
#define ERR_INVALID_LEN		-2
#define ERR_MISSING_OFFSET	-3
#define ERR_INVALID_OFFSET	-4
#define ERR_MISSING_DATA	-3
#define ERR_INVALID_DATA	-4

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
		case 'B':
			if (parse_range(argv[i], NULL, &j) < 0)
				return ERR_MISSING_DATA;
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
			return ERR_INVALID_CMD;
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
			return ERR_INVALID_LEN;
		}

		if (++i >= argc)
			return ERR_MISSING_OFFSET;

		if (!is_valid_num(argv[i], hex, &offset))
			return ERR_INVALID_OFFSET;
		add_address(start_base + offset);

		if (cmd == 'r')
			continue;

		if (++i >= argc)
			return ERR_MISSING_DATA;

		if (!is_valid_num(argv[i], hex, NULL))
			return ERR_INVALID_DATA;
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
			usage(stdout, argv[0]);
			return 0;
		}
	}

	if ((i = check_commands(argc - optind, argv + optind, hex,
				&read_only, base_addr))) {
		fprintf(stderr, "invalid command sequence: %d\n", i);
		usage(stderr, argv[0]);
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
				usage(stderr, argv[0]);
				break;
			}
		}
		len_spec = argv[i][j++];
		if (len_spec == '.')
			len_spec = argv[i][j++];
		if (len_spec == '\0')
			len_spec = 'l';

		if (++i >= argc) {
			usage(stderr, argv[0]);
			break;
		}
		offset = strtoull(argv[i], NULL, hex ? 16 : 0);

		if (cmd != 'r') {
			if (++i >= argc) {
				usage(stderr, argv[0]);
				break;
			}

			data = strtoull(argv[i], NULL, hex ? 16 : 0);
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
