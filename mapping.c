// SPDX-License-Identifier: GPL-2.0+
/*
 * Routines to work out a range of pages that need to be mapped for accessing
 * given memory locations.
 * Each add_address() call will record the page the given address lies in.
 * Subsequent calls will add more pages if needed, potentially joining
 * adjacent pages. After all pages have been mapped (must be done separately,
 * by just walking over the <maps> array and calling mmap()), a call to
 * get_mapping() will return the virtual address mapped to the given physical
 * location.
 */

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>	/* for sysconf() */
#include "mapping.h"

struct mapping *maps = NULL;
int num_maps = 0;

static uintptr_t page_size = 0;

/* assumes power of 2 alignments */
#define ALIGN_DOWN(x, a)	((x) & ~((a) - 1))
#define ALIGN_UP(x, a)		ALIGN_DOWN((x) + (a) - 1, (a))

/*
 * Try to find an existing mapping that covers the address. If the address
 * falls within the previous or next page of an existing mapping, extend that
 * mapping.
 * If no matching mapping exists, allocate a new one.
 */
void add_address(uintptr_t address)
{
	int i;

	if (page_size == 0)
		page_size = sysconf(_SC_PAGESIZE);

	for (i = 0; i < num_maps; i++) {
		size_t new_length;

		if (maps[i].paddr - page_size > address ||
		    maps[i].paddr + maps[i].length + page_size <= address)
			continue;

		if (address < maps[i].paddr) {
			uintptr_t new_base = ALIGN_DOWN(address, page_size);

			maps[i].length += maps[i].paddr - new_base;
			maps[i].paddr = new_base;
		}

		new_length = ALIGN_UP(address + 1 - maps[i].paddr, page_size);
		if (new_length > maps[i].length)
			maps[i].length = new_length;

		return;
	}
	num_maps++;
	maps = realloc(maps, sizeof(*maps) * num_maps);

	maps[i].paddr = address & ~(page_size - 1);
	maps[i].length = ALIGN_UP((address - maps[i].paddr) + 1, page_size);
	maps[i].vaddr = NULL;
}

struct mapping* get_mapping(uintptr_t address)
{
	int i;

	for (i = 0; i < num_maps; i++) {
		if (maps[i].paddr > address ||
		    maps[i].paddr + maps[i].length <= address)
			continue;

		return &maps[i];
	}

	return NULL;
}
