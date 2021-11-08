#ifndef MAPPING_H__
#define MAPPING_H__

#include <stdint.h>

struct mapping {
	uintptr_t paddr;
	size_t length;
	void *vaddr;
};

extern struct mapping *maps;
extern int num_maps;

void add_address(uintptr_t address);
struct mapping* get_mapping(uintptr_t address);

#endif
