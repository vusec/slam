/* Eviction functionality for L1 and L2 data caches, L1 and L2 TLB.
 *
 * Date: November 23, 2023
 * Author: Mathé Hertogh - Vrije Universiteit Amsterdam
 */

#include "slam.h"

/* Eviction buffers, used for evicting the entire L1D cache, the whole L1 TLB,
 * and specific L2 TLB sets.
 */
static volatile char *evset_l1d_cache;
static void **evbuf_l1tlb;
volatile char *evset_l2tlb[EVSET_SIZE_L2TLB];

static void evict_init_l1d_cache()
{
	pr_verbose("Eviction set size L1D cache: %3ld pages (%d cachelines)\n",
		EVSET_SIZE_L1D_CACHE*CACHE_LINE_SIZE/PAGE_SIZE, EVSET_SIZE_L1D_CACHE);
	evset_l1d_cache = mmap(NULL, EVSET_SIZE_L1D_CACHE * CACHE_LINE_SIZE, PROT_RW, MAP_ANON_PRIV_POP, -1, 0);
	if (evset_l1d_cache == MAP_FAILED)
		fail("can not mmap l1d cache eviction set buffer");
}

static void evict_check_l1tlb()
{
	int count = 0;
	int l1tlb_hits[L1TLB_NR_SETS];
	int l2tlb_hits[L2TLB_NR_SETS];
	int l1d_hits[L1D_NR_SETS];
	int l2_hits[L2_NR_SETS];
	memset(l1tlb_hits, 0, L1TLB_NR_SETS*sizeof(int));
	memset(l2tlb_hits, 0, L2TLB_NR_SETS*sizeof(int));
	memset(l1d_hits, 0, L1D_NR_SETS*sizeof(int));
	memset(l2_hits, 0, L2_NR_SETS*sizeof(int));
	
	void **p = evbuf_l1tlb;
	do {
		count++;
		l1tlb_hits[l1tlb_set(p)]++;
		l2tlb_hits[l2tlb_set(p)]++;
		l1d_hits[l1d_set(p)]++;
		l2_hits[l2_set_hugepage(p)]++;
		p = *p;
	} while (p != evbuf_l1tlb);

	assert(count == EVSET_SIZE_L1TLB);
	for (int i = 0; i < L1TLB_NR_SETS; i++)
		assert(l1tlb_hits[i] == EVICT_FACTOR_L1TLB*L1TLB_WAYNESS);
	for (int i = 0; i < L2TLB_NR_SETS; i++)
		assert(l2tlb_hits[i] <= 2);
	for (int i = 0; i < L1D_NR_SETS; i++) {
		if (i < EVSET_SIZE_L1TLB/(EVICT_FACTOR_L1D_CACHE*L1D_WAYNESS))
			assert(l1d_hits[i] == EVICT_FACTOR_L1D_CACHE*L1D_WAYNESS);
		else
			assert(l1d_hits[i] == 0);
	}
	for (int i = 0; i < L2_NR_SETS; i++)
		assert(l2_hits[i] <= 2);
}

static void evict_init_l1tlb()
{
	char *base;
	void **cur;
	int next_idx; // Index of the page that the current page will point to.
	int page_off; // Page offset from base.
	int l1cl_off; // Offset within a page to hit the correct L1D cache line.

	pr_verbose("Eviction set size L1 TLB: %6d pages\n", EVSET_SIZE_L1TLB);
	
	base = alloc_contiguous_pages(NULL);

	// Accessing the first 128 pages flushes the dTLB. We chain them
	// simply as: 0 -> 1 -> 2 -> ... -> 127 -> 0.
	// Note that, as these pages are virtually contiguous, we put minimal
	// pressure on the sTLB, preserving most (recent?) entries.
	// Meanwhile, we make sure that this chase evicts the first 8 cache
	// sets (ie cache lines) from L1D, while preserving them in in L2.
	// Pages 0,1,...,15 access the first cache line,
	// pages 15,16,...,31 access the second cache line, etc.
	// So we hit the first 8 L1D cache sets 16 times (flushing) while
	// hitting each corresponding L2 cache set only twice (preserving).
	cur = (void **)base;
	for (int i = 0; i < EVSET_SIZE_L1TLB; i++) {
		next_idx = (i + 1) % EVSET_SIZE_L1TLB;
		page_off = next_idx * PAGE_SIZE;
		l1cl_off = next_idx/(EVICT_FACTOR_L1D_CACHE*L1D_WAYNESS) * CACHE_LINE_SIZE;
		*cur = (void *)(base + page_off + l1cl_off);
		cur = *cur;
	}

	evbuf_l1tlb = (void **)base;

	evict_check_l1tlb();
}

static void evict_init_l2tlb()
{
	pr_verbose("Eviction set size L2 TLB: %6d pages\n", EVSET_SIZE_L2TLB);

	mmap_random_pages((void **)evset_l2tlb, EVSET_SIZE_L2TLB);
}

static void evict_check_timing()
{
	#define REPEAT 11
	#define NR_TESTS 10000
	uint64_t times[REPEAT];
	uint64_t median;
	int evict_l1d_l1tlb = 0, evict_l1d_l2tlb = 0, evict_all = 0, evict_retry = 0;
	char *tests[NR_TESTS];
	char *p;
	mmap_random_pages((void **)tests, NR_TESTS);
	#define NR_RETRIES 512
	int retries[NR_RETRIES];
	memset(retries, 0, NR_RETRIES*sizeof(int));
	int nr_retries = 0;

	for (int t = 0; t < NR_TESTS; t++) {
		p = tests[t] + PAGE_SIZE/2;

		for (int i = 0; i < REPEAT; i++) {
			load(p);
			cpuid();
			evict_l1d_cache();
			evict_l1tlb();
			cpuid();
			times[i] = time_access(p);
		}
		median = median_sort(times, REPEAT);
		if (median > 40)
			evict_l1d_l1tlb++;

		for (int i = 0; i < REPEAT; i++) {
			load(p);
			cpuid();
			evict_l1d_cache();
			evict_l2tlb();
			cpuid();
			times[i] = time_access(p);
		}
		median = median_sort(times, REPEAT);
		if (median > 40)
			evict_l1d_l2tlb++;

		for (int i = 0; i < REPEAT; i++) {
			load(p);
			cpuid();
			evict_l1d_cache();
			evict_l1tlb();
			evict_l2tlb();
			cpuid();
			times[i] = time_access(p);
		}
		median = median_sort(times, REPEAT);
		if (median > 40)
			evict_all++;
		else if (nr_retries < NR_RETRIES)
			retries[nr_retries++] = t;
	}

	for (int r = 0; r < nr_retries; r++) {
		p = tests[retries[r]] + PAGE_SIZE/2;
		for (int i = 0; i < REPEAT; i++) {
			load(p);
			cpuid();
			evict_l1d_cache();
			evict_l1tlb();
			evict_l2tlb();
			cpuid();
			times[i] = time_access(p);
		}
		median = median_sort(times, REPEAT);
		if (median > 40)
			evict_retry++;
	}

	pr_info("Eviction signal L1D cache + L1 TLB:          %5d / %5d\n", evict_l1d_l1tlb, NR_TESTS);
	pr_info("Eviction signal L1D cache + L2 TLB:          %5d / %5d\n", evict_l1d_l2tlb, NR_TESTS);
	pr_info("Eviction signal L1D cache + L1 TLB + L2 TLB: %5d / %5d\n", evict_all, NR_TESTS);
	pr_info("Retry signal for non-evicted addresses:      %5d / %5d\n", evict_retry, nr_retries);
}

void evict_init()
{
	pr_info("=====[evict init]=====\n");
	srand(time(0));
	evict_init_l1d_cache();
	evict_init_l1tlb();
	evict_init_l2tlb();
	evict_check_timing();
	pr_info("\n");
}

void evict_l1d_cache()
{
	for (int i = 0; i < EVSET_SIZE_L1D_CACHE; i++)
		evset_l1d_cache[i*CACHE_LINE_SIZE];
}

void evict_l1tlb()
{
	void **p = evbuf_l1tlb;
	do {
		p = *p;
	} while (p != evbuf_l1tlb);
}

void evict_l2tlb()
{
	for (int i = 0; i < EVSET_SIZE_L2TLB; i++)
		*(evset_l2tlb[i]);
}
