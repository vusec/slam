/* Eviction functionality for L1 and L2 data caches, L1 TLB, and the IPC.
 *
 * Date: November 23, 2023
 * Author: Mathé Hertogh - Vrije Universiteit Amsterdam
 */

#include "slam.h"

/* Eviction buffers, used for evicting the entire L1D cache, specific L2 cache
 * sets, the whole L1 TLB, and the entire L2 TLB.
 */
static volatile char *evset_l1d_cache;
static char *evset_l2_cache[L2_NR_SETS][EVSET_SIZE_L2_CACHE];
static void **evbuf_l1tlb;

static void evict_init_l1d_cache()
{
	pr_verbose("Eviction set size L1D cache:  %3ld pages (%d cachelines).\n",
		EVSET_SIZE_L1D_CACHE*CACHE_LINE_SIZE/PAGE_SIZE, EVSET_SIZE_L1D_CACHE);
	evset_l1d_cache = mmap(NULL, EVSET_SIZE_L1D_CACHE * CACHE_LINE_SIZE, PROT_RW, MAP_ANON_PRIV_POP, -1, 0);
	if (evset_l1d_cache == MAP_FAILED)
		fail("can not mmap l1d cache eviction set buffer");
}

static void evict_check_l2_cache()
{
	for (int set = 0; set < L2_NR_SETS; set++) {
		for (int i = 0; i < EVSET_SIZE_L2_CACHE; i++) {
			char *p = evset_l2_cache[set][i];
			assert(l2_set_hugepage(p) == set);
		}
	}
}

static void evict_init_l2_cache()
{
	#define NR_CACHELINES (EVICT_FACTOR_L2_CACHE * L2_SIZE)
	#define NR_HUGEPAGES (((NR_CACHELINES * CACHE_LINE_SIZE) + (HUGE_PAGE_SIZE-1)) / HUGE_PAGE_SIZE)
	#define NR_CACHELINES_PER_HUGEPAGE (HUGE_PAGE_SIZE/CACHE_LINE_SIZE)
	pr_verbose("Eviction set size L2 cache:  %3ld pages (%d cachelines).\n",
			NR_CACHELINES*CACHE_LINE_SIZE/PAGE_SIZE, NR_CACHELINES);
	for (int i = 0; i < NR_HUGEPAGES; i++) {
		char *buf = alloc_contiguous_pages(NULL, 0);
		for (int j = 0; j < NR_CACHELINES_PER_HUGEPAGE; j++) {
			char *p = buf + j*CACHE_LINE_SIZE;
			int n = i*NR_CACHELINES_PER_HUGEPAGE + j;
			if (n >= NR_CACHELINES)
				break;
			evset_l2_cache[l2_set_hugepage(p)][n/L2_NR_SETS] = p;
		}
	}

	evict_check_l2_cache();
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

	pr_verbose("Eviction set size L1 TLB:  %6d pages.\n", EVSET_SIZE_L1TLB);

	base = alloc_contiguous_pages(NULL, 1);

	// Accessing the first 128 pages flushes the dTLB. We chain them
	// simply as: 0 -> 1 -> 2 -> ... -> 127 -> 0.
	// Note that, as these pages are virtually contiguous, we put minimal
	// pressure on the sTLB, preserving most (recent?) entries.
	// Meanwhile, we make sure that this chase evicts the first 8 cache
	// sets (ie cache lines) from L1D, while preserving them in in L2.
	// Pages 0,1,...,15 access the first cache line,
	// pages 15,16,...,31 access the second cache line, etc.
	// Note that our pages are also physically contiguous.
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

void evict_init()
{
	pr_verbose("=====[Eviction set initialization]=====\n");
	srand(time(0));
	evict_init_l1d_cache();
	evict_init_l2_cache();
	evict_init_l1tlb();
	pr_verbose("\n");
}

void evict_l1d_cache()
{
	for (int i = 0; i < EVSET_SIZE_L1D_CACHE; i+=64)
		evset_l1d_cache[i*CACHE_LINE_SIZE];
}

void evict_l2_cache_set(int set)
{
	for (int i = 0; i < EVSET_SIZE_L2_CACHE; i++)
		load(evset_l2_cache[set][i]);
}

void evict_l1tlb()
{
	void **p = evbuf_l1tlb;
	do {
		p = *p;
	} while (p != evbuf_l1tlb);
}

/* Evict the Invalid Page Cache. Cf. definition of IPC_SIZE.
 */
void evict_ipc()
{
	for (size_t i = 0; i < EVSET_SIZE_IPC; i++) {
		uint64_t addr =  0xffffffff + (rand() & 0xffffffff);
		prefetcht0((char *)addr);
	}
}

void evict_syscall_table_entry(int syscall_nr)
{
	// Note: we rely on the fact that the system call table in Linux is
	// backed by (a) huge page(s).
	char *entry = (char *)SYSCALL_TABLE_OFFSET + syscall_nr*sizeof(void *);
	int set = l2_set_hugepage(entry);
	evict_l2_cache_set(set);
}
