/* Miscellaneous utility functions.
 *
 * Date: November 23, 2023
 * Author: Mathé Hertogh - Vrije Universiteit Amsterdam
 */

#include "slam.h"

void fail(const char *msg)
{
	pr_err("EXITING DUE TO ERROR: %s\n", msg);
	exit(1);
}

static int cmp_uint64_t(const void *a, const void *b) 
{
	uint64_t x = *(uint64_t *)a;
	uint64_t y = *(uint64_t *)b;
	if (x > y) return  1;
	if (x < y) return -1;
	return 0;
}

void sort(uint64_t A[], unsigned size)
{
	qsort(A, size, 8, cmp_uint64_t);
}

uint64_t median_sort(uint64_t A[], unsigned size)
{
	sort(A, size);
	return A[size/2];
}

uint64_t minimum_sort(uint64_t A[], unsigned size)
{
	sort(A, size);
	return A[0];
}

int max_idx(uint64_t A[], int size)
{
	int max_i = 0;
	for (int i = 1; i < size; i++)
		if (A[i] > A[max_i])
			max_i = i;
	return max_i;
}

uint64_t avg(uint64_t A[], unsigned size)
{
	uint64_t sum = 0;
	for (unsigned i = 0; i < size; i++)
		sum += A[i];
	
	return sum / size;
}

void mmap_random_pages(void **ptrs, int nr)
{
	for (int i = 0; i < nr; i++) {
		void *hint = (void *)((((uint64_t)rand() << 32) | rand()) & 0x00007ffffffff000UL);
		ptrs[i] = mmap(hint, PAGE_SIZE, PROT_RW, MAP_ANON_PRIV_POP, -1, 0);
		if (ptrs[i] == MAP_FAILED)
			fail("mmap failed");
	}
}

/* mmap a readable and writable 4KB page at @addr and populate it.
 *
 * Return 0 on success, -1 on failure.
 */
int mmap_at(void *addr)
{
	void *p;
	int err;
	
	p = mmap(addr, PAGE_SIZE, PROT_RW, MAP_ANON_PRIV_POP, -1, 0);
	if (p == (void *)-1) {
		pr_err("mmap: %s\n", strerror(errno));
		return -1;
	}
	if (p != addr) {
		pr_err("mmap_at: got %p instead of %p\n", p, addr);
		err = munmap(p, PAGE_SIZE);
		if (err)
			pr_err("munmap: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/* Return the RSS (ie the physical memory mapped) under this virtual address
 * range.
 */
static int rss(void *base_addr)
{
	FILE *smaps;
	uint64_t base;
	char line[256];
	char addr[32];
	int rss = -1;

	smaps = fopen("/proc/self/smaps", "r");
	if (!smaps)
		fail("failed to open /proc/self/smaps");
	// Look up the correct address range.
	base = (uint64_t)base_addr;
	snprintf(addr, 32, "%lx-", base);
	while (fgets(line, 256, smaps)) {
		if (strstr(line, addr))
			break;
	}
	// Extract the RSS in KBs.
	assert(fscanf(smaps, "Size: 2048 kB KernelPageSize: 4 kB MMUPageSize: 4 kB Rss: %d kB", &rss) == 1);
	fclose(smaps);
	return rss*KB;
}

/* Allocate a hugepage worth of physical contiguous memory and mmap it into
 * the virtual address space (optionally at @addr) using 4kb page tables.
 * The last page is read-only, the rest read+write.
 */
void *alloc_contiguous_pages(void *addr)
{
	char *p;
	uint64_t base;

	if (!addr) {
		// Find a suitable hugepage aligned address for our eviction buffer. 
		p = mmap(NULL, 2*HUGE_PAGE_SIZE, PROT_RW, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
		if (p == (void *)-1) {
			pr_err("mmap: %s\n", strerror(errno));
			fail("alloc_contiguous_pages alignment mmap failed");
		}
		if (munmap(p, 2*HUGE_PAGE_SIZE) < 0) {
			pr_err("munmap: %s\n", strerror(errno));
			fail("alloc_contiguous_pages munmap failed");
		}
		base = (uint64_t)p;
		while (base % HUGE_PAGE_SIZE)
			base += PAGE_SIZE;
		addr = (void *)base;
	}

	assert((uint64_t)addr % HUGE_PAGE_SIZE == 0);

	// mmap the virtual memory at the chosen address.
	p = mmap(addr, HUGE_PAGE_SIZE, PROT_RW, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (p == (void *)-1) {
		pr_err("mmap: %s\n", strerror(errno));
		fail("alloc_contiguous_pages buf mmap failed");
	}
	if (p != addr)
		fail("alloc_contiguous_pages cant mmap that exact address");
	
	// Turn it into a hugepage.
	if (madvise(p, HUGE_PAGE_SIZE, MADV_HUGEPAGE) < 0) {
		pr_err("madvise: %s\n", strerror(errno));
		fail("alloc_contiguous_pages madvise failed");
	}

	// Populate the hugepage, and check it is indeed huge.
	assert(rss(p) == 0);
	*p = '\0';
	assert(rss(p) == HUGE_PAGE_SIZE); // hugeness check

	// Split the huge page table into 512 small page tables.
	if (mprotect(p + HUGE_PAGE_SIZE - PAGE_SIZE, PAGE_SIZE, PROT_READ) < 0) {
		pr_err("mprotect: %s\n", strerror(errno));
		fail("alloc_contiguous_pages mprotect failed");
	}

	return p;
}

void print_progress_bar(const char *prefix, int percentage)
{
	int i;

	// Erase current line.
	pr_info("\b\r%c[2K\r", 27);

	pr_info("%s [", prefix);
	for (i = 0; i < percentage; i++)
		pr_info("#");
	for (; i < 100; i++)
		pr_info(" ");
	pr_info("] (%d%%)", percentage);
}

uint64_t next_page(uint64_t addr)
{
	return (addr | (PAGE_SIZE-1)) + 1;
}

void set_cpu_affinity(int cpu_id) {
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu_id, &set);
	if (sched_setaffinity(0, sizeof(set), &set) != 0) {
		pr_err("Error setting CPU affinity of process with PID %d to %d: %s\n",
				getpid(), cpu_id, strerror(errno));
		exit(EXIT_FAILURE);
	}
}

int get_sibling(int cpu_id)
{
        int brother, sister;
        char fname[64];
        snprintf(fname, 64, "/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list", cpu_id);
        FILE *f = fopen(fname, "r");
        if (!f) {
                perror("could not open sysfs thread_siblings_list file");
                exit(EXIT_FAILURE);
        }
        assert(fscanf(f, "%d", &brother) == 1);
	fgetc(f);
        assert(fscanf(f, "%d", &sister) == 1);
        if (brother == cpu_id)
                return sister;
        if (sister == cpu_id)
                return brother;
        pr_err("Could not find cpu id %d in file %s\n", cpu_id, fname);
        exit(EXIT_FAILURE);
}

float std_dev(uint64_t A[], unsigned size)
{
	uint64_t sum = 0;
	for (unsigned i = 0; i < size; i++)
		sum += A[i];
	float avg = (float)sum / (float)size;

        float diff, sum_of_squares = 0;
        for (unsigned i = 0; i < size; i++) {
                diff = avg - (float)A[i];
                sum_of_squares += diff * diff;
        }
        return sqrtf(sum_of_squares / (float)size);
}

float avgf(float A[], unsigned size)
{
	float sum = 0.0;
	for (unsigned i = 0; i < size; i++)
		sum += A[i];

	return sum / size;
}

void list_print(uint64_t *A, unsigned size)
{
	for (unsigned i = 0; i < size; i++) {
		if (i == size/4)
			pr_info("<%lu> ", A[i]);
		else
			pr_info("%lu ", A[i]);
	}
	pr_info("\n");
}

void append(volatile char *A[], char *x)
{
	int i = 0;
	while (A[i])
		i++;
	A[i] = x;
}

void load(void *addr)
{
	*(volatile char *)addr;
}

uint64_t direct_map_alias(uint64_t va, uint64_t direct_map)
{
    if (!direct_map) {
        direct_map = 0xffff888000000000ULL;
    } else if (direct_map == 0xffff888100000000UL) {
	// Quirk when running inside a VM (with KASLR disabled).
        direct_map = 0xffff888000000000UL;
    }

    int pagemap = open("/proc/self/pagemap", O_RDONLY);
    if (pagemap < 0)
        fail("direct_map_alias: can not open /proc/self/pagemap, are you root?");

    uint64_t value;
    int got = pread(pagemap, &value, sizeof(uint64_t), (va/PAGE_SIZE) * sizeof(uint64_t));
    if (got != sizeof(uint64_t))
        fail("direct_map_alias: problem reading /proc/self/pagemap, are you root?");
    close(pagemap);

    uint64_t page_frame_number = value & ((1ULL << 54) - 1);
    if (!page_frame_number)
        fail("direct_map_alias: errornous page frame number, are you root?");

    return direct_map + page_frame_number*PAGE_SIZE + va%PAGE_SIZE;
}

char rand_printable_ascii_char()
{
	return (char)(0x20 + rand() % 0x5f);
}

#if VERBOSITY >= 0
void pr_result(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    fflush(stdout);
}
#endif

#if VERBOSITY >= 1
void pr_info(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    fflush(stdout);
}
#endif

#if VERBOSITY >= 2
void pr_verbose(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    fflush(stdout);
}
#endif

#if VERBOSITY >= 3
void pr_debug(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    fflush(stdout);
}
#endif

void pr_err(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fflush(stderr);
}
