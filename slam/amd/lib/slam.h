/* Interface to SLAM's common functionality.
 *
 * Date: November 23, 2023
 * Author: Mathé Hertogh - Vrije Universiteit Amsterdam
 */

#pragma once

#define _XOPEN_SOURCE 600
#define _GNU_SOURCE
#include <time.h>
#include <sched.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <fcntl.h>

// Configurable constants.
#define TIME_INIT_NR_CALIBRATIONS	100
#define NR_RUNS				32
#define CPU				0
#define EVICT_FACTOR_L1D_CACHE	2
#define EVICT_FACTOR_L1TLB	2
#define EVICT_FACTOR_L2TLB	4
#define VERBOSITY			0

/* Eviction set sizes in number of entries, ie cachelines for L1D cache, and
 * pages for the TLBs.
 */
#define EVSET_SIZE_L1D_CACHE	(EVICT_FACTOR_L1D_CACHE * L1D_SIZE)
#define EVSET_SIZE_L1TLB	(EVICT_FACTOR_L1TLB * L1TLB_SIZE)
#define EVSET_SIZE_L2TLB	38

// Universal constants.
#define KB 1024ULL
#define MB (KB*KB)
#define GB (KB*MB)

// Common machine constants.
#define PAGE_SHIFT		12
#define CACHE_LINE_SHIFT	6

// Machine specific constants for the Ryzen 2700X.
#define L1D_WAYNESS		8
#define L1D_NR_SETS		64
#define L2_WAYNESS		8
#define L2_NR_SETS		1024
#define L1TLB_NR_SETS		1
#define L1TLB_WAYNESS		64
#define L2TLB_NR_SETS_BITS      8
#define L2TLB_NR_SETS		(1 << L2TLB_NR_SETS_BITS)
#define L2TLB_WAYNESS		8
#define L2TLB_LIN_12_18__21
#define PHYS_MEM_SIZE         (32*GB)

// Derived constants.
#define PAGE_SIZE	(1UL << PAGE_SHIFT)
#define CACHE_LINE_SIZE (1UL << CACHE_LINE_SHIFT)
#define HUGE_PAGE_SIZE  (1UL << (PAGE_SHIFT+9))
#define L1D_SIZE	(L1D_NR_SETS * L1D_WAYNESS) // nr entires, ie cachelines
#define L1TLB_SIZE	(L1TLB_NR_SETS * L1TLB_WAYNESS) // nr entires, ie pages
#define L2TLB_SIZE	(L2TLB_NR_SETS * L2TLB_WAYNESS) // nr entires, ie pages

// Shortcuts
#define PROT_RW                 (PROT_READ|PROT_WRITE)
#define MAP_ANON_PRIV_POP       (MAP_ANONYMOUS|MAP_PRIVATE|MAP_POPULATE)

// evict.c
void evict_init();
void evict_l1d_cache();
void evict_l1tlb();
void evict_l2tlb_set(int set);
void evict_l2tlb();

// reload.c
void reload_init();
void reload_move_buf(void *new_addr);
void reload(int chain_idx, uint64_t *times);

// set.c
int l1d_set(void *addr);
int l2_set_hugepage(void *addr);
int l1tlb_set(void *addr);
int l2tlb_set(void *addr);

// time.c
void timer_init();
void timer_fini();
uint64_t time_access(volatile char *addr);
uint64_t clock_read();

// util.c
void fail(const char *msg);
void sort(uint64_t A[], unsigned size);
uint64_t median_sort(uint64_t A[], unsigned size);
uint64_t minimum_sort(uint64_t A[], unsigned size);
int max_idx(uint64_t A[], int size);
uint64_t avg(uint64_t A[], unsigned size);
void mmap_random_pages(void **ptrs, int nr);
int mmap_at(void *addr);
void *alloc_contiguous_pages(void *addr);
void print_progress_bar(const char *prefix, int percentage);
uint64_t next_page(uint64_t addr);
void set_cpu_affinity(int cpu_id);
int get_sibling(int cpu_id);
float std_dev(uint64_t A[], unsigned size);
float avgf(float A[], unsigned size);
void list_print(uint64_t *A, unsigned size);
void append(volatile char *A[], char *x);
void load(void *addr);
uint64_t direct_map_alias(uint64_t va, uint64_t direct_map);
char rand_printable_ascii_char();

#if VERBOSITY >= 0
void pr_result(const char *format, ...);
#else
static inline void pr_result(const char *format, ...) { }
#endif
#if VERBOSITY >= 1
void pr_info(const char *format, ...);
#else
static inline void pr_info(const char *format, ...) { }
#endif
#if VERBOSITY >= 2
void pr_verbose(const char *format, ...);
#else
static inline void pr_verbose(const char *format, ...) { }
#endif
#if VERBOSITY >= 3
void pr_debug(const char *format, ...);
#else
static inline void pr_debug(const char *format, ...) { }
#endif
void pr_err(const char *format, ...);


__always_inline static inline uint64_t minimum(uint64_t a, uint64_t b) { return a < b ? a : b; }
__always_inline static inline uint64_t maximum(uint64_t a, uint64_t b) { return a > b ? a : b; }
__always_inline static inline void swap(void **a, void **b) { void *c = *a; *a = *b; *b = c; }
__always_inline static inline void clflush(volatile char *addr) { asm volatile ("clflush (%0)\n\t" :: "r"(addr):); }
__always_inline static inline void cpuid(void) { asm volatile ("xor %%rax, %%rax\ncpuid\n\t" ::: "%rax", "%rbx", "%rcx", "%rdx"); }
__always_inline static inline void mfence(void) { asm volatile ("mfence\n\t":::); }
__always_inline static inline void lfence(void) { asm volatile ("lfence\n\t":::); }
__always_inline static inline void sfence(void) { asm volatile ("sfence\n\t":::); }
