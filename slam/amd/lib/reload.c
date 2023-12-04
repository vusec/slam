/* Reload functionality for EVICT+RELOAD on the TLB.
 *
 * Date: November 23, 2023
 * Author: Mathé Hertogh - Vrije Universiteit Amsterdam
 */

#include "slam.h"

/* Reload buffer, used to measure dTLB hits versus misses.
 */
void *rlbuf;

void reload_init()
{
        rlbuf = alloc_contiguous_pages(NULL);
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

void reload(int page, uint64_t *times)
{
        *times = time_access(((char *)rlbuf) + page*PAGE_SIZE);
}
