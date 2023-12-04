/* Cache set computations.
 *
 * Date: November 23, 2023
 * Author: Mathé Hertogh - Vrije Universiteit Amsterdam
 */

#include "slam.h"

/* Return the L1D cache set of addr.
 */
int l1d_set(void *addr)
{
	uint64_t p = (uint64_t)addr;
	return (p >> CACHE_LINE_SHIFT) % L1D_NR_SETS;
}

/* L2 cache set of an address inside a hugepage. Note that the L2 cache set
 * depends on more than PAGE_SHIFT physical address bits. We use the virtual
 * address bits, hence the set returned is only valid for addresses whose
 * virtual and phyiscal address bits match beyond PAGE_SHIFT bits, such as
 * addresses within a hugepage. 
 */
int l2_set_hugepage(void *addr)
{
	uint64_t p = (uint64_t)addr;
	return (p >> CACHE_LINE_SHIFT) % L2_NR_SETS;
}

/* Return the L1 dTLB set of addr.
 */
int l1tlb_set(void *addr)
{
	uint64_t p = (uint64_t)addr;
	return (p >> PAGE_SHIFT) % L1TLB_NR_SETS;
}

/* Return the L2 dTLB set of addr.
 */
int l2tlb_set(void *addr)
{
	uint64_t va = (uint64_t)addr;
	uint64_t mask = -1ULL >> (64-L2TLB_NR_SETS_BITS);
	va >>= PAGE_SHIFT;
	// return va & mask;
	int a = va & 0x7f;
	int b = (va >> 2) & 0x80;
	return a | b;
}
