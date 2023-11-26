// clang-format off
// implement fork from user space

#include "inc/memlayout.h"
#include "inc/mmu.h"
#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
// clang-format on
static void pgfault(struct UTrapframe *utf)
{
    void *addr = (void *)utf->utf_fault_va;
    uint32_t err = utf->utf_err;
    int r;

    // Check that the faulting access was (1) a write, and (2) to a
    // copy-on-write page.  If not, panic.
    // Hint:
    //   Use the read-only page table mappings at uvpt
    //   (see <inc/memlayout.h>).

    // LAB 4: Your code here.

    addr = ROUNDDOWN(addr, PGSIZE);

    if ((uvpd[PDX(addr)] & PTE_P) != PTE_P ||
        (uvpt[PGNUM(addr)] & (PTE_P | PTE_U | PTE_COW)) !=
            (PTE_P | PTE_U | PTE_COW) ||
        (err & FEC_WR) != FEC_WR)
        panic("`%s' error: addr %x is wrong.\n", __func__, addr);

    // Allocate a new page, map it at a temporary location (PFTEMP),
    // copy the data from the old page to the new page, then move the new
    // page to the old page's address.
    // Hint:
    //   You should make three system calls.

    // LAB 4: Your code here.
    r = sys_page_alloc(0, PFTEMP, PTE_P | PTE_U | PTE_W);
    if (r < 0)
        panic("`%s' error: %e\n", __func__, r);
    memcpy(PFTEMP, addr, PGSIZE);

    r = sys_page_map(0, PFTEMP, 0, addr, PTE_P | PTE_U | PTE_W);
    if (r < 0)
        panic("`%s' error: %e\n", __func__, r);
    r = sys_page_unmap(0, PFTEMP);
    if (r < 0)
        panic("`%s' error: %e\n", __func__, r);
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int duppage(envid_t envid, unsigned pn)
{
    int r;
    pte_t pte = uvpt[pn];
    void *addr = (void *)(pn * PGSIZE);
    if ((pte & (PTE_P | PTE_U)) != (PTE_P | PTE_U))
        panic("`%s' error: pn %u is wrong.", __func__, pn);

    if ((pte & PTE_W) == PTE_W || (pte & PTE_COW) == PTE_COW)
    {
        r = sys_page_map(0, addr, envid, addr, PTE_P | PTE_U | PTE_COW);
        if (r < 0)
            panic("`%s' error: %e.", __func__, r);
        r = sys_page_map(0, addr, 0, addr, PTE_P | PTE_U | PTE_COW);
        if (r < 0)
            panic("`%s' error: %e.", __func__, r);
    }
    else
    {
        r = sys_page_map(0, addr, envid, addr, PTE_P | PTE_U);
        if (r < 0)
            panic("`%s' error: %e.", __func__, r);
    }
    // LAB 4: Your code here.
    return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
envid_t fork(void)
{
    // LAB 4: Your code here.
    set_pgfault_handler(pgfault);

    int fork_ret = sys_exofork();
    if (fork_ret == 0)
        thisenv = &envs[ENVX(sys_getenvid())];

    else if (fork_ret > 0)
    {
        size_t page_addr = 0;
        while (page_addr < UTOP - PGSIZE)
        {
            if ((uvpd[PDX(page_addr)] & (PTE_P | PTE_U)) != (PTE_P | PTE_U))
            {
                page_addr += PGSIZE;
                continue;
            }
            if ((uvpt[PGNUM(page_addr)] & (PTE_P | PTE_U)) != (PTE_P | PTE_U))
            {
                page_addr += PGSIZE;
                continue;
            }

            duppage(fork_ret, PGNUM(page_addr));
            page_addr += PGSIZE;
        }

        int ret = sys_page_alloc(fork_ret, (void *)(UXSTACKTOP - PGSIZE),
                                 PTE_P | PTE_U | PTE_W);
        if (ret < 0)
            panic("1");
        ret = sys_env_set_pgfault_upcall(fork_ret, thisenv->env_pgfault_upcall);
        if (ret < 0)
            panic("2");
        ret = sys_env_set_status(fork_ret, ENV_RUNNABLE);
        if (ret < 0)
            panic("3");
    }

    return fork_ret;
}
// clang-format off

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}