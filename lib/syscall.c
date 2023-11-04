// System call stubs.
// clang-format off
#include <inc/syscall.h>
#include <inc/lib.h>
// clang-format on
static inline int32_t syscall(int num, int check, uint32_t a1, uint32_t a2,
                              uint32_t a3, uint32_t a4, uint32_t a5)
{
    int32_t ret;

    // Generic system call: pass system call number in AX,
    // up to five parameters in DX, CX, BX, DI, SI.
    // Interrupt kernel with T_SYSCALL.
    //
    // The "volatile" tells the assembler not to optimize
    // this instruction away just because we don't use the
    // return value.
    //
    // The last clause tells the assembler that this can
    // potentially change the condition codes and arbitrary
    // memory locations.
    switch (num)
    {
    case SYS_cputs:
    case SYS_cgetc:
    case SYS_getenvid:
    case SYS_env_destroy:
        asm volatile("pushl %%ebp\n"
                     "movl %%esp, %%ebp\n"
                     "leal 1f, %%esi\n"
                     "sysenter\n"
                     "1:\n"
                     "popl %%ebp\n"
                     : "=a"(ret)
                     : "a"(num), "d"(a1), "c"(a2), "b"(a3), "D"(a4)
                     : "%esi");
        break;
    default:
        asm volatile("int %1\n"
                     : "=a"(ret)
                     : "i"(T_SYSCALL), "a"(num), "d"(a1), "c"(a2), "b"(a3),
                       "D"(a4), "S"(a5)
                     : "cc", "memory");
    }
    if (check && ret > 0)
        panic("syscall %d returned %d (> 0)", num, ret);

    return ret;
}
// clang-format off
void
sys_cputs(const char *s, size_t len)
{
	syscall(SYS_cputs, 0, (uint32_t)s, len, 0, 0, 0);
}

int
sys_cgetc(void)
{
	return syscall(SYS_cgetc, 0, 0, 0, 0, 0, 0);
}

int
sys_env_destroy(envid_t envid)
{
	return syscall(SYS_env_destroy, 1, envid, 0, 0, 0, 0);
}

envid_t
sys_getenvid(void)
{
	 return syscall(SYS_getenvid, 0, 0, 0, 0, 0, 0);
}

