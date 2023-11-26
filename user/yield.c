// yield the processor to other environments

#include <inc/lib.h>

void umain(int argc, char **argv)
{
    int i;

    int tmp1 = thisenv->env_id;
    asm volatile("movd (%%eax), %%mm0" :: "a"(&tmp1));
    int tmp2;
    cprintf("Hello, I am environment %08x.\n", thisenv->env_id);
    for (i = 0; i < 5; i++)
    {
        sys_yield();
        asm volatile("movd %%mm0, (%%eax)" :: "a"(&tmp2) : "memory");
        cprintf("Back in environment %08x, iteration %d. tmp2 is %08x\n",
                thisenv->env_id, i, tmp2);
        tmp2 = 7;
    }
    cprintf("All done in environment %08x.\n", thisenv->env_id);
}
