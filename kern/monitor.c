// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.
// clang-format off
#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/trap.h>

#include <kern/pmap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

// clang-format on
extern uint32_t fg_color, bg_color;

int mon_color(int argc, char **argv, struct Trapframe *tf);
int mon_show_map(int argc, char **argv, struct Trapframe *tf);
int mon_set_permission(int argc, char **argv, struct Trapframe *tf);
int mon_si(int argc, char **argv, struct Trapframe *tf);
int mon_c(int argc, char **argv, struct Trapframe *tf);

static struct Command commands[] = {
    {"help", "Display this list of commands", mon_help},
    {"kerninfo", "Display information about the kernel", mon_kerninfo},
    {"backtrace", "Backtrace the stack", mon_backtrace},
    {"color", "Change color", mon_color},
    // {"showmap", "Show mapping relation. DO NOT use it when enable large
    // page.", mon_show_map},
    // {"setperm", "Set perm. DO NOT use it when enable large page.",
    // mon_set_permission},
    {"si", "Run single instruction and then break", mon_si},
    {"c", "Continue to run", mon_c}};
// clang-format off

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}
// clang-format on
int mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
    struct Eipdebuginfo debug_info;
    cprintf("Stack backtrace:\n");

    uint32_t *ebp = (uint32_t *)read_ebp();
    while ((uint32_t)ebp != 0)
    {
        uint32_t eip = *(ebp + 1), arg_1 = *(ebp + 2), arg_2 = *(ebp + 3),
                 arg_3 = *(ebp + 4), arg_4 = *(ebp + 5), arg_5 = *(ebp + 6);
        cprintf("  ebp %08x  eip %08x  args %08x %08x %08x %08x %08x\n", ebp,
                eip, arg_1, arg_2, arg_3, arg_4, arg_5);

        debuginfo_eip(eip, &debug_info);

        cprintf("         %s:%d: %.*s+%d\n", debug_info.eip_file,
                debug_info.eip_line, debug_info.eip_fn_namelen,
                debug_info.eip_fn_name, eip - debug_info.eip_fn_addr);
        ebp = (uint32_t *)(*ebp);
    }
    return 0;
}
// clang-format off
static int parse_color_arg(const char *arg)
{
    if (strlen(arg) != 1)
        return -1;
    switch (arg[0])
    {
    case '0': case '1': case '2': case '3':
    case '4': case '5': case '6': case '7':
    case '8': case '9':
        return arg[0] - '0';

    case 'a': case 'b': case 'c': case 'd':
    case 'e': case 'f':
        return arg[0] - 'a' + 10;

    case 'A': case 'B': case 'C': case 'D':
    case 'E': case 'F':
        return arg[0] - 'A' + 10;

    default:
        return -1;
    }
}
// clang-format on
int mon_color(int argc, char **argv, struct Trapframe *tf)
{
    int m_bg_color = DEFAULT_BG_COLOR, m_fg_color = DEFAULT_FG_COLOR;
    switch (argc)
    {
    case 1:
        bg_color = m_bg_color;
        fg_color = m_fg_color;
        cprintf("Change color to default.\n");
        break;

    case 2:
        m_fg_color = parse_color_arg(argv[1]);
        if (m_fg_color >= 0)
        {
            if (m_fg_color == bg_color)
                cprintf("Foreground and background color can NOT be same.\n");
            else
            {
                fg_color = m_fg_color;
                cprintf("Change foreground color to %s.\n", argv[1]);
            }
        }
        else
            cprintf("Parse args error: %s", argv[1]);
        break;
    case 3:
        m_fg_color = parse_color_arg(argv[1]);
        m_bg_color = parse_color_arg(argv[2]);
        if (m_fg_color >= 0 && m_bg_color >= 0 && m_bg_color <= 0x7)
        {
            if (m_bg_color == m_fg_color)
                cprintf("Foreground and background color can NOT be same.\n");
            else
            {
                bg_color = m_bg_color;
                fg_color = m_fg_color;
                cprintf(
                    "Change foreground color to %s, background color to %s.\n",
                    argv[1], argv[2]);
            }
        }
        else
            cprintf("Parse args error: %s, %s\n", argv[1], argv[2]);
        break;
    default:
        cprintf("Error\n");
        break;
    }

    return 0;
}

static int is_large_page_enabled(void)
{
    uint32_t edx = 0;
    uint32_t cr4 = rcr4();
    cpuid(1, NULL, NULL, NULL, &edx);

    int is_large_page_supported = (edx >> 3) & 1;
    if (is_large_page_supported && (cr4 & CR4_PSE))
        return 1;
    else
        return 0;
}

// int mon_show_map(int argc, char **argv, struct Trapframe *tf)
// {
//     if (argc == 2)
//     {
//         argv[3] = argv[2];
//         argc = 3;
//     }

//     if (argc != 3)
//     {
//         cprintf("`%s': invalid argc.\n", __func__);
//         return 0;
//     }

//     char *error_char = NULL;

//     uintptr_t start_ptr = strtol(argv[1], &error_char, 16);
//     if (*error_char != 0)
//     {
//         cprintf("`%s': invalid arg: %s.\n", __func__, argv[1]);
//         return 0;
//     }

//     uintptr_t end_ptr = strtol(argv[2], &error_char, 16);
//     if (*error_char != 0)
//     {
//         cprintf("`%s': invalid arg: %s.\n", __func__, argv[2]);
//         return 0;
//     }

//     start_ptr = ROUNDDOWN(start_ptr, PGSIZE);
//     end_ptr = ROUNDUP(end_ptr, PGSIZE);

//     if (start_ptr > end_ptr)
//     {
//         cprintf("Start virtual address is larger than end virtual
//         address.\n"); return 0;
//     }
//     // extern pde_t *kern_pgdir;
//     // int is_enabled = is_large_page_enabled();

//     pde_t *pgdir = (pde_t *)rcr3();

//     // 0x00000000 -> 0x00000000, Permission:
//     //  V address -> P address   Permission: K | R

//     int pflag = 1;
//     cprintf("\n V address -> P address   Permission: K | R\n");
//     for (size_t i = start_ptr; i <= end_ptr; i += PGSIZE)
//     {
//         pte_t *pte_ptr = pgdir_walk(pgdir, (void *)i, 0);
//         if (pte_ptr != NULL && (*pte_ptr & PTE_P))
//         {
//             pflag = 1;
//             char perm[6] = "R-|--";

//             if ((*pte_ptr & PTE_W) && !(*pte_ptr & PTE_U))
//                 perm[1] = 'W';
//             if ((*pte_ptr & PTE_W) && (*pte_ptr & PTE_U))
//             {
//                 perm[1] = 'W';
//                 perm[3] = 'R';
//                 perm[4] = 'W';
//             }
//             if (!(*pte_ptr & PTE_W) && (*pte_ptr & PTE_U))
//                 perm[3] = 'R';

//             cprintf("0x%08x -> 0x%08x, Permission: ", i, PTE_ADDR(*pte_ptr));
//             cprintf("%s\n", perm);
//         }
//         else
//         {
//             cprintf("0x%08x -> not mapped\n", i);
//             cprintf("Stop printing until next virtual mapped.\n");
//             pflag = 0;
//         }
//     }
//     return 0;
// }

// int mon_set_permission(int argc, char **argv, struct Trapframe *tf)
// {
//     if (argc != 3)
//     {
//         cprintf("`%s': invalid argc.\n");
//         return 0;
//     }

//     char *error_char = NULL;

//     uintptr_t ptr = strtol(argv[1], &error_char, 16);
//     if (*error_char != 0)
//     {
//         cprintf("`%s': invalid arg: %s.\n", argv[1]);
//         return 0;
//     }

//     if (strlen(argv[2]) != 1)
//     {
//         cprintf("`%s': invalid arg: %s.\n", argv[2]);
//         return 0;
//     }

//     ptr = ROUNDDOWN(ptr, PGSIZE);

//     // FIXME: 多多理解页表自映射！
//     pte_t *pte_ptr = pgdir_walk(pgdir, (void *)ptr, 0);
//     if (pte_ptr != NULL && (*pte_ptr & PTE_P))
//     {
//         switch (argv[2][0])
//         {
//         case 'K':
//             cprintf("PTE_U on virtual address 0x%08x is disabled.\n", ptr);
//             *pte_ptr &= ~PTE_U;
//             break;
//         case 'U':
//             cprintf("PTE_U on virtual address 0x%08x is enabled.\n", ptr);
//             *pte_ptr |= PTE_U;
//             break;
//         case 'R':
//             cprintf("PTE_W on virtual address 0x%08x is disabled.\n", ptr);
//             *pte_ptr &= ~PTE_W;
//             break;
//         case 'W':
//             cprintf("PTE_W on virtual address 0x%08x is enabled.\n", ptr);
//             *pte_ptr |= PTE_W;
//             break;
//         default:
//             cprintf("`%s': invalid arg: %s.\n", argv[2]);
//             return 0;
//         }
//     }
//     else
//         cprintf("Virtual address 0x%08x is not mapped\n", ptr);
//     return 0;
// }

int mon_si(int argc, char **argv, struct Trapframe *tf)
{
    if (tf != NULL && (tf->tf_trapno == T_DEBUG || tf->tf_trapno == T_BRKPT) &&
        (tf->tf_cs & 3) == 3)
    {
        tf->tf_eflags |= FL_TF;
        return -1;
    }

    cprintf("Nothing running\n");
    return 0;
}

int mon_c(int argc, char **argv, struct Trapframe *tf)
{
    if (tf != NULL && (tf->tf_trapno == T_DEBUG || tf->tf_trapno == T_BRKPT) &&
        (tf->tf_cs & 3) == 3)
    {
        tf->tf_eflags &= ~FL_TF;
        return -1;
    }

    cprintf("Nothing running\n");
    return 0;
}
// clang-format off


/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

	if (tf != NULL)
		print_trapframe(tf);

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
