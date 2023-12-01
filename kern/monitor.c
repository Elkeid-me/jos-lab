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
int mon_si(int argc, char **argv, struct Trapframe *tf);
int mon_c(int argc, char **argv, struct Trapframe *tf);

static struct Command commands[] =
    {{"help", "Display this list of commands", mon_help},
     {"kerninfo", "Display information about the kernel", mon_kerninfo},
     {"backtrace", "Backtrace the stack", mon_backtrace},
     {"color", "Change color", mon_color}};
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
