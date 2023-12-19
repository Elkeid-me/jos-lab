/* Simple linker script for the JOS kernel.
   See the GNU ld 'info' manual ("info ld") to learn the syntax. */

OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(_start)

SECTIONS
{
	/* Link the kernel at this address: "." means the current address */
	. = 0xF0100000;

	/* AT(...) gives the load address of this section, which tells
	   the boot loader where to load the kernel in physical memory */
	.text : AT(0x100000) {
		/* 整活：mpentry 到 mp_main 的直接调用
		   如果想要直接调用，请取消注释下面一行，
		   注释掉 `mpentry.S` 中的
		   `movl    $mp_main, %eax`
		   `call    *%eax`
		   两行，并取消注释
		   `call    true_mp_main` */

		/* PROVIDE(true_mp_main = mp_main + (0xF0100000 + mpentry_start - 0x7000)); */
		*(.text .stub .text.* .gnu.linkonce.t.*)
	}

	PROVIDE(etext = .);	/* Define the 'etext' symbol to this value */

	.rodata : {
		*(.rodata .rodata.* .gnu.linkonce.r.*)
	}

	/* Include debugging information in kernel memory */
	.stab : {
		PROVIDE(__STAB_BEGIN__ = .);
		*(.stab);
		PROVIDE(__STAB_END__ = .);
		BYTE(0)		/* Force the linker to allocate space
				   for this section */
	}

	.stabstr : {
		PROVIDE(__STABSTR_BEGIN__ = .);
		*(.stabstr);
		PROVIDE(__STABSTR_END__ = .);
		BYTE(0)		/* Force the linker to allocate space
				   for this section */
	}

	/* Adjust the address for the data segment to the next page */
	. = ALIGN(0x1000);

	/* The data segment */
	.data : {
		*(.data .data.*)
	}

	.bss : {
		PROVIDE(edata = .);
		*(.dynbss)
		*(.bss .bss.*)
		*(COMMON)
		PROVIDE(end = .);
	}


	/DISCARD/ : {
		*(.eh_frame .note.GNU-stack .comment .note)
	}
}
