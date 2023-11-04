/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>


###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)						\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushl $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);							\
	jmp _alltraps

.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
 */

TRAPHANDLER_NOEC(Divide_Error_h, T_DIVIDE)
TRAPHANDLER_NOEC(Debug_Exception_h, T_DEBUG)
TRAPHANDLER_NOEC(NMI_Interrupt_h, T_NMI)
TRAPHANDLER_NOEC(Breakpoint_h, T_BRKPT)

TRAPHANDLER_NOEC(Overflow_h, T_OFLOW)
TRAPHANDLER_NOEC(BOUND_Range_Exceeded_error_h, T_BOUND)
TRAPHANDLER_NOEC(Invalid_Opcode_h, T_ILLOP)
TRAPHANDLER_NOEC(Device_Not_Available_h, T_DEVICE)

TRAPHANDLER(Double_Fault_h, T_DBLFLT)
// 9 is reserved by Intel.
TRAPHANDLER(Invalid_TSS_h, T_TSS)
TRAPHANDLER(Segment_Not_Present_h, T_SEGNP)

TRAPHANDLER(Stack_Segment_Fault_h, T_STACK)
TRAPHANDLER(General_Protection_h, T_GPFLT)
TRAPHANDLER(Page_Fault_h, T_PGFLT)
// 15 is reserved by Intel.

TRAPHANDLER_NOEC(x87_FPU_Floating_Point_Error_h, T_FPERR)
TRAPHANDLER(Alignment_Check_h, T_ALIGN)
TRAPHANDLER_NOEC(Machine_Check_h, T_MCHK)
TRAPHANDLER_NOEC(SIMD_Floating_Point_Exception_h, T_SIMDERR)
TRAPHANDLER_NOEC(System_Call_h, T_SYSCALL)

.global fast_system_call
.type fast_system_call, @function
.align 2
fast_system_call:

	pushl   $0
	pushl	%edi
	pushl	%ebx
	pushl	%ecx
	pushl	%edx
	pushl	%eax

	call	syscall

	movl	%esi, %edx
	movl	%ebp, %ecx
	sysexit


/*
 * Lab 3: Your code here for _alltraps
 */

_alltraps:
	pushw	$0
	pushw	%ds

	pushw	$0
	pushw	%es

	pushal

	xorl	%eax,	%eax

	movw	$GD_KD, %ax
	movw	%ax,	%ds
	movw	%ax,	%es

	pushl	%esp
	call	trap

