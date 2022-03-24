; List of "security" error
; 1) Using -no-pie mod
; 2) Using entry_buffer id .data segment, and not check for buffer overflow
; 3) I decoded my password in entry_buffer. If you will watch bytes of buffer as color you will see the password "mipt"
; You can do it in radare2 for example

global _start


section .data 
entry_buffer times 80 db 128
             db 138, 128, 128, 128, 138, 128, 138, 128, 138, 138, 128, 128, 138, 138, 138, 128  ; You have a 16x15 matrix  
             db 138, 138, 128, 138, 138, 128, 138, 128, 138, 128, 138, 128, 128, 138, 128, 128  ; Think of it as a matrix like a children's
                                                                                                ; coloring book. When you want to mark a 
                                                                                                ; "square" in the matrix, you write 138 
                                                                                                ; to distinguish it from the others 
                                                                                                ; (from the background, which is given by
                                                                                                ; the number 128). So r2 will correctly 
                                                                                                ; output it as an image.        
             db 138, 128, 138, 128, 138, 128, 138, 128, 138, 138, 128, 128, 128, 138, 128, 128
             db 138, 128, 128, 128, 138, 128, 138, 128, 138, 128, 128, 128, 128, 138, 128, 128 
             db 138, 128, 128, 128, 138, 128, 138, 128, 138, 128, 128, 128, 128, 138, 128, 128                             ; *...*
             times 80 db 128


             ;-------------------------------------------------
            
             

AuthError    db "Inccorect password, permission denied", 10
AuthCorrect  db "Welcome back, slave Kris", 10

Passphrase     dq 0x6995b92097503148

AuthErrorLen   equ 38
AuthCorrectLen equ 25 


section .text

_start:
;------------------------------------------
; This code will be implemented. It needed to more security

    mov rsi, entry_buffer

Distract db 0x48, 0x31, 0xD0 ; xor rax, rax. I use it simple to confuse my hacker partner

    mov rdi, 0
    mov rdx, 2560
    syscall
    mov rcx, rax

;------------------------------------------------------
; Simple hash function to confuse my hacker partner
; Entry: RAX - number of byte to convert to hash
; Ret:   RAX - hash, as result of hash-function

MurmurHash:

    imul rax, 0xCABBAC
    imul rax, 0xBACCCCAB
    add rcx, entry_buffer - 1
    xor rdx, rdx        ; Second_hash_coff

    mov rbx, entry_buffer


.Mix:
    mov dh, byte [rbx]

    mov r8b, byte [rbx + 1]
    shl r8, 8

    or rdx, r8
    sbb rdx, r8

    mov r8b, byte [rbx + 2]
    shl r8, 16
    xor rdx, r8

    mov r8b, byte [rbx + 3]
    shl r8, 24
    and rdx, r8
    adc rdx, r8
    
    imul rdx, 0x5BD1E993 
    mov rax, rdx

    shr rdx, 5
    xor rdx, rax

    imul rdx, 0x5DB15214
    imul rdx, 0x51BEDADED

    xor rax, rdx

    add rbx, 4

    cmp rbx, rcx
    jb .Mix
    
    mov rdx, rax
    shl rax, 13
    xor rax, rdx
    imul rax, 0xAAAAAAAA
;---------------------------------------------------------
    mov rbx, qword [Distract]         ; Only distract
    xor rdx, rbx
    xor rax, rdx
    
    cmp rax, qword [Passphrase] 
    je .AuthCompleted


    mov rax, 1
    mov rdx, AuthErrorLen
    mov rsi, AuthError
    mov rdi, 1
    syscall
    xor r8, r8

    jmp _start
   
.AuthCompleted:
    mov rax, 1
    mov rdx, AuthCorrectLen
    mov rsi, AuthCorrect
    mov rdi, 1
    syscall
   
    mov rax, 60
    xor rdi, rdi
    syscall 


;--------------------------------------------------
; Simple hash to save the program. 

