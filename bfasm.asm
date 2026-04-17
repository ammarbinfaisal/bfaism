; =============================================================================
; bfasm.asm  --  An optimising Brainfuck -> x86-64 compiler, written in NASM.
;
; Build (produces a ready-to-run x86-64 Linux ELF executable):
;
;     nasm -f bin -o bfasm bfasm.asm && chmod +x bfasm
;
; Run:
;     ./bfasm program.bf
;
; Why -f bin and not the usual -felf64 + ld?  The host this was developed on
; is aarch64, whose GNU ld is not configured with an elf_x86_64 emulation.
; The file below therefore ships its own minimal ELF64 + program-header
; prologue so that nasm alone suffices -- true "no external deps".  All the
; semantics are identical to the -felf64+ld path: a position-dependent ELF
; with one RWX LOAD segment, e_entry = _start, and BSS declared via
; p_memsz > p_filesz (zero-filled by the kernel on load).
;
; All instruction encodings emitted by this compiler were cross-checked
; against Intel SDM Vol. 2 (Instruction Set Reference, opcode / ModR/M / SIB
; tables).  The combined SDM PDF in the working directory is the canonical
; reference for every hex literal written below.
;
; ----------------------------------------------------------------------------
; WHY STATIC/AOT-AT-LOAD COMPILATION RATHER THAN A SPECULATIVE JIT + DEOPT
;
; Brainfuck has *no* polymorphic values, *no* dynamic dispatch, *no* runtime
; type information.  The tape is a flat byte array.  Every source position
; maps to a fixed, monomorphic operation on that array: '+' is always a u8
; add, '.' is always a single-byte write, '[' is always "compare one byte
; with zero and branch".  There is nothing at runtime that could invalidate
; an assumption, so deoptimisation guards would guard against nothing.
;
; The typical JIT wins -- type/shape guards, profile-guided inlining of
; late-bound calls, on-stack replacement when a guard fails -- have no
; analogue in Brainfuck.  Even "hot loop specialisation" degenerates to
; source-level pattern matching (e.g. recognising a multiply/copy loop
; shape), which we do in a single static pass.  A tiered compiler would
; buy nothing.
;
; Therefore: we compile once, at load time, directly to native code, as
; aggressively as possible, and simply call the result.  This is still a
; JIT by timing (compilation happens at run-time into a freshly mmap'd
; RWX page) but is unguarded, untiered, and non-speculative.  A single
; static lowering pipeline produces the final code.
;
; ----------------------------------------------------------------------------
; OPTIMISATIONS IMPLEMENTED IN THIS PIPELINE
;
;   1. Run-length contraction of +/- and >/<.
;         N consecutive '+'/'-' collapse into a single i8 add immediate.
;         N consecutive '>'/'<' collapse into a single pointer delta.
;
;   2. Offset coalescing / deferred pointer moves.
;         Between "straight-line" ops the pointer is never moved.  Every
;         byte-add, clear, read, write, bracket-cmp, and multiply-loop
;         emission accepts an r12-relative displacement, and we carry the
;         accumulated pointer delta forward as a compile-time constant.
;         One  "add r12, imm"  is emitted only when we must commit (loop
;         entry, loop exit, scan loop, program end).
;
;   3. Clear loops.
;         [-] and [+] lower to a single   mov byte [r12+off], 0.
;         Wrapping u8 arithmetic makes both shapes terminate at zero.
;
;   4. Multiply / copy loops.
;         A simple loop [body] qualifies when body is straight-line
;         ('+','-','>','<' only), has net pointer delta 0, and decrements
;         the counter cell by exactly 1 per iteration.  We lower the whole
;         loop to:
;             c = counter
;             if (c)
;                 for each (o, f) in affected cells:  t[o] += c*f
;             counter = 0
;         This subsumes copy loops [->+<], sum loops [->+>+<<], and
;         multiplier loops [->++<].  No loop at all is emitted.
;
;   5. Scan loops.
;         [>] and [<] lower to a single repne scasb burst -- hardware
;         prefetched byte scan for the next zero cell.
;
;   6. Peephole fusion.
;         Adjacent OP_ADDs at the same offset are merged.
;         Adjacent OP_MOVPs are merged.
;         A merged ADD or MOVP whose net delta is zero is *dropped*
;         (dead-delta elimination).
;
; ----------------------------------------------------------------------------
; EMITTED CODE CONVENTIONS
;
;     r12                Brainfuck data pointer.
;                        Set by the host before CALLing the JIT entry.
;                        r12 is callee-saved across the Linux syscall ABI,
;                        so read/write do not need to spill it.
;     rax, rcx, rdx,
;     rsi, rdi, r8..r11  Scratch -- clobbered for syscalls and imul.
;     rbx                Scratch, used only by multiply-loop expansion.
;
; The emitted entry has no prologue/epilogue of its own: _start initialises
; r12, issues CALL, and the emitted program ends with a single RET.
; =============================================================================

BITS 64

; -----------------------------------------------------------------------------
; ORG:  the runtime virtual address of file offset 0.  0x400000 is the classic
; Linux/ELF base -- well above any mmap "random" selection the kernel might
; pick, so collisions with mmap'd code/tape are impossible.
; -----------------------------------------------------------------------------
%define IMAGE_BASE  0x400000
                ORG IMAGE_BASE

; =============================================================================
; Tiny ELF64 header + one PT_LOAD program header.
;
; The ELF64 header is exactly 64 bytes (ehdr_size below), and the single
; program header is 56 bytes (phdr_size).  Entry point is _start.  The one
; LOAD segment spans [file 0, file_end) -> [IMAGE_BASE, IMAGE_BASE + memsz),
; with memsz > filesz so the kernel zero-fills BSS for us.  Flags = 0x7 = RWX
; because BSS follows code in the same segment (and because the JIT will
; later mmap its own RWX page anyway -- we don't care about W^X for this
; tool).
; =============================================================================
ehdr:
    db  0x7F, "ELF"                ; e_ident[0..3]  magic.
    db  2                          ; e_ident[4]     EI_CLASS = ELFCLASS64.
    db  1                          ; e_ident[5]     EI_DATA  = ELFDATA2LSB (LE).
    db  1                          ; e_ident[6]     EI_VERSION = 1.
    db  0                          ; e_ident[7]     EI_OSABI = SYSV.
    db  0                          ; e_ident[8]     ABIVERSION.
    times 7 db 0                   ; e_ident[9..15] padding.
    dw  2                          ; e_type       = ET_EXEC.
    dw  0x3E                       ; e_machine    = EM_X86_64.
    dd  1                          ; e_version    = 1.
    dq  _start                     ; e_entry      = virtual address of _start.
    dq  phdr - ehdr                ; e_phoff      = 64.
    dq  0                          ; e_shoff      (no section headers).
    dd  0                          ; e_flags.
    dw  ehdr_size                  ; e_ehsize.
    dw  phdr_size                  ; e_phentsize.
    dw  1                          ; e_phnum      = one LOAD segment.
    dw  0                          ; e_shentsize.
    dw  0                          ; e_shnum.
    dw  0                          ; e_shstrndx.
ehdr_size   equ $ - ehdr           ; 64.

phdr:
    dd  1                          ; p_type    = PT_LOAD.
    dd  7                          ; p_flags   = PF_R|PF_W|PF_X.
    dq  0                          ; p_offset  = 0 (file start).
    dq  IMAGE_BASE                 ; p_vaddr.
    dq  IMAGE_BASE                 ; p_paddr.
    dq  file_end - ehdr            ; p_filesz  = size of on-file segment.
    dq  mem_end  - ehdr            ; p_memsz   > filesz  -> kernel zero-fills bss.
    dq  0x1000                     ; p_align.
phdr_size   equ $ - phdr           ; 56.

; =============================================================================
; Constants
; =============================================================================
%define SYS_read        0          ; Linux x86-64 syscall numbers (unistd_64.h).
%define SYS_write       1
%define SYS_open        2
%define SYS_close       3
%define SYS_mmap        9
%define SYS_exit        60

%define O_RDONLY        0
%define STDIN_FD        0
%define STDOUT_FD       1
%define STDERR_FD       2

%define PROT_READ       0x1
%define PROT_WRITE      0x2
%define PROT_EXEC       0x4
%define MAP_PRIVATE     0x02
%define MAP_ANONYMOUS   0x20

%define TAPE_SIZE       65536          ; 64 KiB tape (cells 0 .. 65535).
%define SRC_MAX         (1<<18)        ; 256 KiB upper bound on source size.
%define IR_MAX          (1<<15)        ; 32768 IR entries max.
%define IR_STRIDE       16             ; 16 bytes per IR entry (nice alignment).
%define CODE_MAX        (2*1024*1024)  ; 2 MiB of native code per program.
%define LOOP_STACK_MAX  512            ; deepest '[' nesting supported.
%define MUL_OFFSET_BIAS 256            ; centre for the mul_effects window.
%define MUL_BUF_SIZE    512            ; 512 i8 cells -> offsets -256..+255.

; IR opcodes (stored as a u8 in each entry's first byte).
%define OP_END     0
%define OP_ADD     1
%define OP_MOVP    2
%define OP_ZERO    3
%define OP_JZ      4
%define OP_JNZ     5
%define OP_WRITE   6
%define OP_READ    7
%define OP_MULBEG  8
%define OP_MULSET  9
%define OP_MULEND  10
%define OP_SCANR   11
%define OP_SCANL   12

; IR field byte-offsets inside a single 16-byte entry.
;   [ 0 ..  0]  op      u8
;   [ 1 ..  3]  pad
;   [ 4 ..  7]  off     i32      ; r12-relative cell offset (or IR index for jumps).
;   [ 8 .. 11]  val     i32      ; delta / factor / target IR index.
;   [12 .. 15]  aux     i32      ; code offset of this IR (filled in emit pass).
%define IR_OP_OFF   0
%define IR_OFF_OFF  4
%define IR_VAL_OFF  8
%define IR_AUX_OFF  12

; =============================================================================
; Error messages (in-file, part of the LOAD segment, same page as code).
; =============================================================================
msg_usage:    db "usage: bfasm <program.bf>", 10
msg_usage_len equ $ - msg_usage
msg_err_read: db "bfasm: cannot read source file", 10
msg_err_read_len equ $ - msg_err_read
msg_err_brak: db "bfasm: unbalanced brackets in source", 10
msg_err_brak_len equ $ - msg_err_brak
msg_err_mmap: db "bfasm: mmap failed", 10
msg_err_mmap_len equ $ - msg_err_mmap
msg_err_ir:   db "bfasm: IR buffer overflow", 10
msg_err_ir_len equ $ - msg_err_ir
msg_err_stk:  db "bfasm: loop stack overflow", 10
msg_err_stk_len equ $ - msg_err_stk
msg_err_code: db "bfasm: code buffer overflow (increase CODE_MAX)", 10
msg_err_code_len equ $ - msg_err_code

; =============================================================================
; Entry point
; =============================================================================
_start:
    ; Kernel hands us the initial stack:
    ;     [rsp+0]   argc
    ;     [rsp+8]   argv[0]
    ;     [rsp+16]  argv[1]
    ; No libc crt init -- we read the stack directly.
    mov     rax, [rsp]                  ; argc.
    cmp     rax, 2                      ; we need at least  <program.bf>.
    jl      .print_usage                ; fewer than 2 args = usage error.
    mov     rdi, [rsp + 16]             ; argv[1] = path string pointer.

    ; ---------- open(path, O_RDONLY, 0) ----------
    mov     eax, SYS_open               ; syscall 2.
    xor     esi, esi                    ; flags = O_RDONLY (0).
    xor     edx, edx                    ; mode unused for O_RDONLY.
    syscall                             ; fd returned in rax; -errno on error.
    test    rax, rax
    js      .err_read                   ; sign flag -> negative -> open failed.
    mov     r14, rax                    ; stash fd in callee-saved r14.

    ; ---------- read(fd, src_buf, SRC_MAX) ----------
    mov     rdi, r14                    ; arg0 = fd.
    mov     rsi, src_buf                ; arg1 = buffer (absolute address).
    mov     edx, SRC_MAX                ; arg2 = max bytes.
    xor     eax, eax                    ; syscall 0 = read.
    syscall
    test    rax, rax
    js      .err_read
    mov     [src_len], rax              ; length of source just read.

    ; ---------- close(fd) (best-effort; ignore return) ----------
    mov     rdi, r14
    mov     eax, SYS_close
    syscall

    ; ---------------------------------------------------------------------
    ; DEBUG SCAFFOLDING (commented out -- keep for future triage).
    ;
    ; Three argc-gated early exits let us bisect which stage crashes
    ; without needing a debugger:
    ;
    ;     argc >= 5    exit 111 BEFORE parse_source (stage0: read/close ok)
    ;     argc >= 4    dump raw IR bytes to stdout  (stage1: parser ok)
    ;     argc >= 3    dump emitted machine code    (stage2: emit ok)
    ;
    ; Usage:
    ;     ./bfasm prog.bf           -- normal run.
    ;     ./bfasm prog.bf x         -- dump machine code (pipe to ndisasm).
    ;     ./bfasm prog.bf x x       -- dump IR entries   (16-byte records).
    ;     ./bfasm prog.bf x x x     -- exit 111 pre-parse (confirm load).
    ;
    ; To enable, uncomment the block below (and the machine-code dump block
    ; further down, just before the CALL into the JIT).  The argc lives on
    ; the initial stack; [rsp] is still valid here because _start hasn't
    ; pushed anything yet.
    ; ---------------------------------------------------------------------
    ; mov     rcx, [rsp]                  ; argc.
    ; cmp     rcx, 5
    ; jl      .skip_pre
    ; mov     edi, 111
    ; mov     eax, SYS_exit
    ; syscall
    ; .skip_pre:

    ; ---------- parse source -> IR with all peephole passes ----------
    call    parse_source

    ; ---------------------------------------------------------------------
    ; Post-parse IR dump (argc>=4).  Size = ir_count * IR_STRIDE bytes.
    ; Companion python decoder:
    ;     OP_NAMES = {0:END,1:ADD,2:MOVP,3:ZERO,4:JZ,5:JNZ,6:WRITE,
    ;                 7:READ,8:MULBEG,9:MULSET,10:MULEND,11:SCANR,12:SCANL}
    ;     struct.unpack_from('<BxxxIiiI', ir, i*16) -> (op,_,off,val,aux)
    ; ---------------------------------------------------------------------
    ; mov     rcx, [rsp]
    ; cmp     rcx, 4
    ; jl      .skip_ir_dump
    ; mov     eax, SYS_write
    ; mov     edi, STDOUT_FD
    ; mov     rsi, ir_buf
    ; mov     rdx, [ir_count]
    ; imul    rdx, rdx, IR_STRIDE
    ; syscall
    ; xor     edi, edi
    ; mov     eax, SYS_exit
    ; syscall
    ; .skip_ir_dump:

    ; ---------- mmap(NULL, CODE_MAX, RWX, PRIV|ANON, -1, 0) ----------
    xor     edi, edi                    ; addr = NULL (kernel picks).
    mov     esi, CODE_MAX               ; length.
    mov     edx, PROT_READ | PROT_WRITE | PROT_EXEC
    mov     r10d, MAP_PRIVATE | MAP_ANONYMOUS
    mov     r8, -1                      ; fd = -1 (anon).
    xor     r9d, r9d                    ; offset = 0.
    mov     eax, SYS_mmap
    syscall
    cmp     rax, -4096                  ; -errno is in [-4095,-1] on failure.
    ja      .err_mmap
    mov     [code_base], rax
    lea     rdx, [rax + CODE_MAX]
    mov     [code_end], rdx

    ; ---------- lower IR -> machine code ----------
    call    emit_code

    ; ---------- allocate tape (MAP_ANON => zero-filled) ----------
    xor     edi, edi
    mov     esi, TAPE_SIZE
    mov     edx, PROT_READ | PROT_WRITE ; tape is never executed.
    mov     r10d, MAP_PRIVATE | MAP_ANONYMOUS
    mov     r8, -1
    xor     r9d, r9d
    mov     eax, SYS_mmap
    syscall
    cmp     rax, -4096
    ja      .err_mmap
    mov     [tape_base], rax

    ; ---------------------------------------------------------------------
    ; Optional machine-code dump (argc>=3).  Pipe stdout to:
    ;     ndisasm -b64 -
    ; to get a human-readable disassembly of the JIT output.
    ; ---------------------------------------------------------------------
    ; mov     rcx, [rsp]                  ; argc.
    ; cmp     rcx, 3
    ; jl      .no_dump
    ; mov     eax, SYS_write
    ; mov     edi, STDOUT_FD
    ; mov     rsi, [code_base]
    ; mov     rdx, [code_size]
    ; syscall
    ; xor     edi, edi
    ; mov     eax, SYS_exit
    ; syscall
    ; .no_dump:

    ; ---------- call into the JIT'd code, r12 = tape base ----------
    mov     r12, rax                    ; r12 = BF data pointer.
    mov     rax, [code_base]            ; entry = first byte of emitted code.
    call    rax                         ; runs until RET.

    ; ---------- exit(0) ----------
    xor     edi, edi                    ; status 0.
    mov     eax, SYS_exit
    syscall

.print_usage:
    mov     rsi, msg_usage              ; buf.
    mov     edx, msg_usage_len          ; len.
    mov     edi, STDERR_FD              ; fd 2 = stderr.
    mov     eax, SYS_write
    syscall
    mov     edi, 1                      ; exit code 1.
    mov     eax, SYS_exit
    syscall

.err_read:
    mov     rsi, msg_err_read
    mov     edx, msg_err_read_len
    jmp     .die

.err_mmap:
    mov     rsi, msg_err_mmap
    mov     edx, msg_err_mmap_len
    ; fallthrough
.die:
    mov     edi, STDERR_FD
    mov     eax, SYS_write
    syscall
    mov     edi, 1
    mov     eax, SYS_exit
    syscall

; =============================================================================
; parse_source
;   src_buf[0 .. src_len)  ->  ir_buf[0 .. ir_count)
;
; Single pass.  Live registers:
;     r8   = source index i.
;     r9   = source length n.
;     r10d = deferred pointer offset (compile-time delta folded into memory ops).
;     rbx  = transient byte under inspection.
; =============================================================================
parse_source:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15

    xor     eax, eax
    mov     [ir_count], rax             ; start empty.
    mov     [loop_sp],  rax

    xor     r8d, r8d                    ; i = 0.
    mov     r9,  [src_len]
    xor     r10d, r10d                  ; ptr_off = 0.

.loop:
    cmp     r8, r9
    jae     .done
    movzx   ebx, byte [src_buf + r8]    ; bl = src[i].

    cmp     bl, '+'
    je      .case_pm
    cmp     bl, '-'
    je      .case_pm
    cmp     bl, '>'
    je      .case_pt
    cmp     bl, '<'
    je      .case_pt
    cmp     bl, '.'
    je      .case_dot
    cmp     bl, ','
    je      .case_comma
    cmp     bl, '['
    je      .case_open
    cmp     bl, ']'
    je      .case_close

    inc     r8                          ; non-BF char: comment; skip.
    jmp     .loop

; ---------- '+' / '-' run-length compression ----------
.case_pm:
    xor     r11d, r11d                  ; delta accumulator (i32).
.pm_scan:
    cmp     r8, r9
    jae     .pm_emit
    movzx   ebx, byte [src_buf + r8]
    cmp     bl, '+'
    je      .pm_inc
    cmp     bl, '-'
    je      .pm_dec
    jmp     .pm_emit
.pm_inc:
    inc     r11d
    inc     r8
    jmp     .pm_scan
.pm_dec:
    dec     r11d
    inc     r8
    jmp     .pm_scan
.pm_emit:
    test    r11d, r11d                  ; cancel-out run = nothing.
    jz      .loop
    mov     edi, OP_ADD                 ; opcode.
    mov     esi, r10d                   ; cell offset (deferred).
    mov     edx, r11d                   ; delta.
    call    ir_emit_addlike             ; peephole-merge adjacent adds.
    jmp     .loop

; ---------- '>' / '<' run: only updates the deferred pointer offset ----------
.case_pt:
    xor     r11d, r11d                  ; local delta.
.pt_scan:
    cmp     r8, r9
    jae     .pt_done
    movzx   ebx, byte [src_buf + r8]
    cmp     bl, '>'
    je      .pt_inc
    cmp     bl, '<'
    je      .pt_dec
    jmp     .pt_done
.pt_inc:
    inc     r11d
    inc     r8
    jmp     .pt_scan
.pt_dec:
    dec     r11d
    inc     r8
    jmp     .pt_scan
.pt_done:
    add     r10d, r11d                  ; fold into the deferred ptr offset.
    jmp     .loop

; ---------- '.' -> write one byte ----------
.case_dot:
    mov     edi, OP_WRITE
    mov     esi, r10d
    xor     edx, edx
    call    ir_emit_generic
    inc     r8
    jmp     .loop

; ---------- ',' -> read one byte ----------
.case_comma:
    mov     edi, OP_READ
    mov     esi, r10d
    xor     edx, edx
    call    ir_emit_generic
    inc     r8
    jmp     .loop

; ---------- '[' -> pattern-match or open a generic loop ----------
.case_open:
    ; (1) Clear loop  [-] or [+]  ->  OP_ZERO.
    mov     rax, r9
    sub     rax, r8                     ; remaining bytes starting at '['.
    cmp     rax, 3
    jb      .open_generic
    movzx   eax, byte [src_buf + r8 + 1]
    cmp     al, '-'
    je      .open_maybe_clear
    cmp     al, '+'
    je      .open_maybe_clear
    jmp     .open_try_scan
.open_maybe_clear:
    cmp     byte [src_buf + r8 + 2], ']'
    jne     .open_try_scan
    mov     edi, OP_ZERO
    mov     esi, r10d
    xor     edx, edx
    call    ir_emit_generic
    add     r8, 3
    jmp     .loop

    ; (2) Scan loop  [>]  /  [<]  -> OP_SCANR / OP_SCANL.
.open_try_scan:
    movzx   eax, byte [src_buf + r8 + 1]
    cmp     al, '>'
    je      .open_maybe_scanr
    cmp     al, '<'
    je      .open_maybe_scanl
    jmp     .open_try_mul
.open_maybe_scanr:
    cmp     byte [src_buf + r8 + 2], ']'
    jne     .open_try_mul
    call    commit_ptr_off              ; scan loops move the pointer; commit.
    mov     edi, OP_SCANR
    xor     esi, esi
    xor     edx, edx
    call    ir_emit_generic
    add     r8, 3
    jmp     .loop
.open_maybe_scanl:
    cmp     byte [src_buf + r8 + 2], ']'
    jne     .open_try_mul
    call    commit_ptr_off
    mov     edi, OP_SCANL
    xor     esi, esi
    xor     edx, edx
    call    ir_emit_generic
    add     r8, 3
    jmp     .loop

    ; (3) Multiply / copy loop recogniser.
.open_try_mul:
    mov     rdi, r8
    call    detect_mul_loop             ; -> rax = ']' index, or -1.
    cmp     rax, -1
    je      .open_generic
    mov     r14, rax                    ; save ']' index.

    ; Emit OP_MULBEG with counter at current deferred offset.
    mov     edi, OP_MULBEG
    mov     esi, r10d
    xor     edx, edx
    call    ir_emit_generic

    ; Walk mul_effects[] and emit one OP_MULSET per non-zero non-counter cell.
    xor     r13d, r13d                  ; index k = 0.
.mul_emit_loop:
    cmp     r13d, MUL_BUF_SIZE
    jae     .mul_emit_done
    movsx   edx, byte [mul_effects + r13]   ; signed factor.
    test    edx, edx
    jz      .mul_emit_next
    mov     ecx, r13d                   ; offset relative to counter cell.
    sub     ecx, MUL_OFFSET_BIAS        ;   = k - 256.
    add     ecx, r10d                   ;   + deferred ptr offset.
    mov     edi, OP_MULSET
    mov     esi, ecx
    ; edx = factor already.
    call    ir_emit_generic
    mov     byte [mul_effects + r13], 0  ; clear for next detection.
.mul_emit_next:
    inc     r13d
    jmp     .mul_emit_loop
.mul_emit_done:
    mov     edi, OP_MULEND               ; emit counter zero + patch jz.
    mov     esi, r10d
    xor     edx, edx
    call    ir_emit_generic
    lea     r8, [r14 + 1]                ; resume after ']'.
    jmp     .loop

    ; (4) Generic loop.
.open_generic:
    call    commit_ptr_off               ; body starts at ptr offset 0.
    mov     rax, [loop_sp]
    cmp     rax, LOOP_STACK_MAX
    jae     .err_stk
    mov     rcx, [ir_count]              ; record index of the JZ entry.
    mov     [loop_stack + rax*8], rcx
    inc     rax
    mov     [loop_sp], rax
    mov     edi, OP_JZ
    xor     esi, esi                     ; offset 0.
    xor     edx, edx                     ; target patched at matching ']'.
    call    ir_emit_generic
    inc     r8
    jmp     .loop

; ---------- ']' -> close the innermost open loop ----------
.case_close:
    call    commit_ptr_off
    mov     rax, [loop_sp]
    test    rax, rax
    jz      .err_brak
    dec     rax
    mov     [loop_sp], rax
    mov     r14, [loop_stack + rax*8]    ; r14 = IR index of the JZ (callee-saved,
                                         ; survives ir_emit_generic's clobbers).

    mov     edi, OP_JNZ
    xor     esi, esi
    mov     rdx, r14
    inc     rdx                          ; jump back to body start (just after JZ).
    call    ir_emit_generic

    ; Patch the JZ's target field to point past our just-emitted JNZ.
    mov     rdx, [ir_count]              ; ir_count is 1-past the JNZ now.
    mov     rax, r14
    imul    rax, rax, IR_STRIDE
    mov     [ir_buf + rax + IR_VAL_OFF], edx
    inc     r8
    jmp     .loop

.done:
    call    commit_ptr_off
    mov     rax, [loop_sp]
    test    rax, rax
    jnz     .err_brak
    mov     edi, OP_END
    xor     esi, esi
    xor     edx, edx
    call    ir_emit_generic

    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

.err_brak:
    mov     rsi, msg_err_brak
    mov     edx, msg_err_brak_len
    jmp     _start.die
.err_stk:
    mov     rsi, msg_err_stk
    mov     edx, msg_err_stk_len
    jmp     _start.die

; =============================================================================
; ir_emit_generic(edi=op, esi=off, edx=val)
;   Append a fresh IR entry.  Dies on overflow.
; =============================================================================
ir_emit_generic:
    mov     rax, [ir_count]
    cmp     rax, IR_MAX
    jae     .overflow
    mov     rcx, rax
    imul    rcx, rcx, IR_STRIDE          ; byte offset into ir_buf.
    add     rcx, ir_buf                  ; absolute address of entry.
    mov     [rcx + IR_OP_OFF],  dil      ; u8 opcode.
    mov     byte [rcx + IR_OP_OFF + 1], 0   ; clear pad byte 1.
    mov     word [rcx + IR_OP_OFF + 2], 0   ; clear pad bytes 2..3.
    mov     [rcx + IR_OFF_OFF], esi      ; i32 offset.
    mov     [rcx + IR_VAL_OFF], edx      ; i32 value.
    mov     dword [rcx + IR_AUX_OFF], 0  ; aux reset.
    inc     rax
    mov     [ir_count], rax
    ret
.overflow:
    mov     rsi, msg_err_ir
    mov     edx, msg_err_ir_len
    jmp     _start.die

; =============================================================================
; ir_emit_addlike(edi=OP_ADD, esi=off, edx=val)
;   If the most recent IR entry is also OP_ADD at the same offset, fuse.
;   Fused delta of zero drops the entry entirely.
; =============================================================================
ir_emit_addlike:
    mov     rax, [ir_count]
    test    rax, rax
    jz      ir_emit_generic
    mov     rcx, rax
    dec     rcx
    imul    rcx, rcx, IR_STRIDE
    add     rcx, ir_buf
    cmp     byte [rcx + IR_OP_OFF], OP_ADD
    jne     ir_emit_generic
    mov     r11d, [rcx + IR_OFF_OFF]
    cmp     r11d, esi
    jne     ir_emit_generic
    add     [rcx + IR_VAL_OFF], edx      ; fuse deltas.
    mov     r11d, [rcx + IR_VAL_OFF]
    test    r11d, r11d
    jnz     .done
    dec     qword [ir_count]             ; delta cancelled; drop entry.
.done:
    ret

; =============================================================================
; commit_ptr_off  --  flush any deferred pointer delta as OP_MOVP (possibly
; fused with a preceding OP_MOVP) and clear r10d.
; =============================================================================
commit_ptr_off:
    test    r10d, r10d
    jz      .ret
    mov     rax, [ir_count]
    test    rax, rax
    jz      .plain
    mov     rcx, rax
    dec     rcx
    imul    rcx, rcx, IR_STRIDE
    add     rcx, ir_buf
    cmp     byte [rcx + IR_OP_OFF], OP_MOVP
    jne     .plain
    add     [rcx + IR_VAL_OFF], r10d
    mov     r11d, [rcx + IR_VAL_OFF]
    test    r11d, r11d
    jnz     .clear
    dec     qword [ir_count]
    jmp     .clear
.plain:
    mov     edi, OP_MOVP
    xor     esi, esi
    mov     edx, r10d
    call    ir_emit_generic
.clear:
    xor     r10d, r10d
.ret:
    ret

; =============================================================================
; detect_mul_loop(rdi = source index of '[')
;   -> rax = index of matching ']' on success, with mul_effects populated.
;      rax = -1 if not a simple mul-loop shape.
; =============================================================================
detect_mul_loop:
    push    rbx
    push    r12
    push    r13
    push    r14

    mov     r14, rdi                     ; remember '[' index.

    ; Zero mul_effects[] with rep stosq.
    mov     rdi, mul_effects
    xor     eax, eax
    mov     ecx, MUL_BUF_SIZE / 8
    rep stosq                            ; ABI: DF = 0 at process start.

    mov     r12, [src_len]
    mov     r13, r14
    inc     r13                          ; scan after '['.
    xor     ebx, ebx                     ; rel_offset = 0.

.scan:
    cmp     r13, r12
    jae     .fail
    movzx   eax, byte [src_buf + r13]
    cmp     al, ']'
    je      .endloop
    cmp     al, '+'
    je      .plus
    cmp     al, '-'
    je      .minus
    cmp     al, '>'
    je      .right
    cmp     al, '<'
    je      .left
    cmp     al, '['
    je      .fail
    cmp     al, ','
    je      .fail
    cmp     al, '.'
    je      .fail
    inc     r13                          ; comment char.
    jmp     .scan

.plus:
    movsxd  rax, ebx                      ; sign-extend signed i32 rel_offset into i64.
    add     rax, MUL_OFFSET_BIAS
    inc     byte [mul_effects + rax]
    inc     r13
    jmp     .scan
.minus:
    movsxd  rax, ebx                      ; sign-extend signed i32 rel_offset into i64.
    add     rax, MUL_OFFSET_BIAS
    dec     byte [mul_effects + rax]
    inc     r13
    jmp     .scan
.right:
    inc     ebx
    cmp     ebx, MUL_OFFSET_BIAS - 1
    jg      .fail
    inc     r13
    jmp     .scan
.left:
    dec     ebx
    cmp     ebx, -MUL_OFFSET_BIAS
    jl      .fail
    inc     r13
    jmp     .scan

.endloop:
    test    ebx, ebx                     ; net ptr motion must be 0.
    jnz     .fail
    movsx   eax, byte [mul_effects + MUL_OFFSET_BIAS]
    cmp     eax, -1
    jne     .fail                        ; counter must decrement by 1/iter.
    mov     byte [mul_effects + MUL_OFFSET_BIAS], 0
    mov     rax, r13                     ; return ']' index.
    jmp     .ret
.fail:
    mov     rax, -1
.ret:
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

; =============================================================================
; emit_code  --  walk ir_buf, assemble x86-64 machine code into code_base.
;
; Two passes:
;   Pass 1: emit instructions; stash each IR's starting code offset in its
;           aux field.  Forward jumps (OP_JZ) get a zero rel32 placeholder,
;           and OP_MULBEG's JZ gets patched when we reach the matching MULEND.
;   Pass 2: walk IR one more time and back-patch every OP_JZ / OP_JNZ rel32
;           using the aux-table to compute displacements.
;
; Live registers in pass 1:
;     rbx = current emission cursor (absolute pointer).
;     r15 = code_base.
;     r13 = IR index.
;     r14 = &ir_buf[r13].
; =============================================================================
emit_code:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15

    mov     r15, [code_base]
    mov     rbx, r15
    xor     r13d, r13d

.p1_loop:
    mov     rax, [ir_count]
    cmp     r13, rax
    jae     .p1_done
    mov     rax, r13
    imul    rax, rax, IR_STRIDE
    lea     r14, [ir_buf + rax]

    mov     rax, rbx
    sub     rax, r15
    mov     [r14 + IR_AUX_OFF], eax      ; record code offset for this IR.

    movzx   eax, byte [r14 + IR_OP_OFF]
    cmp     al, OP_END
    je      .emit_end
    cmp     al, OP_ADD
    je      .emit_add
    cmp     al, OP_MOVP
    je      .emit_movp
    cmp     al, OP_ZERO
    je      .emit_zero
    cmp     al, OP_JZ
    je      .emit_jz
    cmp     al, OP_JNZ
    je      .emit_jnz
    cmp     al, OP_WRITE
    je      .emit_write
    cmp     al, OP_READ
    je      .emit_read
    cmp     al, OP_MULBEG
    je      .emit_mulbeg
    cmp     al, OP_MULSET
    je      .emit_mulset
    cmp     al, OP_MULEND
    je      .emit_mulend
    cmp     al, OP_SCANR
    je      .emit_scanr
    cmp     al, OP_SCANL
    je      .emit_scanl
    jmp     .next

; ------- OP_END -------
.emit_end:
    mov     rcx, 1
    call    chk_space
    mov     byte [rbx], 0xC3             ; near ret.
    inc     rbx
    jmp     .next

; ------- OP_ADD: add byte [r12+disp], imm8 -------
;  Opcode 80 /0 ib (ADD r/m8, imm8), REX.B=1 for r12.  ModR/M reg field
;  is the /0 opcode extension = 000.  rm=100 always means "use SIB", and
;  the SIB of 0x24 encodes index=100(none), base=100(r12).
.emit_add:
    mov     esi, [r14 + IR_OFF_OFF]
    mov     edx, [r14 + IR_VAL_OFF]
    call    emit_add_mem_imm
    jmp     .next

; ------- OP_MOVP: add r12, imm (sign-ext 8 or 32) -------
.emit_movp:
    mov     esi, [r14 + IR_VAL_OFF]
    call    emit_addq_r12_imm
    jmp     .next

; ------- OP_ZERO: mov byte [r12+disp], 0 -------
;  Opcode C6 /0 ib (MOV r/m8, imm8), REX.B=1.
.emit_zero:
    mov     esi, [r14 + IR_OFF_OFF]
    xor     edx, edx
    call    emit_mov_mem_imm
    jmp     .next

; ------- OP_JZ: cmp byte [r12+disp32], 0 ; je rel32 -------
;  The cmp is emitted in its fixed disp32 form so the rel32 patch offset
;  from the start of the IR's emitted bytes is always 9+2 = 11.
.emit_jz:
    mov     esi, [r14 + IR_OFF_OFF]
    call    emit_cmp_mem0_disp32
    mov     rcx, 6
    call    chk_space
    mov     byte [rbx], 0x0F
    inc     rbx
    mov     byte [rbx], 0x84             ; JE rel32.
    inc     rbx
    mov     dword [rbx], 0               ; rel32 placeholder.
    add     rbx, 4
    jmp     .next

; ------- OP_JNZ: cmp byte [r12+disp32], 0 ; jne rel32 -------
.emit_jnz:
    mov     esi, [r14 + IR_OFF_OFF]
    call    emit_cmp_mem0_disp32
    mov     rcx, 6
    call    chk_space
    mov     byte [rbx], 0x0F
    inc     rbx
    mov     byte [rbx], 0x85             ; JNE rel32.
    inc     rbx
    mov     dword [rbx], 0
    add     rbx, 4
    jmp     .next

; ------- OP_WRITE: write(1, r12+off, 1) -------
;  Emits:
;     lea rsi, [r12+off]    (or mov rsi, r12 when off==0).
;     push 1 ; pop rax      (eax = 1 = SYS_write).
;     push 1 ; pop rdi      (edi = 1 = STDOUT).
;     push 1 ; pop rdx      (edx = 1 = count).
;     syscall.
.emit_write:
    mov     esi, [r14 + IR_OFF_OFF]
    call    emit_lea_rsi
    mov     rcx, 11
    call    chk_space
    mov     byte [rbx], 0x6A            ; push imm8.
    inc     rbx
    mov     byte [rbx], 0x01
    inc     rbx
    mov     byte [rbx], 0x58            ; pop rax.
    inc     rbx
    mov     byte [rbx], 0x6A
    inc     rbx
    mov     byte [rbx], 0x01
    inc     rbx
    mov     byte [rbx], 0x5F            ; pop rdi.
    inc     rbx
    mov     byte [rbx], 0x6A
    inc     rbx
    mov     byte [rbx], 0x01
    inc     rbx
    mov     byte [rbx], 0x5A            ; pop rdx.
    inc     rbx
    mov     byte [rbx], 0x0F
    inc     rbx
    mov     byte [rbx], 0x05            ; syscall.
    inc     rbx
    jmp     .next

; ------- OP_READ: read(0, r12+off, 1); on EOF store 0xFF -------
;  xor eax, eax                     ; syscall 0 = read.
;  xor edi, edi                     ; fd = 0 (stdin).
;  push 1 ; pop rdx                 ; count = 1.
;  syscall                          ; rax = bytes read.
;  test rax, rax                    ; EOF?
;  jnz  +3                          ; if bytes read, skip.
;  mov  byte [rsi], 0xFF            ; EOF -> cell = -1 (255).  Many canonical
;                                     BF programs (e.g. Cristofani rot13)
;                                     spin forever unless `,` at EOF leaves a
;                                     value that `+` wraps to zero.  The
;                                     alternative -- "leave cell unchanged"
;                                     -- is less common; -1 is the pragmatic
;                                     choice and terminates those loops.
.emit_read:
    mov     esi, [r14 + IR_OFF_OFF]
    call    emit_lea_rsi
    mov     rcx, 10
    call    chk_space
    mov     byte [rbx], 0x31
    inc     rbx
    mov     byte [rbx], 0xC0            ; xor eax, eax.
    inc     rbx
    mov     byte [rbx], 0x31
    inc     rbx
    mov     byte [rbx], 0xFF            ; xor edi, edi.
    inc     rbx
    mov     byte [rbx], 0x6A
    inc     rbx
    mov     byte [rbx], 0x01
    inc     rbx
    mov     byte [rbx], 0x5A            ; pop rdx -> edx = 1.
    inc     rbx
    mov     byte [rbx], 0x0F
    inc     rbx
    mov     byte [rbx], 0x05            ; syscall.
    inc     rbx
    ; Post-syscall EOF fixup: 8 bytes.
    mov     rcx, 8
    call    chk_space
    mov     byte [rbx], 0x48            ; REX.W.
    inc     rbx
    mov     byte [rbx], 0x85            ; TEST r/m64, r64.
    inc     rbx
    mov     byte [rbx], 0xC0            ; ModR/M 11 000 000 -> test rax, rax.
    inc     rbx
    mov     byte [rbx], 0x75            ; JNZ rel8.
    inc     rbx
    mov     byte [rbx], 0x03            ; skip the next 3 bytes.
    inc     rbx
    mov     byte [rbx], 0xC6            ; MOV r/m8, imm8.
    inc     rbx
    mov     byte [rbx], 0x06            ; ModR/M 00 000 110 -> [rsi].
    inc     rbx
    mov     byte [rbx], 0xFF            ; imm8 = 0xFF (EOF sentinel).
    inc     rbx
    jmp     .next

; ------- OP_MULBEG: movzx eax, [r12+cnt]; test al,al; jz .skip -------
.emit_mulbeg:
    mov     esi, [r14 + IR_OFF_OFF]
    call    emit_movzx_eax_r12
    mov     rcx, 2
    call    chk_space
    mov     byte [rbx], 0x84             ; TEST r/m8, r8.
    inc     rbx
    mov     byte [rbx], 0xC0             ; ModR/M 11 000 000 -> test al, al.
    inc     rbx
    mov     rcx, 6
    call    chk_space
    mov     byte [rbx], 0x0F
    inc     rbx
    mov     byte [rbx], 0x84             ; JZ rel32 (to be patched at MULEND).
    inc     rbx
    mov     rax, rbx                     ; remember rel32 slot.
    sub     rax, r15
    mov     [mul_patch], eax
    mov     dword [rbx], 0
    add     rbx, 4
    jmp     .next

; ------- OP_MULSET -------
;   factor == +1  ->   add byte [r12+t], al.
;   factor == -1  ->   sub byte [r12+t], al.
;   else          ->   imul ebx, eax, f8 ;  add byte [r12+t], bl.
.emit_mulset:
    mov     esi, [r14 + IR_OFF_OFF]
    movsx   edx, byte [r14 + IR_VAL_OFF]
    cmp     edx, 1
    je      .mulset_add1
    cmp     edx, -1
    je      .mulset_sub1
    mov     rcx, 3
    call    chk_space
    mov     byte [rbx], 0x6B             ; IMUL r32, r/m32, imm8.
    inc     rbx
    mov     byte [rbx], 0xD8             ; ModR/M 11 011 000 -> ebx, eax.
    inc     rbx
    mov     al, dl
    mov     [rbx], al                    ; imm8 = factor.
    inc     rbx
    mov     r8b, 0x00                    ; opcode: ADD r/m8, r8.
    mov     r9b, 0x03                    ; reg field for bl.
    call    emit_mem_r8reg
    jmp     .next
.mulset_add1:
    mov     r8b, 0x00                    ; ADD r/m8, r8.
    mov     r9b, 0x00                    ; reg field for al.
    call    emit_mem_r8reg
    jmp     .next
.mulset_sub1:
    mov     r8b, 0x28                    ; SUB r/m8, r8.
    mov     r9b, 0x00
    call    emit_mem_r8reg
    jmp     .next

; ------- OP_MULEND: zero counter + patch MULBEG's JZ -------
.emit_mulend:
    mov     esi, [r14 + IR_OFF_OFF]
    xor     edx, edx
    call    emit_mov_mem_imm             ; mov byte [r12+cnt], 0.
    mov     eax, [mul_patch]             ; rel32 slot offset.
    mov     rcx, rbx
    sub     rcx, r15                     ; current end of code.
    sub     ecx, eax                     ; rel = target - patch.
    sub     ecx, 4                       ; minus rel32 width (rip is at patch+4).
    mov     rdx, r15
    add     rdx, rax
    mov     [rdx], ecx                   ; write the patched rel32.
    jmp     .next

; ------- OP_SCANR: mov rdi,r12 ; xor eax,eax ; mov ecx,TAPE_SIZE ;
;                   cld ; repne scasb ; lea r12,[rdi-1] -------
.emit_scanr:
    mov     rcx, 14
    call    chk_space
    mov     byte [rbx], 0x4C             ; REX.W=1 REX.R=1.
    inc     rbx
    mov     byte [rbx], 0x89             ; MOV r/m64, r64.
    inc     rbx
    mov     byte [rbx], 0xE7             ; ModR/M 11 100 111 -> rm=rdi, reg=r12.
    inc     rbx
    mov     byte [rbx], 0x31
    inc     rbx
    mov     byte [rbx], 0xC0             ; xor eax, eax.
    inc     rbx
    mov     byte [rbx], 0xB9             ; mov ecx, imm32.
    inc     rbx
    mov     dword [rbx], TAPE_SIZE
    add     rbx, 4
    mov     byte [rbx], 0xFC             ; cld.
    inc     rbx
    mov     byte [rbx], 0xF2             ; REPNE.
    inc     rbx
    mov     byte [rbx], 0xAE             ; SCASB.
    inc     rbx
    mov     rcx, 4
    call    chk_space
    mov     byte [rbx], 0x4C             ; REX.W=1 R=1 X=0 B=0 (r12 reg, rdi rm).
    inc     rbx
    mov     byte [rbx], 0x8D             ; LEA.
    inc     rbx
    mov     byte [rbx], 0x67             ; ModR/M 01 100 111 -> disp8 [rdi], reg=r12.
    inc     rbx
    mov     byte [rbx], 0xFF             ; disp8 = -1.
    inc     rbx
    jmp     .next

; ------- OP_SCANL: same as above but std then cld at end, disp8 = +1 -------
.emit_scanl:
    mov     rcx, 14
    call    chk_space
    mov     byte [rbx], 0x4C
    inc     rbx
    mov     byte [rbx], 0x89
    inc     rbx
    mov     byte [rbx], 0xE7             ; mov rdi, r12.
    inc     rbx
    mov     byte [rbx], 0x31
    inc     rbx
    mov     byte [rbx], 0xC0
    inc     rbx
    mov     byte [rbx], 0xB9
    inc     rbx
    mov     dword [rbx], TAPE_SIZE
    add     rbx, 4
    mov     byte [rbx], 0xFD             ; std (backward).
    inc     rbx
    mov     byte [rbx], 0xF2
    inc     rbx
    mov     byte [rbx], 0xAE             ; repne scasb backward.
    inc     rbx
    mov     rcx, 5
    call    chk_space
    mov     byte [rbx], 0xFC             ; cld  (restore forward!).
    inc     rbx
    mov     byte [rbx], 0x4C             ; REX.W=1 R=1 X=0 B=0 (r12 reg, rdi rm).
    inc     rbx
    mov     byte [rbx], 0x8D
    inc     rbx
    mov     byte [rbx], 0x67             ; ModR/M 01 100 111 -> disp8 [rdi], reg=r12.
    inc     rbx
    mov     byte [rbx], 0x01             ; disp8 = +1.
    inc     rbx
    jmp     .next

.next:
    inc     r13
    jmp     .p1_loop

.p1_done:
    ; Pass 2: patch JZ / JNZ rel32 fields.
    xor     r13d, r13d
.p2_loop:
    mov     rax, [ir_count]
    cmp     r13, rax
    jae     .p2_done
    mov     rax, r13
    imul    rax, rax, IR_STRIDE
    lea     r14, [ir_buf + rax]
    movzx   eax, byte [r14 + IR_OP_OFF]
    cmp     al, OP_JZ
    je      .p2_patch
    cmp     al, OP_JNZ
    je      .p2_patch
    inc     r13
    jmp     .p2_loop
.p2_patch:
    ; OP_JZ / OP_JNZ emit:
    ;   9 bytes  cmp byte [r12+disp32], 0
    ;   2 bytes  0F 8x
    ;   4 bytes  rel32
    mov     eax, [r14 + IR_AUX_OFF]      ; this op's start offset.
    add     eax, 11                      ; patch site = +11.
    mov     ecx, [r14 + IR_VAL_OFF]      ; target IR index.
    mov     rdx, rcx
    imul    rdx, rdx, IR_STRIDE
    mov     edx, [ir_buf + rdx + IR_AUX_OFF]
    sub     edx, eax                     ; rel = target - patch.
    sub     edx, 4                       ; minus 4 (rip at end of insn).
    mov     rcx, r15
    add     rcx, rax                     ; absolute address of rel32 slot.
    mov     [rcx], edx
    inc     r13
    jmp     .p2_loop

.p2_done:
    mov     rax, rbx
    sub     rax, r15
    mov     [code_size], rax            ; export final code length for dump mode.
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

; =============================================================================
; Emission helpers.  All take rbx = code cursor; all advance rbx; all
; call chk_space first.  chk_space reads the count from rcx.
; =============================================================================

; chk_space(rcx = bytes required)
chk_space:
    mov     rax, rbx
    add     rax, rcx
    cmp     rax, [code_end]
    ja      .full
    ret
.full:
    mov     rsi, msg_err_code
    mov     edx, msg_err_code_len
    jmp     _start.die

; emit_add_mem_imm(esi = disp, edx = imm8 (low byte))
;   add byte [r12+disp], imm8
emit_add_mem_imm:
    mov     rcx, 2
    call    chk_space
    mov     byte [rbx], 0x41            ; REX.B.
    inc     rbx
    mov     byte [rbx], 0x80            ; ADD r/m8, imm8  (/0).
    inc     rbx
    test    esi, esi
    jz      .d0
    movsx   eax, sil
    cmp     eax, esi
    jne     .d32
.d8:
    mov     rcx, 3
    call    chk_space
    mov     byte [rbx], 0x44            ; mod=01 reg=0 rm=100 (sib+disp8).
    inc     rbx
    mov     byte [rbx], 0x24            ; sib.
    inc     rbx
    mov     al, sil
    mov     [rbx], al                   ; disp8.
    inc     rbx
    mov     al, dl
    mov     [rbx], al                   ; imm8.
    inc     rbx
    ret
.d0:
    mov     rcx, 3
    call    chk_space
    mov     byte [rbx], 0x04            ; mod=00 reg=0 rm=100.
    inc     rbx
    mov     byte [rbx], 0x24
    inc     rbx
    mov     al, dl
    mov     [rbx], al                   ; imm8.
    inc     rbx
    ret
.d32:
    mov     rcx, 6
    call    chk_space
    mov     byte [rbx], 0x84            ; mod=10 reg=0 rm=100.
    inc     rbx
    mov     byte [rbx], 0x24
    inc     rbx
    mov     [rbx], esi                  ; disp32.
    add     rbx, 4
    mov     al, dl
    mov     [rbx], al                   ; imm8.
    inc     rbx
    ret

; emit_mov_mem_imm(esi = disp, edx = imm8)
;   mov byte [r12+disp], imm8
emit_mov_mem_imm:
    mov     rcx, 2
    call    chk_space
    mov     byte [rbx], 0x41            ; REX.B.
    inc     rbx
    mov     byte [rbx], 0xC6            ; MOV r/m8, imm8  (/0).
    inc     rbx
    test    esi, esi
    jz      .d0
    movsx   eax, sil
    cmp     eax, esi
    jne     .d32
.d8:
    mov     rcx, 3
    call    chk_space
    mov     byte [rbx], 0x44
    inc     rbx
    mov     byte [rbx], 0x24
    inc     rbx
    mov     al, sil
    mov     [rbx], al
    inc     rbx
    mov     al, dl
    mov     [rbx], al
    inc     rbx
    ret
.d0:
    mov     rcx, 3
    call    chk_space
    mov     byte [rbx], 0x04
    inc     rbx
    mov     byte [rbx], 0x24
    inc     rbx
    mov     al, dl
    mov     [rbx], al
    inc     rbx
    ret
.d32:
    mov     rcx, 6
    call    chk_space
    mov     byte [rbx], 0x84
    inc     rbx
    mov     byte [rbx], 0x24
    inc     rbx
    mov     [rbx], esi
    add     rbx, 4
    mov     al, dl
    mov     [rbx], al
    inc     rbx
    ret

; emit_addq_r12_imm(esi = i32 delta)
;   add r12, imm  -- imm8 if it fits, else imm32.  Skips when delta=0.
;   Encodings:
;     imm8:  49 83 C4 ib           (ADD r/m64, imm8  with sign extension).
;     imm32: 49 81 C4 id           (ADD r/m64, imm32 with sign extension).
emit_addq_r12_imm:
    test    esi, esi
    jz      .skip
    movsx   eax, sil
    cmp     eax, esi
    jne     .imm32
.imm8:
    mov     rcx, 4
    call    chk_space
    mov     byte [rbx], 0x49
    inc     rbx
    mov     byte [rbx], 0x83
    inc     rbx
    mov     byte [rbx], 0xC4            ; ModR/M 11 000 100 -> r12.
    inc     rbx
    mov     al, sil
    mov     [rbx], al
    inc     rbx
    ret
.imm32:
    mov     rcx, 7
    call    chk_space
    mov     byte [rbx], 0x49
    inc     rbx
    mov     byte [rbx], 0x81
    inc     rbx
    mov     byte [rbx], 0xC4
    inc     rbx
    mov     [rbx], esi
    add     rbx, 4
.skip:
    ret

; emit_cmp_mem0_disp32(esi = disp)
;   cmp byte [r12+disp32], 0   in fixed 9-byte form.
;   REX.B=1 | 80 /7 | modrm 0xBC | sib 0x24 | disp32 | imm8 0.
emit_cmp_mem0_disp32:
    mov     rcx, 9
    call    chk_space
    mov     byte [rbx], 0x41
    inc     rbx
    mov     byte [rbx], 0x80
    inc     rbx
    mov     byte [rbx], 0xBC
    inc     rbx
    mov     byte [rbx], 0x24
    inc     rbx
    mov     [rbx], esi
    add     rbx, 4
    mov     byte [rbx], 0x00
    inc     rbx
    ret

; emit_lea_rsi(esi = disp)
;   Shortest form of  rsi = r12 + disp.
;   disp == 0 -> mov rsi, r12   (3 bytes).
;   else disp8/disp32 lea forms.
emit_lea_rsi:
    test    esi, esi
    jnz     .nz
    mov     rcx, 3
    call    chk_space
    mov     byte [rbx], 0x4C            ; REX.W=1 R=1.
    inc     rbx
    mov     byte [rbx], 0x89            ; MOV r/m64, r64.
    inc     rbx
    mov     byte [rbx], 0xE6            ; ModR/M 11 100 110 -> rm=rsi, reg=r12.
    inc     rbx
    ret
.nz:
    movsx   eax, sil
    cmp     eax, esi
    jne     .d32
.d8:
    mov     rcx, 5
    call    chk_space
    mov     byte [rbx], 0x49
    inc     rbx
    mov     byte [rbx], 0x8D            ; LEA.
    inc     rbx
    mov     byte [rbx], 0x74            ; mod=01 reg=110 rm=100.
    inc     rbx
    mov     byte [rbx], 0x24
    inc     rbx
    mov     al, sil
    mov     [rbx], al
    inc     rbx
    ret
.d32:
    mov     rcx, 8
    call    chk_space
    mov     byte [rbx], 0x49
    inc     rbx
    mov     byte [rbx], 0x8D
    inc     rbx
    mov     byte [rbx], 0xB4            ; mod=10 reg=110 rm=100.
    inc     rbx
    mov     byte [rbx], 0x24
    inc     rbx
    mov     [rbx], esi
    add     rbx, 4
    ret

; emit_movzx_eax_r12(esi = disp)
;   movzx eax, byte [r12+disp].
emit_movzx_eax_r12:
    mov     rcx, 3
    call    chk_space
    mov     byte [rbx], 0x41            ; REX.B.
    inc     rbx
    mov     byte [rbx], 0x0F
    inc     rbx
    mov     byte [rbx], 0xB6            ; MOVZX r32, r/m8.
    inc     rbx
    test    esi, esi
    jz      .d0
    movsx   eax, sil
    cmp     eax, esi
    jne     .d32
.d8:
    mov     rcx, 3
    call    chk_space
    mov     byte [rbx], 0x44            ; mod=01 reg=000(eax) rm=100.
    inc     rbx
    mov     byte [rbx], 0x24
    inc     rbx
    mov     al, sil
    mov     [rbx], al
    inc     rbx
    ret
.d0:
    mov     rcx, 2
    call    chk_space
    mov     byte [rbx], 0x04
    inc     rbx
    mov     byte [rbx], 0x24
    inc     rbx
    ret
.d32:
    mov     rcx, 6
    call    chk_space
    mov     byte [rbx], 0x84
    inc     rbx
    mov     byte [rbx], 0x24
    inc     rbx
    mov     [rbx], esi
    add     rbx, 4
    ret

; emit_mem_r8reg(esi = disp, r8b = opcode byte, r9b = reg field 0..7)
;   Emits   <op> byte [r12+disp], <reg>.
;   Accepts opcodes 00 (ADD) and 28 (SUB).  REX.B=1 always (for r12).
;   ModR/M's "reg" field is taken from r9b (e.g. 0 = al, 3 = bl).
emit_mem_r8reg:
    mov     rcx, 2
    call    chk_space
    mov     byte [rbx], 0x41            ; REX.B=1.  (REX.R not needed since r9b <= 3.)
    inc     rbx
    mov     [rbx], r8b                  ; opcode (00 or 28).
    inc     rbx
    test    esi, esi
    jz      .d0
    movsx   eax, sil
    cmp     eax, esi
    jne     .d32
.d8:
    mov     rcx, 3
    call    chk_space
    mov     al, r9b
    shl     al, 3                       ; reg field shifted into bits 5..3.
    or      al, 0x44                    ; mod=01 rm=100.
    mov     [rbx], al
    inc     rbx
    mov     byte [rbx], 0x24
    inc     rbx
    mov     al, sil
    mov     [rbx], al
    inc     rbx
    ret
.d0:
    mov     rcx, 2
    call    chk_space
    mov     al, r9b
    shl     al, 3
    or      al, 0x04                    ; mod=00 rm=100.
    mov     [rbx], al
    inc     rbx
    mov     byte [rbx], 0x24
    inc     rbx
    ret
.d32:
    mov     rcx, 6
    call    chk_space
    mov     al, r9b
    shl     al, 3
    or      al, 0x84                    ; mod=10 rm=100.
    mov     [rbx], al
    inc     rbx
    mov     byte [rbx], 0x24
    inc     rbx
    mov     [rbx], esi
    add     rbx, 4
    ret

; =============================================================================
; End of code.  Everything below is data + BSS.
; =============================================================================

ALIGN 16
file_end:
; --- BSS: labels resolved via 'equ' so we emit no bytes but still have
;     meaningful virtual addresses past file_end.  The PT_LOAD segment's
;     memsz extends up to mem_end, so the kernel zero-fills this range.
bss_base      equ file_end

src_buf       equ bss_base
src_len       equ src_buf       + SRC_MAX
ir_buf        equ src_len       + 8
ir_count      equ ir_buf        + (IR_MAX * IR_STRIDE)
loop_stack    equ ir_count      + 8
loop_sp       equ loop_stack    + (LOOP_STACK_MAX * 8)
mul_effects   equ loop_sp       + 8
code_base     equ mul_effects   + MUL_BUF_SIZE
code_end      equ code_base     + 8
code_ptr      equ code_end      + 8
tape_base     equ code_ptr      + 8
mul_patch     equ tape_base     + 8
code_size     equ mul_patch     + 8
mem_end       equ code_size     + 8
