
EXTERN pWinHVOnInterruptOrig:QWORD
EXTERN pHvlpInterruptCallbackOrig:QWORD
EXTERN ParseHvMessage:NEAR

mPUSHAD MACRO
	push rax
	push rbx
	push rcx
	push rdx
	push rdi
	push rsi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
ENDM

mPOPAD MACRO
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rsi
	pop rdi
	pop rdx
	pop rcx
	pop rbx
	pop rax
ENDM

.CODE

Arch_SendVMCall PROC
	mPUSHAD
	;mov rcx,5Ch
	mov rcx,200000051h;
	;mov rdx, 200000000000h
	;mov rdx, 200000000000h
	;mov r8, 200000000001h
	mov rdx, 2000000000h
	mov r8, 2000000001h
	vmcall	
	mPOPAD
	ret
Arch_SendVMCall ENDP

ARCH_VMCALL PROC
	push rsi
	push rdi
	push rbx
	xor rdx,rdx
	xor rbx,rbx
	xor rsi,rsi
	xor rdi,rdi
	mov rax, rcx
	vmcall
	pop rbx
	pop rdi
	pop rsi
	ret
ARCH_VMCALL ENDP

ARCH_VMCALL_REG_MOD PROC
	push rsi
	push rdi
	push rbx
	xor rdx,rdx
	xor rbx,rbx
	xor rsi,rsi
	xor rdi,rdi
	mov rdx, rcx
	mov rcx, 10042h
	vmcall
	pop rbx
	pop rdi
	pop rsi
	ret
ARCH_VMCALL_REG_MOD ENDP

ArchmWinHvOnInterrupt PROC
	;mov rdx,cr8
	mPUSHAD	
	;mov rcx,0Fh
	;mov cr8,rcx
	call ParseHvMessage
	mPOPAD
	;mov cr8,rdx
	mov rdx,pWinHVOnInterruptOrig
	jmp rdx 
ArchmWinHvOnInterrupt ENDP

ArchmHvlRegisterInterruptCallback PROC
	;mov [rdx+r8*8],rcx
	mov [rdx],rcx
	ret
ArchmHvlRegisterInterruptCallback ENDP

ArchReadMsr PROC
	rdmsr
	shl rdx, 20h
	or rax,rdx
	ret 
ArchReadMSR ENDP
END 
