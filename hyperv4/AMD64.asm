
EXTERN pvWinHVOnInterruptOrig:QWORD
EXTERN pvHvlpInterruptCallbackOrig:QWORD
EXTERN pvXPartEnlightenedIsrOrig:QWORD
EXTERN ParseHvMessage:NEAR
EXTERN ParseVmbusMessage:NEAR

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

ArchmWinHvOnInterrupt PROC
	mPUSHAD	
	call ParseHvMessage
	mPOPAD
	mov rdx,pvWinHVOnInterruptOrig
	jmp rdx 
ArchmWinHvOnInterrupt ENDP

ArchXPartEnlightenedIsr PROC
	mPUSHAD
	call ParseVmbusMessage
	mPOPAD
	mov rdx,pvXPartEnlightenedIsrOrig
	jmp rdx 
ArchXPartEnlightenedIsr ENDP

ArchmHvlRegisterInterruptCallback PROC
	mov [rdx+r8*8],rcx
	ret
ArchmHvlRegisterInterruptCallback ENDP

ArchReadMsr PROC
	rdmsr
	shl rdx, 20h
	or rax,rdx
	ret 
ArchReadMSR ENDP


END 
