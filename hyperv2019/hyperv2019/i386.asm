.MODEL flat, C
.CODE

ARCH_VMCALL_MM PROC param1:DWORD, param2:DWORD, param3:DWORD
	push esi
	push edi
	push ebx
	xor edx,edx
	mov ecx, param2
	mov ebx, [ecx+4] ;pHyperCallInPA.HighPart
	mov ecx, [ecx] ;pHyperCallInPA.lowPart
	mov esi, param3
	mov edi, [esi+4] ;pHyperCallOutPA.HighPart
	mov esi, [esi] ;pHyperCallOutPA.LowPart
	mov eax, param1
	vmcall
	pop ebx
	pop edi
	pop esi
	ret
ARCH_VMCALL_MM ENDP

ARCH_VMCALL_REG PROC param1:DWORD
	push esi
	push edi
	push ebx
	xor edx,edx
	xor ecx,ecx
	xor ebx,ebx
	xor esi,esi
	xor edi,edi
	mov eax, param1
	vmcall
	pop ebx
	pop edi
	pop esi
	ret
ARCH_VMCALL_REG ENDP

ARCH_VMCALL_REG_MOD PROC
	push esi
	push edi
	push ebx
	xor edx,edx
	;mov ecx, param1
	mov ecx, 60h
	xor ebx,ebx
	xor esi,esi
	xor edi,edi
	;mov eax, 10041h
	mov eax, 10001h ; for HvSwitchVirtualAddressSpace call
	vmcall
	pop ebx
	pop edi
	pop esi
	ret
ARCH_VMCALL_REG_MOD ENDP

ArchmWinHvOnInterrupt PROC
	nop
	ret
ArchmWinHvOnInterrupt ENDP

ArchmHvlRegisterInterruptCallback PROC
	nop
	ret
ArchmHvlRegisterInterruptCallback ENDP

ArchReadMsr PROC
	rdmsr
	ret 
ArchReadMSR ENDP

Arch_SendVMCall PROC
	pushad
	xor edx,edx
	mov ecx, 57h
	xor ecx,ecx
	mov edx,2000h
	xor esi,esi
	mov esi,2001h
	vmcall
	popad
Arch_SendVMCall ENDP

END 