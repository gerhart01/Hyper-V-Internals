#include "hyperv4.h"
#include "dummy.c"
#include "trace.h"
#include "guest.tmh"
#include <stdarg.h>

PVOID pvWinHVOnInterruptOrig;
PVOID pvXPartEnlightenedIsrOrig;
PVOID pvHvlpInterruptCallbackOrig;
PVOID pvSIMP[MAX_PROCESSOR_COUNT];
PVOID pvSIEFP[MAX_PROCESSOR_COUNT];
BOOLEAN IsActivated = FALSE;

int SetupIntercept()
{
	HV_INTERCEPT_DESCRIPTOR Descriptor;
	HV_INTERCEPT_PARAMETERS Parameters = {0};
	HV_STATUS hvStatus = 0;
	HV_PARTITION_ID PartID = 0x0, NextPartID = 0;
	//Если в качестве параметра инструкции в rax инструкции cpuid будет передано значение 0x11114444,
	//то гипервизор выполнит перехват и отправит сообщение родительскому разделу для обработки результата
	DbgPrintString("SetupInterception was called");
	Parameters.CpuidIndex = 0x11114444;
	Descriptor.Type = HvInterceptTypeX64Cpuid;
	Descriptor.Parameters = Parameters;
	hvStatus = WinHvGetPartitionId(&PartID);
	do
	{
		hvStatus = WinHvGetNextChildPartition(PartID, NextPartID, &NextPartID);
		if (NextPartID != 0){
			DbgLog("Child partition id", NextPartID);
			hvStatus = WinHvInstallIntercept(NextPartID, HV_INTERCEPT_ACCESS_MASK_EXECUTE, &Descriptor);
			DbgLog("hvstatus of WinHvInstallIntercept = ", hvStatus);
		}
	} while ((NextPartID != HV_PARTITION_ID_INVALID) && (hvStatus == 0));
	return 0;
}

int FindHvlpInterruptCallback(unsigned char *buf)
{
	_DecodeResult res;
	_DInst adv_res;
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	unsigned int decodedInstructionsCount = 0, i, next;
	_DecodeType dt = Decode64Bits;
	const char *sMnemonicName = "LEA";
	const char *sOperandName = "R10";
	_CodeInfo ci;

	_OffsetType offset = 0;
	char* errch = NULL;

	int len = 100;
	for (;;) {
		res = distorm_decode64(offset, (const unsigned char*)buf, len, dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);
		if (res == DECRES_INPUTERR) {
			DbgPrint(("NULL Buffer?!\n"));
			break;
		}
		for (i = 0; i < decodedInstructionsCount; i++) {
			if (strstr((char *)decodedInstructions[i].mnemonic.p,(char *)sMnemonicName) && strstr((char*)decodedInstructions[i].operands.p,(char *)sOperandName)){
				DbgPrint("%08I64x (%02d) %s %s %s\n", decodedInstructions[i].offset, decodedInstructions[i].size, 
					 (char*)decodedInstructions[i].instructionHex.p,
					 (char*)decodedInstructions[i].mnemonic.p,
					 (char*)decodedInstructions[i].operands.p);
				ci.codeOffset = offset;
				ci.code = (const unsigned char*)buf;
				ci.codeLen = len;
				ci.dt = dt;
				ci.features = DF_NONE;
				res = decode_internal(&ci, FALSE, &adv_res, MAX_INSTRUCTIONS, &decodedInstructionsCount);
				DbgLog("RIP-relative offset",adv_res.disp);
				pvHvlpInterruptCallbackOrig = (PVOID)((UINT64)buf+adv_res.disp+adv_res.size);
				DbgLog16("HvlpInterruptCallback address:",pvHvlpInterruptCallbackOrig);
				pvWinHVOnInterruptOrig = (PVOID)*(PUINT64)pvHvlpInterruptCallbackOrig;
				DbgLog16("WinHvOnInterrupt address:",pvWinHVOnInterruptOrig);
				pvXPartEnlightenedIsrOrig = (PVOID)*((PUINT64)pvHvlpInterruptCallbackOrig + 1);
				DbgLog16("XPartEnlightenedIsr address:", pvXPartEnlightenedIsrOrig);
				return 0;
			}
		}

		if (res == DECRES_SUCCESS || decodedInstructionsCount == 0) {
			break; // All instructions were decoded.
		}

		// Synchronize:
		next = (unsigned int)(decodedInstructions[decodedInstructionsCount-1].offset - offset);
		next += decodedInstructions[decodedInstructionsCount-1].size;

		// Advance ptr and recalc offset.
		buf += next;
		len -= next;
		offset += next;
	}
	DbgPrintString("LEA R10 mnemonic not found!");
	return 1;
}

int RegisterInterrupt()
{
	UNICODE_STRING     uniName;
	PVOID pvHvlRegisterAddress = NULL;
	PHYSICAL_ADDRESS pAdr = {0};
	ULONG i,ProcessorCount;
	if (IsActivated == TRUE)
	{
		DbgPrintString("RegisterInterrupt was already called");
		return 1;
	}
	//получаем число активных ядер процессоров
	ProcessorCount = KeQueryActiveProcessorCount(NULL); 
	//выполняем поиск адреса экспортируемой функции HvlRegisterInterruptCallback
	DbgLog("Active processor count",ProcessorCount);
	RtlInitUnicodeString(&uniName, L"HvlRegisterInterruptCallback");
	pvHvlRegisterAddress = MmGetSystemRoutineAddress(&uniName);
	if (pvHvlRegisterAddress == NULL){
		DbgPrintString("Cannot find HvlRegisterInterruptCallback!");
		return 0;
	}
	DbgLog16("HvlRegisterInterruptCallback address ",pvHvlRegisterAddress);
	//выполняем поиск адреса переменной HvlpInterruptCallback
	FindHvlpInterruptCallback((unsigned char *)pvHvlRegisterAddress);
	//производим замену оригинальных обработчиков на свои
	ArchmHvlRegisterInterruptCallback((uintptr_t)&ArchmWinHvOnInterrupt, (uintptr_t)pvHvlpInterruptCallbackOrig, WIN_HV_ON_INTERRUPT_INDEX);
	ArchmHvlRegisterInterruptCallback((uintptr_t)&ArchXPartEnlightenedIsr, (uintptr_t)pvHvlpInterruptCallbackOrig, XPART_ENLIGHTENED_ISR0_INDEX);
	ArchmHvlRegisterInterruptCallback((uintptr_t)&ArchXPartEnlightenedIsr, (uintptr_t)pvHvlpInterruptCallbackOrig, XPART_ENLIGHTENED_ISR1_INDEX);
	ArchmHvlRegisterInterruptCallback((uintptr_t)&ArchXPartEnlightenedIsr, (uintptr_t)pvHvlpInterruptCallbackOrig, XPART_ENLIGHTENED_ISR2_INDEX);
	ArchmHvlRegisterInterruptCallback((uintptr_t)&ArchXPartEnlightenedIsr, (uintptr_t)pvHvlpInterruptCallbackOrig, XPART_ENLIGHTENED_ISR3_INDEX);
	//т.к. значение SIMP для всех ядер разное, то необходимо получить физическиеа дреса всех SIM,   
	//сделать возможным доступ к содержимому страницы, смапировав её с помощью MmMapIoSpace
	//и сохранить полученные виртуальные адреса каждой страницы в массив для последующего использования
	for (i = 0; i < ProcessorCount; i++){
		KeSetSystemAffinityThreadEx(1i64 << i);
		DbgLog("Current processor number", KeGetCurrentProcessorNumberEx(NULL));
		pAdr.QuadPart = ArchReadMsr(HV_X64_MSR_SIMP) & 0xFFFFFFFFFFFFF000;
		pvSIMP[i] = MmMapIoSpace(pAdr, PAGE_SIZE, MmCached);
		if (pvSIMP[i] == NULL){
			DbgPrintString("Error during pvSIMP MmMapIoSpace");
			return 1;
		}
		DbgLog16("pvSIMP[i] address", pvSIMP[i]);
		pAdr.QuadPart = ArchReadMsr(HV_X64_MSR_SIEFP) & 0xFFFFFFFFFFFFF000;
		pvSIEFP[i] = MmMapIoSpace(pAdr, PAGE_SIZE, MmCached);
		if (pvSIEFP[i] == NULL){
			DbgPrintString("Error during pvSIEFP MmMapIoSpace");
			return 1;
		}
		DbgLog16("pvSIEFP  address", pvSIEFP[i]);
	}
return 0;
}

void PrintIoPortInterceptMessage(PHV_MESSAGE hvMessage)
{
	PHV_X64_IO_PORT_INTERCEPT_MESSAGE phvIOPORT = (PHV_X64_IO_PORT_INTERCEPT_MESSAGE)hvMessage->Payload;
	//DbgLog("	phvIOPORT->Rax",phvIOPORT->Rax);
	//DbgLog16("phvIOPORT->InstructionBytes[0]",phvIOPORT->InstructionBytes0);
	//DbgLog16("phvIOPORT->InstructionBytes[1]",phvIOPORT->InstructionBytes1);
	//DbgLog("	phvIOPORT->PortNumber",phvIOPORT->PortNumber);
	//DbgLog("	phvIOPORT->Header.VpIndex",phvIOPORT->Header.VpIndex);
	//DbgLog16("	phvIOPORT->Header.Rip",phvIOPORT->Header.Rip);
	//DbgLog16("phvIOPORT->Header.Rflags",phvIOPORT->Header.Rflags);
	//DbgLog("	phvIOPORT->Header.ExecutionState.EferLma",phvIOPORT->Header.ExecutionState.EferLma);
	//DbgLog("	phvIOPORT->Header.InstructionLength",phvIOPORT->Header.InstructionLength);
	//DbgLog("	phvIOPORT->Header.InterceptAccessType",phvIOPORT->Header.InterceptAccessType);
	//DbgLog("	phvIOPORT->InstructionByteCount",phvIOPORT->InstructionByteCount);
}

void PrintCpuidInterceptMessage(PHV_MESSAGE hvMessage)
{
	PHV_X64_CPUID_INTERCEPT_MESSAGE phvCPUID = (PHV_X64_CPUID_INTERCEPT_MESSAGE)hvMessage->Payload;
	DbgLog("	phvCPUID->DefaultResultRax", phvCPUID->DefaultResultRax);
	DbgLog("	phvCPUID->DefaultResultRbx", phvCPUID->DefaultResultRbx);
	DbgLog("	phvCPUID->DefaultResultRcx", phvCPUID->DefaultResultRcx);
	DbgLog("	phvCPUID->DefaultResultRdx", phvCPUID->DefaultResultRdx);
	if (phvCPUID->Rax == 0x11114444){
		phvCPUID->DefaultResultRdx = 0x12345678;
		DbgLog16("	phvCPUID->Header.Rip", phvCPUID->Header.Rip);
		DbgPrintString("	Interception was handled");
	}
}

void PrintMsrInterceptMessage(PHV_MESSAGE phvMessage)
{
	PHV_X64_MSR_INTERCEPT_MESSAGE phvMSR = (PHV_X64_MSR_INTERCEPT_MESSAGE)phvMessage->Payload;
	DbgLog("	phvMSR->MsrNumber", phvMSR->MsrNumber);
}

void PrintExceptionInterceptMessage(PHV_MESSAGE phvMessage)
{
	PHV_X64_EXCEPTION_INTERCEPT_MESSAGE phvExc = (PHV_X64_EXCEPTION_INTERCEPT_MESSAGE)phvMessage->Payload;
	DbgLog("	phvExc->ErrorCode", phvExc->ErrorCode);
}

void ParseGpadlHeaderMessage(PVMBUS_MESSAGE msg)
{
	PVMBUS_CHANNEL_GPADL_HEADER vmbGpaHeader = (PVMBUS_CHANNEL_GPADL_HEADER)msg;
	DbgLog("vmbGpaHeader->CHILD_RELID", vmbGpaHeader->CHILD_RELID);
	DbgLog("vmbGpaHeader->GPADL", vmbGpaHeader->GPADL);
	DbgLog("vmbGpaHeader->RANGE.BYTE_COUNT", vmbGpaHeader->RANGE.BYTE_COUNT);
	DbgLog16("vmbGpaHeader->RANGE.PFN_ARRAY[0]", vmbGpaHeader->RANGE.PFN_ARRAY[0]);
	//DbgLog("vmbGpaHeader->RANGE.PFN_ARRAY[1]", vmbGpaHeader->RANGE.PFN_ARRAY[1]);
}

void ParseOpenChannelMessage(PVMBUS_MESSAGE msg)
{
	PVMBUS_CHANNEL_OPEN_CHANNEL vmbOpenChannel = (PVMBUS_CHANNEL_OPEN_CHANNEL)msg;
	DbgLog("vmbOpenChannel->CHILD_RELID", vmbOpenChannel->CHILD_RELID);
	DbgLog("vmbOpenChannel->RINGBUFFER_GPADLHANDLE", vmbOpenChannel->RINGBUFFER_GPADLHANDLE);
	DbgLog("vmbOpenChannel->HEADER", vmbOpenChannel->HEADER);
	DbgLog("vmbOpenChannel->OPENID", vmbOpenChannel->OPENID);
}

void ParseVmbusEvent(ULONG uCurProcNum)
{
	PVOID pvSiefpElement = pvSIEFP[uCurProcNum];
	DbgPrintString("Parse vmbus event");
	if (pvSiefpElement != NULL){
		for (size_t i = 0; i < SINT_COUNT; i++)
		{
			if (*(PUINT32)pvSiefpElement != 0)
			{
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL, "EventFlag %d, value = %x, \n",i, *(PUINT32)pvSiefpElement);
			}
			pvSiefpElement = (PUINT8)pvSiefpElement+SINT_SIZE;
		}
	}
}

void ParseVmbusMessage(size_t index)
{
	//получаем номер активного логического процессора
	ULONG uCurProcNum = KeGetCurrentProcessorNumberEx(NULL);
	PHV_MESSAGE phvMessage4;
	PVMBUS_MESSAGE pvmbMessage;
	if (pvSIMP[uCurProcNum] != NULL){
		//получаем указатель на 4-й слот SIM
		phvMessage4 = (PHV_MESSAGE)((PUINT8)pvSIMP[uCurProcNum] + HV_MESSAGE_SIZE * 4);
		//DbgLog("Hv interrupt vector index", index);
		//если тип сообщения не равен HvMessageTypeNone то в Payload содержится vmbus сообщение 
		if (phvMessage4->Header.MessageType != HvMessageTypeNone){
			pvmbMessage = (PVMBUS_MESSAGE)phvMessage4->Payload;
			//анализируем тип vmbus сообщения и выполняем парсинг
			//структуры vmbus сообщений описаны в LIS
			switch (pvmbMessage->vmbHeader.msgtype)
			{
			case CHANNELMSG_GPADL_HEADER:
				ParseGpadlHeaderMessage(pvmbMessage);
				break;
			case CHANNELMSG_OPENCHANNEL:
				ParseOpenChannelMessage(pvmbMessage);
				break;
			default:
				DbgLog("Unhandled vmbus message", pvmbMessage->vmbHeader.msgtype);
				break;
			}
		}
		else {
			//можем пропарсить SIEF, но пока парсинг приводит к абсолютно разным BSOD
			//ParseVmbusEvent(uCurProcNum); random BSOD
		}
	}
	else{
		DbgPrintString("Error.pvSIMP is NULL");
		return;
	}	
}

void ParseHvMessage()
{
	PHV_MESSAGE phvMessage, phvMessage1;
	//получаем номер активного логического процессора
	ULONG uCurProcNum = KeGetCurrentProcessorNumberEx(NULL);
	if (pvSIMP[uCurProcNum] != NULL){
		phvMessage = (PHV_MESSAGE)pvSIMP[uCurProcNum]; 
	} else{
		DbgPrintString("pvSIMP is NULL");
		return;
	}
	//уведомление об отправке сообщения через 1-й слот SIM
	phvMessage1 = (PHV_MESSAGE)((PUINT8)pvSIMP[uCurProcNum] + HV_MESSAGE_SIZE); //for SINT1
	if (phvMessage1->Header.MessageType != 0){
		DbgPrintString("SINT1 interrupt");
	}
	//в зависимости от типа сообщения вызываем процедуры обработчики
	//структуры для каждого типа сообщения описаны в TLFS
	switch (phvMessage->Header.MessageType)
	{
	case HvMessageTypeX64IoPortIntercept:
		PrintIoPortInterceptMessage(phvMessage);
		break;
	case HvMessageTypeNone:
		DbgPrintString("HvMessageTypeNone");
		break;
	case HvMessageTypeUnmappedGpa:
		break;
	case HvMessageTypeGpaIntercept:
		break;
	case HvMessageTimerExpired:
		break;
	case HvMessageTypeInvalidVpRegisterValue:
		break;
	case HvMessageTypeUnrecoverableException:
		break;
	case HvMessageTypeUnsupportedFeature:
		break;
	case HvMessageTypeEventLogBufferComplete:
		break;
	case HvMessageTypeX64MsrIntercept:
		PrintMsrInterceptMessage(phvMessage);
		break;
	case HvMessageTypeX64CpuidIntercept:
		PrintCpuidInterceptMessage(phvMessage);
		break;
	case HvMessageTypeX64ExceptionIntercept:
		PrintExceptionInterceptMessage(phvMessage);
		break;
	case HvMessageTypeX64ApicEoi:
		break;
	case HvMessageTypeX64LegacyFpError:
		break;
	default:
		DbgLog("Unknown MessageType", phvMessage->Header.MessageType);
		break;
	}
}


