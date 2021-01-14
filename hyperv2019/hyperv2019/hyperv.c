
#include "hv.h"
extern PVOID pHvlpInterruptCallbackOrig;
extern PVOID pWinHVOnInterruptOrig;

NTSTATUS DeviceControlRoutine( IN PDEVICE_OBJECT fdo, IN PIRP Irp );
VOID     UnloadRoutine(IN PDRIVER_OBJECT DriverObject);
NTSTATUS Create_File_IRPprocessing(IN PDEVICE_OBJECT fdo, IN PIRP Irp);
NTSTATUS Close_HandleIRPprocessing(IN PDEVICE_OBJECT fdo, IN PIRP Irp);
NTSTATUS ReadWrite_IRPhandler(IN PDEVICE_OBJECT fdo, IN PIRP Irp);

KSPIN_LOCK MySpinLock;

NTSTATUS DriverEntry( IN PDRIVER_OBJECT DriverObject,
                      IN PUNICODE_STRING RegistryPath  )
{
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT  fdo;
	UNICODE_STRING  devName;
	PEXAMPLE_DEVICE_EXTENSION dx;
	UNICODE_STRING symLinkName;

	DriverObject->DriverUnload = UnloadRoutine;
	DriverObject->MajorFunction[IRP_MJ_CREATE]= Create_File_IRPprocessing;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = Close_HandleIRPprocessing;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]= DeviceControlRoutine;
    DriverObject->MajorFunction[IRP_MJ_READ] = ReadWrite_IRPhandler;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = ReadWrite_IRPhandler;

	RtlInitUnicodeString( &devName, L"\\Device\\hyperv" );

	status = IoCreateDevice(DriverObject,
                            sizeof(EXAMPLE_DEVICE_EXTENSION),
                            &devName, 
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE, 
                            &fdo);
	if(!NT_SUCCESS(status)) return status;

	dx = (PEXAMPLE_DEVICE_EXTENSION)fdo->DeviceExtension;
	dx->fdo = fdo;  

	#define   SYM_LINK_NAME   L"\\DosDevices\\hyperv"

	RtlInitUnicodeString( &symLinkName, SYM_LINK_NAME );
	dx->ustrSymLinkName = symLinkName;
	
	status = IoCreateSymbolicLink( &symLinkName, &devName );
	if (!NT_SUCCESS(status))
	{ 
		DbgLog("Error IoCreateSymbolicLink", status);
        IoDeleteDevice( fdo );
		return status;
    } 

	InitWinHV();

    return status;
}

NTSTATUS CompleteIrp( PIRP Irp, NTSTATUS status, ULONG info)
{
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp,IO_NO_INCREMENT);
	return status;
}

NTSTATUS ReadWrite_IRPhandler( IN PDEVICE_OBJECT fdo, IN PIRP Irp )
{
	ULONG BytesTxd = 0;
	NTSTATUS status = STATUS_SUCCESS; 
	return CompleteIrp(Irp,status,BytesTxd);
}

NTSTATUS Create_File_IRPprocessing(IN PDEVICE_OBJECT fdo,IN PIRP Irp)
{
	return CompleteIrp(Irp,STATUS_SUCCESS,0); 
}

NTSTATUS Close_HandleIRPprocessing(IN PDEVICE_OBJECT fdo,IN PIRP Irp)
{
	return CompleteIrp(Irp,STATUS_SUCCESS,0);
}

NTSTATUS DeviceControlRoutine( IN PDEVICE_OBJECT fdo, IN PIRP Irp )
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG BytesTxd =0; 
	PIO_STACK_LOCATION IrpStack=IoGetCurrentIrpStackLocation(Irp);
	ULONG ControlCode =	IrpStack->Parameters.DeviceIoControl.IoControlCode;
	size_t i;
	//size_t res;
	ULONG counter = 0;
	PVOID pHyperCallIn = NULL, pHyperCallOut = NULL;
	PHYSICAL_ADDRESS pHyperCallInPA, pHyperCallOutPA;

	DbgLog("IOCTL", ControlCode);
	switch(ControlCode) {
	case SEND_MESSAGE_TO_HOST:
	{
		Arch_SendVMCall();
		break;
	}

	case START_FUZZING:
	{
		//fHvConnectPort();
		//SignalEvent();
		PostMessage();
		break;
	}
#ifndef IS_GUEST
	case INTERRUPT_CODE:
	{
		RegisterInterrupt();
		break;
	}
	case ENUM_PARTITION_CODE:
	{
		EnumActivePartitionID();
		break;
	}
	case INTERCEPTION_CODE:
	{
		SetupInterception();
		break;
	}
#endif // !IS_GUEST
	case IOCTL_VMCALL:
	{     
		DbgLog("IOCTL_VMCALL",ControlCode);
		//InitWinHV();
		pHyperCallIn = MmAllocateNonCachedMemory(0x1000);
		if (pHyperCallIn == NULL) 
		{
			DbgPrintString("pHyperCallIn MmAllocateNonCachedMemory failed!");
			break;
		}
		pHyperCallOut = MmAllocateNonCachedMemory(0x1000);
		if (pHyperCallOut == NULL)
		{
			DbgPrintString("pHyperCallOut MmAllocateNonCachedMemory failed!");
			MmFreeNonCachedMemory(pHyperCallIn,0x1000);
			break;
		}
		pHyperCallInPA =  MmGetPhysicalAddress(pHyperCallIn);
		pHyperCallOutPA =  MmGetPhysicalAddress(pHyperCallOut);
		DbgLog16("pHyperCallInPA",pHyperCallInPA);
		DbgLog16("pHyperCallOutPA",pHyperCallOutPA);
		//ARCH_VMCALL_REG_MOD(0x1);
		//DbgLog("VMCALL_RES_EAX",ARCH_VMCALL_MM(VMCALL_ID,(uintptr_t)&pHyperCallInPA,(uintptr_t)&pHyperCallOutPA));
		//for (i = 0x70; i <=0x70; i++)
		//{
		//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL,"i %x VMCALL_EAX %x",i,ARCH_VMCALL_MM(0x10000+i,(uintptr_t)&pHyperCallInPA,(uintptr_t)&pHyperCallOutPA));
		//}
		//for (i = 0x2; i <=0x10000; i++)
		//{
		//	res = ARCH_VMCALL_REG_MOD(i);
		//	if (res == HV_STATUS_ACCESS_DENIED){
		//		counter++;
		//		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL,"PartitionID %x VMCALL_EAX %x \n",i,res);
		//	}
		//}
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL,"Number of active virtual machines: %x \n",counter);
		for (i = 0x00; i <=0x100; i++)
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL,"i %x VMCALL_EAX %x \n",i,ARCH_VMCALL_REG_MOD(i));
		}
		//DbgPrint("VMCALL_RES_EDX %x\n",VMCALL_RES_EDX);
		//InitWinHV();
		//SignalEvent();
		//PostMessage();
		//ConnectPort();
		MmFreeNonCachedMemory(pHyperCallIn,0x1000);
		MmFreeNonCachedMemory(pHyperCallOut,0x1000);
		break;
	}

	default: status = STATUS_INVALID_DEVICE_REQUEST;
	}

return CompleteIrp(Irp,status,BytesTxd); 
}


VOID UnloadRoutine(IN PDRIVER_OBJECT pDriverObject)
{
	PDEVICE_OBJECT	pNextDevObj;
	int i;

	pNextDevObj = pDriverObject->DeviceObject;
	if ((pWinHVOnInterruptOrig!= NULL) & (pHvlpInterruptCallbackOrig!=NULL)){
		ArchmHvlRegisterInterruptCallback((UINT64)pWinHVOnInterruptOrig, (UINT64)pHvlpInterruptCallbackOrig,0);
	}

	for(i=0; pNextDevObj!=NULL; i++)
	{
		PEXAMPLE_DEVICE_EXTENSION dx =
				(PEXAMPLE_DEVICE_EXTENSION)pNextDevObj->DeviceExtension;
		UNICODE_STRING *pLinkName = & (dx->ustrSymLinkName);
		pNextDevObj = pNextDevObj->NextDevice;
		IoDeleteSymbolicLink(pLinkName);
		IoDeleteDevice(dx->fdo);
	}
}