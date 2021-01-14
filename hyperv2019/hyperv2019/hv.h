#include "Driver.h"
#include "mWin.h"
#include "distorm/include/distorm.h" 

//#define IS_GUEST

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define HV_PARTITION_ID_INVALID	0x0000000000000000UI64
#define HV_STATUS_SUCCESS  0x0000	
#define HV_STATUS_INVALID_HYPERCALL_CODE  0x0002	
#define HV_STATUS_INVALID_HYPERCALL_INPUT  0x0003	
#define HV_STATUS_INVALID_ALIGNMENT  0x0004	
#define HV_STATUS_INVALID_PARAMETER  0x0005	
#define HV_STATUS_ACCESS_DENIED  0x0006	
#define HV_STATUS_INVALID_PARTITION_STATE  0x0007	
#define HV_STATUS_OPERATION_DENIED  0x0008	
#define HV_STATUS_UNKNOWN_PROPERTY  0x0009	
#define HV_STATUS_PROPERTY_VALUE_OUT_OF_RANGE  0x000A	
#define HV_STATUS_INSUFFICIENT_MEMORY  0x000B	
#define HV_STATUS_PARTITION_TOO_DEEP  0x000C	
#define HV_STATUS_INVALID_PARTITION_ID  0x000D	
#define HV_STATUS_INVALID_VP_INDEX  0x000E	


#define HV_INTERCEPT_ACCESS_MASK_NONE	0
#define HV_INTERCEPT_ACCESS_MASK_READ	1
#define HV_INTERCEPT_ACCESS_MASK_WRITE	2
#define HV_INTERCEPT_ACCESS_MASK_EXECUTE	4
#define WIN_HV_ON_INTERRUPT_OFFSET	0x1AE0 //Warning!! Hardcode constant
#define HV_SYNIC_SINT_COUNT 	16

#define HV_X64_MSR_SIMP 0x40000083
#define HV_X64_MSR_SIEFP 0x40000082
#define HV_X64_MSR_EOM 0x40000084
#define HV_X64_MSR_SINT0 0x40000090

#define MAX_PROCESSOR_COUNT 32

typedef UINT16 HV_STATUS;
typedef UINT64 HV_PARTITION_ID;
typedef UINT64 HV_GPA;
typedef UINT64 HV_ADDRESS_SPACE_ID; 
typedef HV_PARTITION_ID *PHV_PARTITION_ID;
typedef UINT64 HV_NANO100_TIME;
typedef HV_NANO100_TIME *PHV_NANO100_TIME;
typedef UINT64 HV_PARTITION_PROPERTY;
typedef HV_PARTITION_PROPERTY *PHV_PARTITION_PROPERTY;
typedef UINT8 HV_INTERCEPT_ACCESS_TYPE_MASK;
typedef UINT32 HV_VP_INDEX;



int InitWinHV(VOID);
int SignalEvent(VOID);
int PostMessage(VOID);
int ConnectPort(VOID);
int SetupInterception(VOID);
int RegisterInterrupt(VOID);
int FindWinHvOnInterrupt(VOID);
int EnumActivePartitionID(VOID);
VOID ParseHvMessage(VOID);
VOID PrintIO_PORT_INTERCEPT_MESSAGE(VOID);
int SendMessageToHost(VOID); 
int GetActivePartitionsId();
int fHvConnectPort(VOID);

typedef enum
{
	HvUnsupportedFeatureIntercept		= 1,
	HvUnsupportedFeatureTaskSwitchTss			= 2	
} HV_UNSUPPORTED_FEATURE_CODE;


typedef enum  { 
  HvPartitionPropertyPrivilegeFlags          = 0x00010000,
  HvPartitionPropertyCpuReserve              = 0x00020001,
  HvPartitionPropertyCpuCap                  = 0x00020002,
  HvPartitionPropertyCpuWeight               = 0x00020003,
  HvPartitionPropertyEmulatedTimerPeriod     = 0x00030000,
  HvPartitionPropertyEmulatedTimerControl    = 0x00030001,
  HvPartitionPropertyPmTimerAssist           = 0x00030002,
  HvPartitionPropertyDebugChannelId          = 0x00040000,
  HvPartitionPropertyVirtualTlbPageCount     = 0x00050000,
  HvPartitionPropertyProcessorVendor         = 0x00060000,
  HvPartitionPropertyProcessorFeatures       = 0x00060001,
  HvPartitionPropertyProcessorXsaveFeatures  = 0x00060002,
  HvPartitionPropertyProcessorCLFlushSize    = 0x00060003
} HV_PARTITION_PROPERTY_CODE, *PHV_PARTITION_PROPERTY_CODE;

typedef UINT16 HV_X64_IO_PORT;

typedef enum _HV_INTERCEPT_TYPE { 
  HvInterceptTypeX64IoPort     = 0x00000000,
  HvInterceptTypeX64Msr        = 0x00000001,
  HvInterceptTypeX64Cpuid      = 0x00000002,
  HvInterceptTypeX64Exception  = 0x00000003
} HV_INTERCEPT_TYPE, *PHV_INTERCEPT_TYPE;

typedef union _HV_INTERCEPT_PARAMETERS {
  UINT64         AsUINT64;
  HV_X64_IO_PORT IoPort;
  UINT32         CpuidIndex;
  UINT16         ExceptionVector;
} HV_INTERCEPT_PARAMETERS, *PHV_INTERCEPT_PARAMETERS;


typedef struct _HV_INTERCEPT_DESCRIPTOR {
  HV_INTERCEPT_TYPE       Type;
  HV_INTERCEPT_PARAMETERS Parameters;
} HV_INTERCEPT_DESCRIPTOR, *PHV_INTERCEPT_DESCRIPTOR;



typedef enum _HV_MESSAGE_TYPE { 
  HvMessageTypeNone                    = 0x00000000,
  HvMessageTypeUnmappedGpa             = 0x80000000,
  HvMessageTypeGpaIntercept            = 0x80000001,
  HvMessageTimerExpired                = 0x80000010,
  HvMessageTypeInvalidVpRegisterValue  = 0x80000020,
  HvMessageTypeUnrecoverableException  = 0x80000021,
  HvMessageTypeUnsupportedFeature      = 0x80000022,
  HvMessageTypeEventLogBufferComplete  = 0x80000040,
  HvMessageTypeX64IoPortIntercept      = 0x80010000,
  HvMessageTypeX64MsrIntercept         = 0x80010001,
  HvMessageTypeX64CpuidIntercept       = 0x80010002,
  HvMessageTypeX64ExceptionIntercept   = 0x80010003,
  HvMessageTypeX64ApicEoi              = 0x80010004,
  HvMessageTypeX64LegacyFpError        = 0x80010005
} HV_MESSAGE_TYPE, *PHV_MESSAGE_TYPE;


typedef union
{
	UINT32 AsUint32;
	struct
	{
	    UINT32 Id:24;
	    UINT32 Reserved:8;
	};
} HV_CONNECTION_ID;

typedef union
{
	UINT32 AsUint32;
	struct
	{
	    UINT32 Id:24;
	    UINT32 Reserved:8;
	};
} HV_PORT_ID;

typedef enum _HV_PORT_TYPE { 
  HvPortTypeMessage  = 1,
  HvPortTypeEvent    = 2,
  HvPortTypeMonitor  = 3
} HV_PORT_TYPE, *PHV_PORT_TYPE;


typedef struct _HV_CONNECTION_INFO {
  HV_PORT_TYPE PortType;
  UINT32       Padding;
  union {
    struct {
      UINT64 RsvdZ;
    } MessageConnectionInfo;
    struct {
      UINT64 RsvdZ;
    } EventConnectionInfo;
    struct {
      HV_GPA MonitorAddress;
    } MonitorConnectionInfo;
  };
} HV_CONNECTION_INFO, *PHV_CONNECTION_INFO;

#define HV_MESSAGE_SIZE  	256
#define HV_MESSAGE_MAX_PAYLOAD_BYTE_COUNT	240
#define HV_MESSAGE_MAX_PAYLOAD_QWORD_COUNT	30

typedef struct
{
	UINT8 MessagePending:1;
	UINT8 Reserved:7;
} HV_MESSAGE_FLAGS;


typedef struct
{
	HV_MESSAGE_TYPE	MessageType; 
	UINT16	Reserved; 
	HV_MESSAGE_FLAGS	MessageFlags; 
	UINT8	PayloadSize; 
	union 
	{
        UINT64		OriginationId;
		HV_PARTITION_ID		Sender;
		HV_PORT_ID		Port;
	};
} HV_MESSAGE_HEADER;

typedef struct
{
	HV_MESSAGE_HEADER	Header;
	UINT64	Payload[HV_MESSAGE_MAX_PAYLOAD_QWORD_COUNT];
} HV_MESSAGE, *PHV_MESSAGE;

typedef union _HV_X64_IO_PORT_ACCESS_INFO {
  UINT8  AsUINT8;
  struct {
    UINT8 AccessSize  :3;
    UINT8 StringOp  :1;
    UINT8 RepPrefix  :1;
    UINT8 Reserved  :3;
  };
} HV_X64_IO_PORT_ACCESS_INFO, *PHV_X64_IO_PORT_ACCESS_INFO;

typedef union _HV_X64_VP_EXECUTION_STATE {
  UINT16 AsUINT16;
  struct {
    UINT16 Cpl  :2;
    UINT16 Cr0Pe  :1;
    UINT16 Cr0Am  :1;
    UINT16 EferLma  :1;
    UINT16 DebugActive  :1;
    UINT16 InterruptionPending  :1;
    UINT16 Reserved  :9;
  };
} HV_X64_VP_EXECUTION_STATE, *PHV_X64_VP_EXECUTION_STATE;

typedef struct _HV_X64_SEGMENT_REGISTER {
  UINT64 Base;
  UINT32 Limit;
  UINT16 Selector;
  union {
    struct {
      UINT16 SegmentType  :4;
      UINT16 NonSystemSegment  :1;
      UINT16 DescriptorPrivilegeLevel  :2;
      UINT16 Present  :1;
      UINT16 Reserved  :4;
      UINT16 Available  :1;
      UINT16 Long  :1;
      UINT16 Default  :1;
      UINT16 Granularity  :1;
    };
    UINT16 Attributes;
  };
} HV_X64_SEGMENT_REGISTER, *PHV_X64_SEGMENT_REGISTER;


typedef struct _HV_X64_INTERCEPT_MESSAGE_HEADER {
  HV_VP_INDEX               VpIndex;
  UINT8                     InstructionLength;
  HV_INTERCEPT_ACCESS_TYPE_MASK  InterceptAccessType;//in original undefined type HV_INTERCEPT_ACCESS_TYPE - A bitwise OR combination of HV_INTERCEPT_ACCESS_TYPE_MASK 
  HV_X64_VP_EXECUTION_STATE ExecutionState;
  HV_X64_SEGMENT_REGISTER   CsSegment;
  UINT64                    Rip;
  UINT64                    Rflags;
} HV_X64_INTERCEPT_MESSAGE_HEADER, *PHV_X64_INTERCEPT_MESSAGE_HEADER;


typedef struct _HV_X64_IO_PORT_INTERCEPT_MESSAGE {
  HV_X64_INTERCEPT_MESSAGE_HEADER Header;
  UINT16                          PortNumber;
  HV_X64_IO_PORT_ACCESS_INFO      AccessInfo;
  UINT8                           InstructionByteCount;
  UINT32                          Reserved;
  UINT64                          Rax;
  //UINT64                          InstructionBytes0;
  //UINT64                          InstructionBytes1;
  UINT8                           InstructionBytes[16];
  HV_X64_SEGMENT_REGISTER         DsSegment;
  HV_X64_SEGMENT_REGISTER         EsSegment;
  UINT64                          Rcx;
  UINT64                          Rsi;
  UINT64                          Rdi;
} HV_X64_IO_PORT_INTERCEPT_MESSAGE, *PHV_X64_IO_PORT_INTERCEPT_MESSAGE;


typedef struct _HV_X64_CPUID_INTERCEPT_MESSAGE {
  HV_X64_INTERCEPT_MESSAGE_HEADER Header;
  UINT64                          Rax;
  UINT64                          Rcx;
  UINT64                          Rdx;
  UINT64                          Rbx;
  UINT64                          DefaultResultRax;
  UINT64                          DefaultResultRcx;
  UINT64                          DefaultResultRdx;
  UINT64                          DefaultResultRbx;
} HV_X64_CPUID_INTERCEPT_MESSAGE, *PHV_X64_CPUID_INTERCEPT_MESSAGE;

typedef struct _HV_X64_MSR_INTERCEPT_MESSAGE {
  HV_X64_INTERCEPT_MESSAGE_HEADER Header;
  UINT32                          MsrNumber;
  UINT32                          Reserved;
  UINT64                          Rdx;
  UINT64                          Rax;
} HV_X64_MSR_INTERCEPT_MESSAGE, *PHV_X64_MSR_INTERCEPT_MESSAGE;

typedef union _HV_X64_EXCEPTION_INFO {
  UINT8  AsUINT8;
  struct {
    UINT8 ErrorCodeValid  :1;
    UINT8 Reserved  :7;
  };
} HV_X64_EXCEPTION_INFO, *PHV_X64_EXCEPTION_INFO;


typedef struct _HV_X64_EXCEPTION_INTERCEPT_MESSAGE {
  HV_X64_INTERCEPT_MESSAGE_HEADER Header;
  UINT16                          ExceptionVector;
  HV_X64_EXCEPTION_INFO           ExceptionInfo;
  UINT8                           InstructionByteCount;
  UINT32                          ErrorCode;
  UINT64                          ExceptionParameter;
  UINT64                          Reserved;
  UINT8                           InstructionBytes[16];
  HV_X64_SEGMENT_REGISTER         DsSegment;
  HV_X64_SEGMENT_REGISTER         SsSegment;
  UINT64                          Rax;
  UINT64                          Rcx;
  UINT64                          Rdx;
  UINT64                          Rbx;
  UINT64                          Rsp;
  UINT64                          Rbp;
  UINT64                          Rsi;
  UINT64                          Rdi;
  UINT64                          R8;
  UINT64                          R9;
  UINT64                          R10;
  UINT64                          R11;
  UINT64                          R12;
  UINT64                          R13;
  UINT64                          R14;
  UINT64                          R15;
} HV_X64_EXCEPTION_INTERCEPT_MESSAGE, *PHV_X64_EXCEPTION_INTERCEPT_MESSAGE;



//x86/x64 specific functions definition
#ifdef _WIN64
size_t ARCH_VMCALL(size_t);
size_t ARCH_VMCALL_REG_MOD(size_t);
size_t ArchmWinHvOnInterrupt(VOID);
size_t ArchmHvlRegisterInterruptCallback(UINT64 ArchmWinHvOnInterruptAddress,UINT64 HvlpInterruptCallbackAddress, UINT64 Index);
size_t ArchReadMsr(size_t MsrReg);
size_t Arch_SendVMCall(VOID);
#else
size_t _cdecl ARCH_VMCALL_MM(size_t, size_t, size_t);
size_t _cdecl ARCH_VMCALL_REG(size_t);
size_t _cdecl ARCH_VMCALL_REG_MOD(size_t);
size_t _cdecl ArchmWinHvOnInterrupt(VOID);
size_t _cdecl ArchmHvlRegisterInterruptCallback(UINT64 ArchmWinHvOnInterruptAddress,UINT64 HvlpInterruptCallbackAddress, UINT64 Index);
size_t _cdecl ArchReadMsr(size_t MsrReg);
size_t _cdecl Arch_SendVMCall(VOID);
#endif

//
// Host only API
//

#ifndef IS_GUEST

DECLSPEC_IMPORT HV_STATUS 
#ifndef _WIN64
	_stdcall 
#endif 
	WinHvGetPartitionId(__out PHV_PARTITION_ID PartitionId);

DECLSPEC_IMPORT HV_STATUS 
#ifndef _WIN64
	_stdcall 
#endif
	WinHvGetPartitionProperty(
	  _In_   HV_PARTITION_ID PartitionId,
	  _In_   HV_PARTITION_PROPERTY_CODE PropertyCode,
	  _Out_  PHV_PARTITION_PROPERTY PropertyValue
	);

DECLSPEC_IMPORT HV_STATUS 
#ifndef _WIN64
	_stdcall 
#endif
	WinHvGetNextChildPartition(	__in  HV_PARTITION_ID	ParentId,__in  HV_PARTITION_ID	PreviousChildId,__out PHV_PARTITION_ID	NextChildId);

DECLSPEC_IMPORT HV_STATUS
#ifndef _WIN64
_stdcall
#endif
WinHvInstallIntercept(
	_In_  HV_PARTITION_ID PartitionId,
	_In_  HV_INTERCEPT_ACCESS_TYPE_MASK AccessType,
	_In_  PHV_INTERCEPT_DESCRIPTOR Descriptor
);

DECLSPEC_IMPORT HV_STATUS 
#ifndef _WIN64
_stdcall 
#endif
	WinHvSetPartitionProperty(__in HV_PARTITION_ID	PartitionId,__in HV_PARTITION_PROPERTY_CODE	PropertyCode,__in HV_PARTITION_PROPERTY	PropertyValue);

#endif //IS_GUEST

DECLSPEC_IMPORT HV_STATUS 
#ifndef _WIN64
_stdcall 
#endif 
	WinHvGetLogicalProcessorRunTime(__out PHV_NANO100_TIME	GlobalTime,	__out PHV_NANO100_TIME	LocalRunTime,__out PHV_NANO100_TIME	HypervisorTime,	__out PHV_NANO100_TIME	SomethingTime);


DECLSPEC_IMPORT
HV_STATUS
#ifndef _WIN64
	_stdcall 
#endif
 WinHvSignalEvent(__in HV_CONNECTION_ID	ConnectionId,__in UINT16 FlagNumber);

DECLSPEC_IMPORT 
HV_STATUS 
#ifndef _WIN64
_stdcall 
#endif
	WinHvConnectPort(
	__in HV_PARTITION_ID	ConnectionPartition,
	__in HV_CONNECTION_ID	ConnectionId,
	__in HV_PARTITION_ID	PortPartition,
	__in HV_PORT_ID	PortId,
	__in PHV_CONNECTION_INFO	ConnectionInfo,
	__in UINT32 param6
	);

DECLSPEC_IMPORT HV_STATUS
#ifndef _WIN64
_stdcall
#endif
WinHvPostMessage(
  _In_  HV_CONNECTION_ID ConnectionId,
  _In_  HV_MESSAGE_TYPE MessageType,
  _In_  PVOID Message,
  _In_  UINT32 PayloadSize
);




