__author__ = "Gerhart"
__license__ = "GPL"
__version__ = "1.2.0"
# python 3.x version

from pykd import *
import sys

WINDOWS_SERVER_2016 = 0
WINDOWS_SERVER_2019 = 1

GPAR_ARRAY_OFFSET = 0x8

MBLOCK_ARRAY_START_POSITION_OFFSET = 8
MBLOCK_ARRAY_ELEMENT_COUNT_OFFSET = 0

if WINDOWS_SERVER_2019 == 1:
    PARTITION_NAME_OFFSET = 0x78
    PARTITION_ID_OFFSET = PARTITION_NAME_OFFSET + 0x200
    MBLOCKS_ARRAY_OFFSET = 0x1218

    GPAR_BLOCK_HANDLE_OFFSET = 0x1520
    GPAR_ELEMENT_COUNT_OFFSET = 0x14

    # GPAR element offsets

    GPAR_ELEMENT_SIGNATURE = 0  # ANSI string
    GPAR_ELEMENT_GPA_INDEX_START = 0x100
    GPAR_ELEMENT_GPA_INDEX_END = 0x108
    GPAR_ELEMENT_UM_FLAGS = 0x120  # dword
    GPAR_ELEMENT_MBLOCK_ELEMENT = 0x170
    GPAR_ELEMENT_SOME_GPA_OFFSET = 0x178
    GPAR_ELEMENT_VMMEM_GPA_OFFSET = 0x180

    # MBLOCK element offsets

    MBLOCK_ELEMENT_SIGNATURE = 0
    MBLOCK_ELEMENT_MBHANDLE = 0x18
    MBLOCK_ELEMENT_BITMAP_SIZE_01 = 0x38
    MBLOCK_ELEMENT_BITMAP_SIZE_02 = 0x40
    MBLOCK_ELEMENT_GUEST_ADDRESS_ARRAY = 0xF0

if WINDOWS_SERVER_2016 == 1:
    PARTITION_NAME_OFFSET = 0x70
    PARTITION_ID_OFFSET = PARTITION_NAME_OFFSET + 0x200
    MBLOCKS_ARRAY_OFFSET = 0x1240

    GPAR_BLOCK_HANDLE_OFFSET = 0x13A0
    GPAR_ELEMENT_COUNT_OFFSET = 0x18

    # GPAR element offsets

    GPAR_ELEMENT_SIGNATURE = 0  # ANSI string
    GPAR_ELEMENT_GPA_INDEX_START = 0x100
    GPAR_ELEMENT_GPA_INDEX_END = 0x108
    GPAR_ELEMENT_UM_FLAGS = 0x120  # dword
    GPAR_ELEMENT_MBLOCK_ELEMENT = 0x128
    GPAR_ELEMENT_SOME_GPA_OFFSET = 0x178
    GPAR_ELEMENT_VMMEM_GPA_OFFSET = 0x180

    # MBLOCK element offsets

    MBLOCK_ELEMENT_SIGNATURE = 0
    MBLOCK_ELEMENT_MBHANDLE = 0x18
    MBLOCK_ELEMENT_BITMAP_SIZE_01 = 0x38
    MBLOCK_ELEMENT_BITMAP_SIZE_02 = 0x40
    MBLOCK_ELEMENT_GUEST_ADDRESS_ARRAY = 0xE0


def get_pykd_version():
    # https://github.com/fireeye/flare-dbg/blob/master/flaredbg/flaredbg.py
    """
    Gets the pykd version number 2 or 3.
    Returns: pykd version number
    """
    version = pykd.version
    version_number = int(version.replace(',', '.').replace(' ', '').split('.')[1])
    if version_number == 3:
        return True
    print("You need 3.x version of pykd. Use !select command for choosing it")
    return False


def PrintMBlockArray(pMBlockArray, dqMBlocksCount):
    dash = '-' * 110
    format_string = '{:<6s}{:>12s}{:>22s}{:>10s}{:>16s}{:>16s}{:>22s}'

    print("")
    print("MBlock Array content:")

    print(dash)
    print(format_string.format("Index", "Signature", "MBlock Address", "MBHandle", "BitmapSize01", "BitmapSize02",
                               "GPA Array"))
    print(dash)

    for i in range(0, dqMBlocksCount):

        objMBlock = pykd.ptrQWord(pMBlockArray + MBLOCK_ARRAY_START_POSITION_OFFSET + i * 8)

        if objMBlock < 0xffff000000000000:
            print("objMBlock has unusual value. Probably, this is one of docker partitions, which is not contain some memory "
                  "blocks links")
            return None

        uSignature = pykd.loadCStr(objMBlock)
        qwMBHandle = pykd.ptrQWord(objMBlock + MBLOCK_ELEMENT_MBHANDLE)
        qwBitmapSize01 = pykd.ptrQWord(objMBlock + MBLOCK_ELEMENT_BITMAP_SIZE_01)
        qwBitmapSize02 = pykd.ptrQWord(objMBlock + MBLOCK_ELEMENT_BITMAP_SIZE_02)
        if qwBitmapSize01 == qwBitmapSize02:
            qwBitmapSize02 = "Same"
        qwGuestAddressArray = pykd.ptrQWord(objMBlock + MBLOCK_ELEMENT_GUEST_ADDRESS_ARRAY)

        if (qwBitmapSize02 == "Same"):
            print(format_string.format(str(i), uSignature, hex(objMBlock), str(qwMBHandle), hex(qwBitmapSize01),
                                       qwBitmapSize02, hex(qwGuestAddressArray)))
        else:
            print(format_string.format(str(i), uSignature, str(qwMBHandle), hex(qwBitmapSize01), hex(qwBitmapSize02),
                                       hex(qwGuestAddressArray)))


def PrintGparArray(pGparArray, dwGparElementCounts):
    dash = '-' * 160

    if (WINDOWS_SERVER_2016 == 0):
        format_string = '{:<6s}{:>12s}{:>15s}{:>15s}{:>15s}{:>26s}{:>22s}{:>22s}{:>22s}'

    if (WINDOWS_SERVER_2016 == 1):
        format_string = '{:<6s}{:>12s}{:>15s}{:>15s}{:>15s}{:>26s}{:>22s}'

    print("")
    print("GPAR Array content:")
    print(dash)

    if (WINDOWS_SERVER_2016 == 0):
        print(format_string.format("Index", "Signature", "StartPageNum", "EndPageNum", "BlockSize",
                                   "MemoryBlockGpaRangeFlag", "MBlock", "SomeGPA offset", "VmmemGPA offset"))
    if (WINDOWS_SERVER_2016 == 1):
        print(format_string.format("Index", "Signature", "StartPageNum", "EndPageNum", "BlockSize",
                                   "MemoryBlockGpaRangeFlag", "MBlock"))
    print(dash)

    for i in range(0, dwGparElementCounts):

        objGpar = pykd.ptrQWord(pGparArray + i * 8)
        uSignature = pykd.loadCStr(objGpar)
        qwGpaIndexStart = pykd.ptrQWord(objGpar + GPAR_ELEMENT_GPA_INDEX_START)
        qwGpaIndexEnd = pykd.ptrQWord(objGpar + GPAR_ELEMENT_GPA_INDEX_END)
        qwBlockSize = qwGpaIndexEnd - qwGpaIndexStart + 1
        dwUmFlag = pykd.ptrDWord(objGpar + GPAR_ELEMENT_UM_FLAGS)
        qwMblockAddress = pykd.ptrQWord(objGpar + GPAR_ELEMENT_MBLOCK_ELEMENT)

        if WINDOWS_SERVER_2016 == 0:  # it is container feature. Doesn't exist on Windows Server 2016 and early
            qwSomeGpa = pykd.ptrQWord(objGpar + GPAR_ELEMENT_SOME_GPA_OFFSET)
            qwVmmemGpa = pykd.ptrQWord(objGpar + GPAR_ELEMENT_VMMEM_GPA_OFFSET)

        if WINDOWS_SERVER_2016 == 1:
            print(format_string.format(str(i), uSignature, hex(qwGpaIndexStart), hex(qwGpaIndexEnd), hex(qwBlockSize),
                                       str(dwUmFlag), hex(qwMblockAddress)))
        else:
            print(format_string.format(str(i), uSignature, hex(qwGpaIndexStart), hex(qwGpaIndexEnd), hex(qwBlockSize),
                                       str(dwUmFlag), hex(qwMblockAddress), hex(qwSomeGpa), hex(qwVmmemGpa)))


def PrintPartitionHandleInfo(hPartitionHandle):
    print("")
    strHandle = "<?dml?> <col fg=\"changed\">Partition handle: "+hex(hPartitionHandle)+"</col>\n"
    pykd.dprintln(strHandle, True)
    #return None
    #print("Partition handle:", hex(hPartitionHandle))
    # Partition handle information

    sPartitionSignature = pykd.loadCStr(hPartitionHandle)
    print("Partition signature: ", sPartitionSignature)

    if sPartitionSignature == "Exo ":
        print("EXO partition parsing is not implemented yet.")
        return None

    uPartitionName = pykd.loadWStr(hPartitionHandle + PARTITION_NAME_OFFSET)
    qwPartitionId = pykd.ptrQWord(hPartitionHandle + PARTITION_ID_OFFSET)

    # MBLOCK information

    pMBlockTable = pykd.ptrQWord(hPartitionHandle + MBLOCKS_ARRAY_OFFSET)
    qwMBlocksCount = pykd.ptrQWord(pMBlockTable + MBLOCK_ARRAY_ELEMENT_COUNT_OFFSET) - 1

    # GPAR blocks information

    pGparBlockHandle = pykd.ptrQWord(hPartitionHandle + GPAR_BLOCK_HANDLE_OFFSET)
    dwGparElementCounts = pykd.ptrDWord(pGparBlockHandle + GPAR_ELEMENT_COUNT_OFFSET)
    pGparArray = pykd.ptrQWord(pGparBlockHandle + GPAR_ARRAY_OFFSET)


    print("Partition name: ", uPartitionName)
    print("Partition id: ", qwPartitionId)

    print("MBBlocks table address: ", hex(pMBlockTable))
    print("MBBlocks table element count: ", qwMBlocksCount)

    print("Gpar block handle address: ", hex(pGparBlockHandle))
    print("Gpar Element Count: ", dwGparElementCounts)
    print("pGparArray address: ", hex(pGparArray))

    PrintGparArray(pGparArray, dwGparElementCounts)
    PrintMBlockArray(pMBlockTable, qwMBlocksCount)


# General winhvr.sys info

if not get_pykd_version:
    exit()

winhvr = pykd.module("winhvr")
WinHvpPartitionArray = winhvr.WinHvpPartitionArray
ptrInternalPartitions = pykd.ptrQWord(WinHvpPartitionArray)
PartitionsCount = pykd.ptrQWord(ptrInternalPartitions)

print("Count of Hyper-V partitions: ", PartitionsCount)

partitions = []

for i in range(PartitionsCount):
    PartitionsVar = pykd.ptrQWord(ptrInternalPartitions + 0x10 + (i * 0x10))
    VidPartitionId = pykd.ptrQWord(PartitionsVar + 8)
    PartitionHandle = pykd.ptrQWord(PartitionsVar + 0x18)
    print("VidPartitionId =", VidPartitionId, "PartitionHandle =", hex(PartitionHandle))
    partitions.append(PartitionHandle)

for i in partitions:
    PrintPartitionHandleInfo(i)