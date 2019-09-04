from pykd import *
import sys


hPartitionHandle = 0xFFFFCC814FB7F000L

WINDOWS_SERVER_2016 = 0
WINDOWS_SERVER_2019 = 1

GPAR_ARRAY_OFFSET = 0x8

MBLOCK_ARRAY_START_POSITION_OFFSET = 8
MBLOCK_ARRAY_ELEMENT_COUNT_OFFSET = 0

if WINDOWS_SERVER_2019 == 1:
        PARTITION_NAME_OFFSET = 0x78
        PARTITION_ID_OFFSET = PARTITION_NAME_OFFSET+0x200
        MBLOCKS_ARRAY_OFFSET = 0x1218
        
        GPAR_BLOCK_HANDLE_OFFSET = 0x1520
        GPAR_ELEMENT_COUNT_OFFSET = 0x14

        #GPAR element offsets

        GPAR_ELEMENT_SIGNATURE = 0 #ANSI string
        GPAR_ELEMENT_GPA_INDEX_START = 0x100
        GPAR_ELEMENT_GPA_INDEX_END = 0x108
        GPAR_ELEMENT_UM_FLAGS = 0x120 #dword
        GPAR_ELEMENT_MBLOCK_ELEMENT = 0x170
        GPAR_ELEMENT_SOME_GPA_OFFSET = 0x178
        GPAR_ELEMENT_VMMEM_GPA_OFFSET = 0x180

        #MBLOCK element offsets

        MBLOCK_ELEMENT_SIGNATURE = 0
        MBLOCK_ELEMENT_MBHANDLE = 0x18
        MBLOCK_ELEMENT_BITMAP_SIZE_01 = 0x38
        MBLOCK_ELEMENT_BITMAP_SIZE_02 = 0x40
        MBLOCK_ELEMENT_GUEST_ADDRESS_ARRAY = 0xF0

if WINDOWS_SERVER_2016 == 1:
        PARTITION_NAME_OFFSET = 0x70
        PARTITION_ID_OFFSET = PARTITION_NAME_OFFSET+0x200
        MBLOCKS_ARRAY_OFFSET = 0x1240
        
        GPAR_BLOCK_HANDLE_OFFSET = 0x13A0
        GPAR_ELEMENT_COUNT_OFFSET = 0x18

        #GPAR element offsets

        GPAR_ELEMENT_SIGNATURE = 0 #ANSI string
        GPAR_ELEMENT_GPA_INDEX_START = 0x100
        GPAR_ELEMENT_GPA_INDEX_END = 0x108
        GPAR_ELEMENT_UM_FLAGS = 0x120 #dword
        GPAR_ELEMENT_MBLOCK_ELEMENT = 0x128
        GPAR_ELEMENT_SOME_GPA_OFFSET = 0x178
        GPAR_ELEMENT_VMMEM_GPA_OFFSET = 0x180

        #MBLOCK element offsets

        MBLOCK_ELEMENT_SIGNATURE = 0
        MBLOCK_ELEMENT_MBHANDLE = 0x18
        MBLOCK_ELEMENT_BITMAP_SIZE_01 = 0x38
        MBLOCK_ELEMENT_BITMAP_SIZE_02 = 0x40
        MBLOCK_ELEMENT_GUEST_ADDRESS_ARRAY = 0xE0

def PrintMBlockArray(pMBlockArray,dqMBlocksCount):
        
        dash = '-' * 130
        format_string = '{:<6s}{:>12s}{:>22s}{:>10s}{:>16s}{:>16s}{:>22s}'

        print ""
        print "MBlock Array content:"
        
        print dash
        print(format_string.format("Index","Signature","MBlock Address","MBHandle","BitmapSize01", "BitmapSize02","GPA Array"))
        print dash
        
        for i in range(0,dqMBlocksCount):
                
                objMBlock = ptrQWord(pMBlockArray+MBLOCK_ARRAY_START_POSITION_OFFSET+i*8)
                
                uSignature = loadCStr(objMBlock)
                qwMBHandle = ptrQWord(objMBlock+MBLOCK_ELEMENT_MBHANDLE)
                qwBitmapSize01 = ptrQWord(objMBlock+MBLOCK_ELEMENT_BITMAP_SIZE_01)
                qwBitmapSize02 = ptrQWord(objMBlock+MBLOCK_ELEMENT_BITMAP_SIZE_02)
                if qwBitmapSize01 == qwBitmapSize02:
                        qwBitmapSize02 = "Same"
                qwGuestAddressArray = ptrQWord(objMBlock+MBLOCK_ELEMENT_GUEST_ADDRESS_ARRAY)

                if (qwBitmapSize02 == "Same"):
                        print(format_string.format(str(i),uSignature,hex(objMBlock), str(qwMBHandle), hex(qwBitmapSize01), qwBitmapSize02, hex(qwGuestAddressArray)))        
                else:      
                        print(format_string.format(str(i),uSignature,str(qwMBHandle), hex(qwBitmapSize01), hex(qwBitmapSize02), hex(qwGuestAddressArray)))

                

def PrintGparArray(pGparArray,dwGparElementCounts):
        
        dash = '-' * 130

        if (WINDOWS_SERVER_2016 == 0):
                format_string = '{:<6s}{:>12s}{:>15s}{:>15s}{:>15s}{:>26s}{:>22s}{:>22s}{:>22s}'

        if (WINDOWS_SERVER_2016 == 1):
                format_string = '{:<6s}{:>12s}{:>15s}{:>15s}{:>15s}{:>26s}{:>22s}'

        print ""
        print "GPAR Array content:"
        
        print dash
        if (WINDOWS_SERVER_2016 == 0):
                print(format_string.format("Index","Signature","StartPageNum","EndPageNum","BlockSize", "MemoryBlockGpaRangeFlag","MBlock", "SomeGPA offset","VmmemGPA offset"))
        if (WINDOWS_SERVER_2016 == 1):
                 print(format_string.format("Index","Signature","StartPageNum","EndPageNum","BlockSize", "MemoryBlockGpaRangeFlag","MBlock"))
        print dash
        
        for i in range(0,dwGparElementCounts):
                
                objGpar = ptrQWord(pGparArray+i*8)
                uSignature = loadCStr(objGpar)
                qwGpaIndexStart = ptrQWord(objGpar+GPAR_ELEMENT_GPA_INDEX_START)
                qwGpaIndexEnd = ptrQWord(objGpar+GPAR_ELEMENT_GPA_INDEX_END)
                qwBlockSize = qwGpaIndexEnd-qwGpaIndexStart+1
                dwUmFlag = ptrDWord(objGpar+GPAR_ELEMENT_UM_FLAGS)
                qwMblockAddress = ptrQWord(objGpar+GPAR_ELEMENT_MBLOCK_ELEMENT)
                
                if WINDOWS_SERVER_2016 == 0: #it is container feature. Doesn't exist on Windows Server 2016 and early
                        qwSomeGpa = ptrQWord(objGpar+GPAR_ELEMENT_SOME_GPA_OFFSET)
                        qwVmmemGpa = ptrQWord(objGpar+GPAR_ELEMENT_VMMEM_GPA_OFFSET)

                if WINDOWS_SERVER_2016 == 1:
                        print(format_string.format(str(i),uSignature,hex(qwGpaIndexStart), hex(qwGpaIndexEnd),hex(qwBlockSize), str(dwUmFlag), hex(qwMblockAddress)))
                else:
                        print(format_string.format(str(i),uSignature,hex(qwGpaIndexStart), hex(qwGpaIndexEnd),hex(qwBlockSize), str(dwUmFlag), hex(qwMblockAddress), hex(qwSomeGpa), hex(qwVmmemGpa)))      
        

#Partition handle information

sPartitionSignature = loadCStr(hPartitionHandle)
uPartitionName = loadWStr(hPartitionHandle+PARTITION_NAME_OFFSET)
qwPartitionId = ptrQWord(hPartitionHandle+PARTITION_ID_OFFSET)

#MBLOCK information

pMBlockTable = ptrQWord(hPartitionHandle+MBLOCKS_ARRAY_OFFSET)
qwMBlocksCount = ptrQWord(pMBlockTable+MBLOCK_ARRAY_ELEMENT_COUNT_OFFSET)-1

#GPAR blocks information

pGparBlockHandle = ptrQWord(hPartitionHandle+GPAR_BLOCK_HANDLE_OFFSET)
dwGparElementCounts = ptrDWord(pGparBlockHandle+GPAR_ELEMENT_COUNT_OFFSET)
pGparArray = ptrQWord(pGparBlockHandle+GPAR_ARRAY_OFFSET)

print "Partition signature: ",sPartitionSignature
print "Partition name: ",uPartitionName
print "Partition id: ",qwPartitionId

print "MBBlocks table address: ",hex(pMBlockTable)
print "MBBlocks table element count: ",qwMBlocksCount

print "Gpar block handle address: ",hex(pGparBlockHandle)
print "Gpar Element Count: ",dwGparElementCounts
print "pGparArray address: ",hex(pGparArray)


PrintGparArray(pGparArray,dwGparElementCounts)
PrintMBlockArray(pMBlockTable,qwMBlocksCount)


#        afd = module("afd")
#        ListHead = afd.AfdEndpointListHead
#        print "afd!AfdEndpointListHead address is ",hex(ListHead)
#        ptrNext = ptrQWord(ListHead)
#        print "----AfdEndpoint",hex(ListHead),hex(ptrWord(ListHead-0x120))
#        count = 1
#        while (ptrNext <> ListHead) & (ptrNext != 0xffffffffffffffffL):
#                print "----AfdEndpoint",hex(ptrNext),hex(ptrWord(ptrNext-0x120)),findSymbol(ptrQWord(ptrNext-0x108)),loadCStr(ptrQWord(ptrNext-0x120+0x28)+0x450),hex(ptrQWord(ptrQWord(ptrNext-0x120+0x28)+0x2e8))
#                ptrNext = ptrQWord(ptrNext)
#                count = count+1
#        print "Cycle end. Count", count*/

