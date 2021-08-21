
# HELPER FUNCTION FOR PAGING

def _dump_1th_paging(address):
    print("OFFSET =", hex(address & 0xFFF))
    print("PAGE TABLE INDEX =", hex((address >> 0xC) & 0x3FF))
    print("PAGE DIRECTORY INDEX =", hex((address >> 0x16) & 0x3FF));

def _dump_2th_paging(address):
    print("OFFSET =", hex(address & 0xFFF))
    print("PAGE TABLE INDEX =", hex((address >> 0xC) & 0x1FF))
    print("PAGE DIRECTORY INDEX =", hex((address >> 0x15) & 0x1FF));
    print("PAGE DIRECTORY POINTER INDEX =", hex((address >> 0x1E) & 0x3));

def _dump_3th_paging(address):
    print("OFFSET =", hex(address & 0xFFF))
    print("PAGE TABLE INDEX =", hex((address >> 0xC) & 0x1FF))
    print("PAGE DIRECTORY INDEX =", hex((address >> 0x15) & 0x1FF));
    print("PAGE DIRECTORY POINTER INDEX =", hex((address >> 0x1E) & 0x1FF));
    print("PAGE LEVEL MAP 4 INDEX =", hex((address >> 0x27) & 0x1FF));
    _canonical = (address >> 0x30)
    _extend = (address & (0x1 << 0x2F))
    if ((_canonical == 0xFFFF) and (_extend)): print("HIGHER HALF")
    elif ((_canonical == 0x00) and (not _extend)): print("LOWER HALF")
    else: print("INVALID")

_dump_2th_paging(0x00000000ffdfb000)
