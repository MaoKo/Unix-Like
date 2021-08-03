
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

_dump_2th_paging(0x0007ff00)
