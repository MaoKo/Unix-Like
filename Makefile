
.PHONY: all debug clean

AS = fasm
DEFINE =
SRC = kfs_5.asm system.inc kernel.inc bitmap.inc init.inc login.inc kbd.inc fonts.inc teletype.inc\
	shell.inc copyright.inc help.inc sigint.inc uid.inc uname.inc reboot.inc shutdown.inc hostname.inc\
	color.inc resolution.inc clear.inc usertest.inc segvtest.inc kill.inc vdso.inc vm86.inc signal.inc\
	sockpoc.inc client.inc server.inc sqrt.inc md5.inc
ELF = kfs_5
CFG = grub.cfg
ISO = iso

TARGET = achiu-au.iso

ifeq ($(MAKECMDGOALS),debug)
DEFINE = -dDEBUG=""
endif

all: $(TARGET) ; 
debug: $(TARGET) ;

$(TARGET): $(SRC)
	$(AS) $(DEFINE) -m100000 $< $(ELF)
	@mkdir -p $(ISO)/boot/grub
	@cp $(ELF) $(ISO)/boot
	@cp grub.cfg $(ISO)/boot/grub
	@grub-mkrescue -o $@ $(ISO)

clean:
	@rm -rf $(ISO) $(TARGET) $(ELF)

