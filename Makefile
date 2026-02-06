# Makefile for EDR/AV/EPP Enumeration BOF
# Compiles service & driver enumeration Beacon Object Files for x64 and x86 architectures

# Compiler toolchains
CC_X64 = x86_64-w64-mingw32-gcc
CC_X86 = i686-w64-mingw32-gcc

# Compiler flags
CFLAGS = -c -Wall -Wextra

# Source and output files
# NOTE: Output filenames use dot convention (svc_enum_bof.x64.o) to match
# the CNA script_resource() lookup: "svc_enum_bof." . $arch . ".o"
SRC = svc_enum_bof.c
OBJ_X64 = svc_enum_bof.x64.o
OBJ_X86 = svc_enum_bof.x86.o

# Default target: build both architectures
all: $(OBJ_X64) $(OBJ_X86)
	@echo ""
	@echo "[+] Compilation complete!"
	@echo "[+] Place both .o files in the same directory as edr-enum.cna"
	@echo ""

# x64 BOF
$(OBJ_X64): $(SRC) beacon.h
	@echo "[*] Compiling x64 BOF..."
	$(CC_X64) $(CFLAGS) $(SRC) -o $(OBJ_X64)

# x86 BOF
$(OBJ_X86): $(SRC) beacon.h
	@echo "[*] Compiling x86 BOF..."
	$(CC_X86) $(CFLAGS) $(SRC) -o $(OBJ_X86)

# Clean compiled objects
clean:
	@echo "[*] Cleaning compiled objects..."
	rm -f $(OBJ_X64) $(OBJ_X86)
	@echo "[+] Clean complete"

# Help target
help:
	@echo "EDR Enumeration BOF Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all     - Compile both x64 and x86 BOFs (default)"
	@echo "  clean   - Remove compiled .o files"
	@echo "  help    - Display this help message"
	@echo ""
	@echo "Requirements:"
	@echo "  - MinGW-w64 cross-compiler (x86_64-w64-mingw32-gcc)"
	@echo "  - MinGW-w64 cross-compiler (i686-w64-mingw32-gcc)"
	@echo ""
	@echo "Output Files:"
	@echo "  - svc_enum_bof.x64.o (for x64 Beacons)"
	@echo "  - svc_enum_bof.x86.o (for x86 Beacons)"

.PHONY: all clean help
