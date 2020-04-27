// Export Mega drive program as a ELF binary file.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;

public class ExportMegaDriveElf extends GhidraScript {
    @Override
    protected void run() throws Exception {
        MemoryBlock romBlock = currentProgram.getMemory().getBlock("ROM");
        int romSize = (int)romBlock.getSize();
        
        byte[] signature = {(byte)0x7f, 'E', 'L', 'F'};
        byte[] zeroByte = {0};


        println("Mega drive elf export.");
        File file = askFile("Select Elf file to save.", "Save");

        FileOutputStream fos = new FileOutputStream(file);

        //wipe ELF header we'll fill it in later.
        for (int i = 0; i < 0x100; i++) {
            fos.write(zeroByte);
        }

        byte[] programBytes = romBlock.getData().readAllBytes();
        fos.write(programBytes);

        ElfSections sections = new ElfSections();

        ElfSectionHeader textSection = new ElfSectionHeader();
        textSection.name = ".text\0";
        textSection.sh_type = 1; //SHT_PROGBITS
        textSection.sh_flags = 6; //SF32_Write_alloc
        textSection.sh_addr = 0;
        textSection.sh_offset = 0x100;
        textSection.sh_link = 0;
        textSection.sh_info = 0;
        textSection.sh_addralign = 0x100;
        textSection.sh_entsize = 0;
        textSection.sectionData = programBytes;
        textSection.alreadyWrittenData = true;

        int textSectionIndex = sections.addSection(textSection);

        ElfSectionHeader bssSection = new ElfSectionHeader();
        bssSection.name = ".bss\0";
        bssSection.sh_type = 8; //SHT_NOBITS
        bssSection.sh_flags = 6; //SF32_Alloc_Exec
        bssSection.sh_addr = (int)romSize;
        bssSection.sh_size = 0xffffff - (int)romSize;
        bssSection.sh_offset = 0;
        bssSection.sh_link = 0;
        bssSection.sh_info = 0;
        bssSection.sh_addralign = 4;
        bssSection.sh_entsize = 0;
        bssSection.alreadyWrittenData = true;

        sections.addSection(bssSection);

        ElfSymbolTable elfSymbolTable = new ElfSymbolTable(textSectionIndex, this);
        elfSymbolTable.addSymbol("_Entry_Point", 0x200, 0, ElfSymbolBinding.TB_LOCAL, ElfSymbolType.STT_NOTYPE, 2);

        addProgramSymbols(elfSymbolTable);

        elfSymbolTable.writeToSectionsTable(sections);

        sections.write(fos);

        //build header

        ByteBuffer elfHeader = ByteBuffer.allocate(0x34);
        elfHeader.order(ByteOrder.BIG_ENDIAN);
        elfHeader.put(signature);
        elfHeader.put((byte)1);
        elfHeader.put((byte)2);
        elfHeader.put((byte)1);
        elfHeader.put((byte)0);
        elfHeader.put((byte)0);
        //padding
        for(int i = 0; i < 6; i++) {
            elfHeader.put((byte)0);
        }
        elfHeader.put((byte)0);
        elfHeader.putShort((short)2); //ET_EXEC
        elfHeader.putShort((short)4); //EM_68K
        elfHeader.putInt(1); //EV_CURRENT
        elfHeader.putInt(0); //start address
        elfHeader.putInt(52); //program header offset
        elfHeader.putInt(sections.sectionHeaderTableOffset); //section header in file
        elfHeader.putInt(0x1000000); //processor flags

        elfHeader.putShort((short)52); //elf header size
        elfHeader.putShort((short)32); //program header entry size
        elfHeader.putShort((short)2); //number of program headers TODO

        elfHeader.putShort((short)40); //section header table entry size
        elfHeader.putShort((short)sections.headers.size()); //number of section header entries
        elfHeader.putShort((short)1); //string table index TODO
        elfHeader.flip();

        FileChannel fileChannel = fos.getChannel();
        fileChannel.position(0);
        fileChannel.write(elfHeader);

        ByteBuffer programTableEntry = ByteBuffer.allocate(0x20);
        programTableEntry.order(ByteOrder.BIG_ENDIAN);
        programTableEntry.putInt(1); //PT_LOAD
        programTableEntry.putInt(0x100); //FROM_FILE_BEGIN
        programTableEntry.putInt(0); // virtual address
        programTableEntry.putInt(0); // physical address
        programTableEntry.putInt((int)romSize); // segment file length
        programTableEntry.putInt((int)romSize); // segment ram length
        programTableEntry.putInt(5); //PF_Read_Exec
        programTableEntry.putInt(0x100); //segment alignment

        programTableEntry.flip();
        fileChannel.write(programTableEntry);

        programTableEntry = ByteBuffer.allocate(0x20);
        programTableEntry.order(ByteOrder.BIG_ENDIAN);
        programTableEntry.putInt(1); //PT_LOAD
        programTableEntry.putInt(0x100 + (int)romSize); //FROM_FILE_BEGIN
        programTableEntry.putInt((int)romSize); // virtual address
        programTableEntry.putInt(0x100 + (int)romSize); // physical address
        programTableEntry.putInt(0); // segment file length
        programTableEntry.putInt(0xffffff - (int)romSize); // segment ram length
        programTableEntry.putInt(4); //PF_Read_Write
        programTableEntry.putInt(4); //segment alignment

        programTableEntry.flip();
        fileChannel.write(programTableEntry);

        fos.close();
    }

    private void addProgramSymbols(ElfSymbolTable elfSymbolTable) {
        SymbolTable symbolTable = currentProgram.getSymbolTable();

        SymbolIterator symbolIterator = symbolTable.getAllSymbols(false);

        for (Symbol symbol : symbolIterator) {
            if (symbol.isPrimary()) {
                printf("Symbol: %s\n", symbol.getName());
                int addr = (int)symbol.getAddress().getOffset();
                if (symbol.getSymbolType().equals(SymbolType.FUNCTION)) {
                    printf("Func Symbol: %s\n", symbol.getName());
                    elfSymbolTable.addSymbol(symbol.getName(),
                            addr,
                            0,
                            ElfSymbolBinding.STB_GLOBAL,
                            ElfSymbolType.STT_FUNC,
                            addr > 0x3FFFFF ? 3 : 2);
                } else if (symbol.getSymbolType().equals(SymbolType.LABEL)) {
                    printf("Label Symbol: %s\n", symbol.getName());
                    elfSymbolTable.addSymbol(symbol.getName(),
                            addr,
                            0,
                            ElfSymbolBinding.STB_GLOBAL,
                            ElfSymbolType.STT_NOTYPE,
                            addr > 0x3FFFFF ? 3 : 2);
                }
            }
        }
    }
    private static class ElfSections {
        List<ElfSectionHeader> headers;
        ElfSectionHeader sectionNameTable;
        public int sectionHeaderTableOffset;

        public ElfSections() {
            headers = new ArrayList<>();

            ElfSectionHeader undefSection = new ElfSectionHeader();
            undefSection.name = "\0";

            sectionNameTable = new ElfSectionHeader();

            sectionNameTable.name = ".shstrtab\0";
            sectionNameTable.sh_type = 3;
            sectionNameTable.sh_addralign = 1;

            addSection(undefSection);
            addSection(sectionNameTable);
        }

        public int addSection(ElfSectionHeader header) {
            headers.add(header);
            header.sh_name = getNameOffset(header.name);
            return headers.size() - 1; //section index.
        }

        public void write(FileOutputStream fos) throws IOException {
            final byte[] zeroByte = { 0 };
            updateSectionNameTable();
            long offset = fos.getChannel().position();
            for (ElfSectionHeader header : headers) {
                if (header.sectionData == null || header.sectionData.length == 0 || header.alreadyWrittenData) {
                    continue;
                }

                if (header.sh_addralign > 1) {
                    long padding = offset % header.sh_addralign;
                    if (padding > 0) {
                        for ( int i = 0; i < padding; i++) {
                            fos.write(zeroByte);
                        }
                        offset += padding;
                    }
                }
                header.sh_offset = (int)offset;
                fos.write(header.sectionData);
                offset += header.sectionData.length;
            }

            sectionHeaderTableOffset = (int)offset;

            for (ElfSectionHeader header : headers) {
                header.write(fos);
            }
        }

        private void updateSectionNameTable() {
            String names = headers.stream().map(h -> h.name).collect(Collectors.joining());
            sectionNameTable.sectionData = names.getBytes();
        }

        private int getNameOffset(String name) {
            int offset = 0;

            for (int i = 0; i < headers.size(); i++) {
                if (headers.get(i).name.equals(name)) {
                    return offset;
                }
                offset += headers.get(i).name.length();
            }
            throw new RuntimeException("Failed to find name.");
        }
    }

    private static class ElfSectionHeader {
        int sh_name;
        int sh_type;
        int sh_flags;
        int sh_addr;
        int sh_offset;
        int sh_size;
        int sh_link;
        int sh_info;
        int sh_addralign;
        int sh_entsize;
        String name;
        byte[] sectionData;
        boolean alreadyWrittenData;

        public void write(FileOutputStream fileOutputStream) throws IOException {
            ByteBuffer sectionTableEntry = ByteBuffer.allocate(0x28);
            sectionTableEntry.putInt(sh_name);
            sectionTableEntry.putInt(sh_type); //SHT_PROGBITS
            sectionTableEntry.putInt(sh_flags); //SF32_Write_alloc
            sectionTableEntry.putInt(sh_addr); //s_addr
            sectionTableEntry.putInt(sh_offset); //s_offset
            sectionTableEntry.putInt(sectionData != null ? sectionData.length : sh_size); //s_size
            sectionTableEntry.putInt(sh_link); //s_link
            sectionTableEntry.putInt(sh_info); //s_info
            sectionTableEntry.putInt(sh_addralign); //s_addralign
            sectionTableEntry.putInt(sh_entsize); //s_entsize
            sectionTableEntry.flip();
            fileOutputStream.getChannel().write(sectionTableEntry);
        }
    }

    enum ElfSymbolBinding {
        TB_LOCAL 	(0),
        STB_GLOBAL 	(1),
        STB_WEAK 	(2),
        STB_LOOS 	(10),
        STB_HIOS 	(12),
        STB_LOPROC 	(13),
        STB_HIPROC 	(15);

        int value;
        ElfSymbolBinding(int value) {
            this.value = value;
        }
    }

    enum ElfSymbolType {
        STT_NOTYPE 	(0),
        STT_OBJECT 	(1),
        STT_FUNC 	(2),
        STT_SECTION (3),
        STT_FILE 	(4),
        STT_COMMON 	(5),
        STT_TLS 	(6),
        STT_LOOS 	(10),
        STT_HIOS 	(12),
        STT_LOPROC 	(13),
        STT_HIPROC 	(15);

        int value;
        ElfSymbolType(int value) {
            this.value = value;
        }
    }

    private static class ElfSymbolRecord {
        int st_name;
        int st_value;
        int st_size;
        int st_info;
        int st_other;
        int st_shndx;

        public ElfSymbolRecord(int name, int value, short size, ElfSymbolBinding binding, ElfSymbolType type, int shndx) {
            this.st_name = name;
            this.st_value = value;
            this.st_size = size;
            this.st_info = (binding.value<<4) + (type.value & 0xf);
            this.st_other = 0; //STV_DEFAULT
            this.st_shndx = shndx;
        }
    }

    private static class ElfSymbolTable {
        ElfStringTable elfStringTable;
        List<ElfSymbolRecord> symbols;
        GhidraScript ghidraScript;

        int programTextSectionIndex;

        ElfSymbolTable(int programTextSectionIndex, GhidraScript ghidraScript) {
            elfStringTable = new ElfStringTable();
            symbols = new ArrayList<>();
            this.programTextSectionIndex = programTextSectionIndex;
            this.ghidraScript = ghidraScript;

            addSymbol("", 0, 0, ElfSymbolBinding.TB_LOCAL, ElfSymbolType.STT_NOTYPE, programTextSectionIndex);
        }

        void addSymbol(String name, int value, int size, ElfSymbolBinding binding, ElfSymbolType type, int idx) {
            int sh_name = elfStringTable.addString(name);
            ElfSymbolRecord symbolRecord = new ElfSymbolRecord(sh_name, value, (short)size, binding, type, idx);
            symbols.add(symbolRecord);
        }

        void writeToSectionsTable(ElfSections sections) {
            ElfSectionHeader stringTableSectionHeader;
            stringTableSectionHeader = new ElfSectionHeader();
            stringTableSectionHeader.name = ".strtab\0";
            stringTableSectionHeader.sh_type = 3; //SHT_STRTAB
            stringTableSectionHeader.sh_flags = 0;
            stringTableSectionHeader.sh_addr = 0;
            stringTableSectionHeader.sh_offset = 0;
            stringTableSectionHeader.sh_link = 0;
            stringTableSectionHeader.sh_info = 0;
            stringTableSectionHeader.sh_addralign = 1;
            stringTableSectionHeader.sh_entsize = 0;
            stringTableSectionHeader.sectionData = elfStringTable.createBytes();

            int stringTableSectionIndex = sections.addSection(stringTableSectionHeader);

            ElfSectionHeader symbolTableSectionHeader;
            symbolTableSectionHeader = new ElfSectionHeader();
            symbolTableSectionHeader.name = ".symtab\0";
            symbolTableSectionHeader.sh_type = 2; //SHT_SYMTAB
            symbolTableSectionHeader.sh_flags = 0;
            symbolTableSectionHeader.sh_addr = 0;
            symbolTableSectionHeader.sh_offset = 0;
            symbolTableSectionHeader.sh_link = stringTableSectionIndex;
            symbolTableSectionHeader.sh_info = 1; //TODO index + 1 of last LOCAL symbol.
            symbolTableSectionHeader.sh_addralign = 4;
            symbolTableSectionHeader.sh_entsize = 16;
            symbolTableSectionHeader.sectionData = createBytes();

            sections.addSection(symbolTableSectionHeader);
        }

        private byte[] createBytes() {
            ByteBuffer byteBuffer = ByteBuffer.allocate(0x10);
            byte[] bytes = new byte[symbols.size() * 0x10];
            int bytesOffset = 0;
            for (ElfSymbolRecord symbol : symbols) {
                byteBuffer.putInt(0, symbol.st_name);
                byteBuffer.putInt(4, symbol.st_value);
                byteBuffer.putInt(8, symbol.st_size);
                byteBuffer.put(0xc, (byte)symbol.st_info);
                byteBuffer.put(0xd, (byte)symbol.st_other);
                byteBuffer.putShort(0xe, (short)symbol.st_shndx);
                for (int i = 0; i < 0x10; i++) {
                    bytes[bytesOffset++] = byteBuffer.get(i);
                }
            }
            return bytes;
        }
    }

    private static class ElfStringTable {
        LinkedHashMap<String, Integer> strings;
        int currentOffset;

        public ElfStringTable() {
            strings = new LinkedHashMap<>();
            currentOffset = 0;
            addString("");
        }

        int addString(String string) {
            String zeroTerminatedString = string + "\0";
            if (!strings.containsKey(zeroTerminatedString)) {
                strings.put(zeroTerminatedString, currentOffset);
                currentOffset += zeroTerminatedString.length();
            }
            return strings.get(zeroTerminatedString);
        }

        byte[] createBytes() {
            byte[] bytes = new byte[currentOffset];
            int offset = 0;
            for (String string : strings.keySet()) {
                byte[] stringBytes = string.getBytes();
                System.arraycopy(stringBytes, 0, bytes, offset, stringBytes.length);
                offset += stringBytes.length;
            }
            return bytes;
        }
    }
}
