#include <stdio.h>
#include <stdint.h>
#include <windows.h>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("사용법: %s ""PE 파일 경로""\n", argv[0]);
        return 1;
    }

    FILE* file = fopen(argv[1], "rb");
    if (file == NULL) {
        printf("파일을 열 수 없습니다.");
        return 1;
    }

    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS32 ntHeaders;
    IMAGE_SECTION_HEADER sectionHeader;
    fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, file);

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("DOS 헤더 시그니처가 'MZ'가 아닙니다.\n");
        fclose(file);
        return 1;
    }

    fseek(file, dosHeader.e_lfanew, SEEK_SET);


    fread(&ntHeaders, sizeof(IMAGE_NT_HEADERS32), 1, file);

    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        printf("PE 시그니처가 'PE'가 아닙니다.\n");
        fclose(file);
        return 1;
    }

    if (ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        printf("이 파일은 32비트 PE 파일이 아닙니다.\n");
        fclose(file);
        return 1;
    }
    printf("File Name: %s\n", argv[1]);

    printf("\nFile Header (32-bit):\n");
    printf("  Machine: 0x%x\n", ntHeaders.FileHeader.Machine);
    printf("  Number of Sections: %d\n", ntHeaders.FileHeader.NumberOfSections);
    printf("  TimeDateStamp: 0x%x\n", ntHeaders.FileHeader.TimeDateStamp);
    printf("  Size of Optional Header: %d\n", ntHeaders.FileHeader.SizeOfOptionalHeader);
    printf("  Characteristics: 0x%x\n", ntHeaders.FileHeader.Characteristics);

    printf("\nOptional Header (32-bit):\n");
    printf("  Magic: 0x%x\n", ntHeaders.OptionalHeader.Magic);
    printf("  AddressOfEntryPoint: 0x%x\n", ntHeaders.OptionalHeader.AddressOfEntryPoint);
    printf("  ImageBase: 0x%x\n", ntHeaders.OptionalHeader.ImageBase);
    printf("  SectionAlignment: 0x%x\n", ntHeaders.OptionalHeader.SectionAlignment);
    printf("  FileAlignment: 0x%x\n", ntHeaders.OptionalHeader.FileAlignment);
    printf("  SizeOfImage: 0x%x\n", ntHeaders.OptionalHeader.SizeOfImage);
    printf("  Subsystem: 0x%x\n", ntHeaders.OptionalHeader.Subsystem);
    printf("  NumberOfRvaAndSizes: %d\n", ntHeaders.OptionalHeader.NumberOfRvaAndSizes);

    printf("\nSection Information:\n");

    for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
        fread(&sectionHeader, sizeof(IMAGE_SECTION_HEADER), 1, file);

        printf("  Section %d: %s\n", i + 1, sectionHeader.Name);
        printf("    Virtual Size: 0x%x\n", sectionHeader.Misc.VirtualSize);
        printf("    Virtual Address (RVA): 0x%x\n", sectionHeader.VirtualAddress);
        printf("    Size of Raw Data: 0x%x\n", sectionHeader.SizeOfRawData);
        printf("    Pointer to Raw Data: 0x%x\n", sectionHeader.PointerToRawData);
        printf("    Characteristics: 0x%x\n", sectionHeader.Characteristics);
    }

    fclose(file);

    return 0;
}
