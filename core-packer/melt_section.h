#ifndef __MELT_SECTION_H_
	#define __MELT_SECTION_H_

PIMAGE_SECTION_HEADER lookup_core_section(PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS32 pImageNtHeaders32, BOOL dllTARGET);
PIMAGE_SECTION_HEADER lookup_core_section(PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS64 pImageNtHeaders64, BOOL dllTARGET);

#endif
