#ifndef __RELOC_H_
	#define __RELOC_H_

#include "peasm/peasm.h"
#include "peasm/pesection.h"

typedef struct _relocation_block {
	DWORD	PageRVA;
	DWORD	BlockSize;
} relocation_block_t;

#define base_relocation_block_t relocation_block_t
#define base_relocation_entry_t relocation_entry_t 

typedef short relocation_entry;

typedef struct base_relocation_entry
{
	WORD offset : 12;
	WORD type : 4;
} base_relocation_entry_t;



#ifndef _UNPACKERSECTION

	#ifdef _BUILD64
	void Reloc_Process(LPVOID pModule, PIMAGE_NT_HEADERS64 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionPointer, LPVOID lpRelocAddress, DWORD dwRelocSize);
	
	size_t SizeOfRelocSection(LPVOID hProcessModule, PIMAGE_NT_HEADERS64 pSelf, PIMAGE_SECTION_HEADER pSection);

	#else
	//void Reloc_Process(LPVOID pModule, PIMAGE_NT_HEADERS32 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionPointer, LPVOID lpRelocAddress, DWORD dwRelocSize);
	void Reloc_Process(LPVOID pModule, PIMAGE_NT_HEADERS32 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionPointer, LPVOID lpRelocAddress, DWORD dwRelocSize, PIMAGE_SECTION_HEADER pTextPointer, LPVOID lpTextAddr);
	void reloctext(LPVOID pModule, PIMAGE_NT_HEADERS32 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionPointer, LPVOID lpRelocAddress, DWORD dwRelocSize, LPVOID lpTextAddr);
	
	DWORD Transfer_Reloc_Table(LPVOID hProcessModule, PIMAGE_NT_HEADERS32 pSelf, PIMAGE_SECTION_HEADER pSection, LPVOID lpOutput, DWORD dwNewVirtualAddress, CPeAssembly *destination, PIMAGE_NT_HEADERS32 pNewFile);
	DWORD Patch_Reloc(LPVOID hProcessModule, PIMAGE_NT_HEADERS32 pSelf, PIMAGE_SECTION_HEADER pSection, LPVOID lpOutput, DWORD dwNewVirtualAddress, CPeAssembly *destination, PIMAGE_NT_HEADERS32 pNewFile);
	
	size_t SizeOfRelocSection(LPVOID hProcessModule, PIMAGE_NT_HEADERS32 pSelf, PIMAGE_SECTION_HEADER pSection);
	
	#endif

#endif

#endif

