#include <Windows.h>
#include <iostream>

#include "peasm/peasm.h"
#include "peasm/pesection.h"
#include "patchutils.h"


static void Patch_EXPORT_SYMBOL(LPVOID lpBaseBlock, LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, DWORD newOffset, DWORD oldOffset)
{
	LPVOID lpInitialByte = FindBlockMem((LPBYTE) lpInitialMem, dwSize, lpSignature, 0x12);

	if (lpInitialByte != NULL)
	{
		for(int i = 0; i < 0x20; i++)
		{
			DWORD dwMarker = 0x10001000;
			if (memcmp(CALC_OFFSET(LPVOID, lpInitialByte, i), &dwMarker, sizeof(DWORD))	== 0)
			{
				LPDWORD c = CALC_OFFSET(LPDWORD, lpInitialByte, i);
				*c = oldOffset;
				return;
			}
		}

	}

}

/**
 *	_EXPORT_TABLE_EXE
 **/
void MELT_EXPORT_TABLE_DLL(CPeAssembly *pTarget, CPeSection *pTargetSection, LPVOID lpRawDestin, int basesize, ULONG *table, PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_SECTION_HEADER pUnpackerCode)
{
	PIMAGE_DATA_DIRECTORY pDataDir = pTarget->DataDirectory();

	PIMAGE_EXPORT_DIRECTORY ExportDirectory =  
		(PIMAGE_EXPORT_DIRECTORY) pTarget->RawPointer(pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	LPDWORD AddressOfFunctions = (LPDWORD) pTarget->RawPointer(ExportDirectory->AddressOfFunctions);

	for(int i=0; i < ExportDirectory->NumberOfFunctions; i++)
	{
		ULONG exportRVA = table[i];

		if (exportRVA == NULL)
		{
			std::cout << "Warning -> more exports into module!" << std::endl;
			continue;	// no more symbols!
		}

		ULONG exportSymbolEntryPoint = exportRVA - ((ULONG) pImageDosHeader) - pUnpackerCode->VirtualAddress; // - pImageNtHeaders64->OptionalHeader.SectionAlignment); // 
		
		exportSymbolEntryPoint = pTargetSection->VirtualAddress() + basesize + exportSymbolEntryPoint; // - pTargetNtHeader->OptionalHeader.SectionAlignment;
		
		DWORD dwOldValue = AddressOfFunctions[i];
		AddressOfFunctions[i] = exportSymbolEntryPoint;
		
		Patch_EXPORT_SYMBOL(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, (LPVOID) table[i], exportSymbolEntryPoint, dwOldValue - 0x1000);
	}
}
