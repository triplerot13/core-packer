#include <Windows.h>
#include "peasm/peasm.h"
#include "peasm/pesection.h"
#include "patchutils.h"

/**
 *	_EXPORT_TABLE_EXE
 **/
void MELT_EXPORT_TABLE_EXE(CPeAssembly *pTarget, CPeSection *pTargetSection, LPVOID lpRawDestin, int basesize, ULONG *table, PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_SECTION_HEADER pUnpackerCode)
{
	int stubsize = (int)(table[1] - table[0]);

		PIMAGE_DATA_DIRECTORY dir = pTarget->DataDirectory();

		BYTE watermark[8];

		if (dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0)
		{
			PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY) pTarget->RawPointer(dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

			memcpy(watermark, pTarget->RawPointer(pExportDir->Name), 8);
		}

		for(int i = 0; i < (sizeof(table) / sizeof(ULONG)); i++)
		{	//
			ULONG exportRVA = table[i];
			ULONG exportSymbolEntryPoint = exportRVA - ((ULONG) pImageDosHeader) - pUnpackerCode->VirtualAddress; // - pImageNtHeaders64->OptionalHeader.SectionAlignment); // 
		
			exportSymbolEntryPoint = pTargetSection->VirtualAddress() + basesize + exportSymbolEntryPoint; // - pTargetNtHeader->OptionalHeader.SectionAlignment;

			LPVOID lp = FindBlockMem((LPBYTE)lpRawDestin, pUnpackerCode->SizeOfRawData, (LPVOID) table[i], stubsize);

			if (lp != NULL)
				memset(lp, 0xCC, stubsize);
		}
}
