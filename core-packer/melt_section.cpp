/**
 *	PACKER32/64	- MELT section for PE files
 *	(c) ]HackingTeam[ 2013
 *	http://www.hackingteam.com
 *
 *	cod
 **/
#include <Windows.h>
#include <iostream>

#include "macro.h"
#include "rva.h"

static char *szSectionName[] = { ".hermit\0", ".pedll32\0", ".pedll64\0", ".peexe32\0", ".peexe64\0" };

PIMAGE_SECTION_HEADER lookup_core_section(PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS32 pImageNtHeaders32, BOOL dllTARGET)
{
	short NumberOfSections = pImageNtHeaders32->FileHeader.NumberOfSections;

	char *szHermitName = szSectionName[1];

	if (dllTARGET == FALSE)
		szHermitName = szSectionName[3];

	PIMAGE_SECTION_HEADER pResult = NULL;

	for(PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pImageNtHeaders32); NumberOfSections > 0; NumberOfSections--, pSection++)
	{
		if (memcmp(szHermitName, pSection->Name, 8) == 0)
		{
			std::cout << szHermitName << "/32bit section found in code" << std::endl;
			
			std::cout << "\tSize of raw data: " << std::hex << pSection->SizeOfRawData << std::endl;
			std::cout << "\t    Virtual size: " << std::hex << pSection->Misc.VirtualSize << std::endl;
			std::cout << "\t             RVA: " << std::hex << pSection->VirtualAddress << std::endl;
			std::cout << "\t Virtual Address: " << std::hex << rva2addr(pImageDosHeader, pImageNtHeaders32, CALC_OFFSET(LPVOID, pImageDosHeader, pSection->VirtualAddress)) << std::endl;

			pResult = pSection;
			break;
		}
	}

	return pResult;
}

PIMAGE_SECTION_HEADER lookup_core_section(PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_NT_HEADERS64 pImageNtHeaders64, BOOL dllTARGET)
{
	short NumberOfSections = pImageNtHeaders64->FileHeader.NumberOfSections;

	char *szHermitName = szSectionName[2];

	if (dllTARGET == FALSE)
		szHermitName = szSectionName[4];

	PIMAGE_SECTION_HEADER pResult = NULL;

	for(PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pImageNtHeaders64); NumberOfSections > 0; NumberOfSections--, pSection++)
	{
		if (memcmp(szHermitName, pSection->Name, 8) == 0)
		{
			std::cout << szHermitName << "/64bit section found in code" << std::endl;
			
			std::cout << "\tSize of raw data: " << std::hex << pSection->SizeOfRawData << std::endl;
			std::cout << "\t    Virtual size: " << std::hex << pSection->Misc.VirtualSize << std::endl;
			std::cout << "\t             RVA: " << std::hex << pSection->VirtualAddress << std::endl;
			std::cout << "\t Virtual Address: " << std::hex << rva2addr(pImageDosHeader, pImageNtHeaders64, CALC_OFFSET(LPVOID, pImageDosHeader, pSection->VirtualAddress)) << std::endl;

			pResult = pSection;
			break;
		}
	}

	return pResult;
}