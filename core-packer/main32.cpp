#include <Windows.h>
#include <iostream>
#include "peasm/peasm.h"
#include "peasm/pesection.h"
#include "melt_random.h"
#include "melt_section.h"

#include "library.h"
#include "macro.h"
#include "rva.h"
#include "crypto/rc4.h"
#include "symbols.h"
#include "dll32.h"
#include "crypto/tea.h"
#include "patchutils.h"
#include "reloc.h"

#ifdef _BUILD32

extern BOOL WINAPI DllEntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
extern "C" VOID WINAPI __crt0Startup(DWORD);
extern "C" VOID WINAPI DELAYDECRYPT();

ULONG dll32_FakeExport[14] =
{
	(ULONG) _FakeEntryPoint0,
	(ULONG) _FakeEntryPoint1,
	(ULONG) _FakeEntryPoint2,
	(ULONG) _FakeEntryPoint3,
	(ULONG) _FakeEntryPoint4,
	(ULONG) _FakeEntryPoint5,
	(ULONG) _FakeEntryPoint6,
	(ULONG) _FakeEntryPoint7,
	(ULONG) _FakeEntryPoint8,
	(ULONG) _FakeEntryPoint9,
	(ULONG) _FakeEntryPointA,
	(ULONG) _FakeEntryPointB,
	(ULONG) _FakeEntryPointC,
	NULL
};

ULONG exe32_FakeExport[11] =
{
	(ULONG) _FakeEntryPoint0,
	(ULONG) _FakeEntryPoint1,
	(ULONG) _FakeEntryPoint2,
	(ULONG) _FakeEntryPoint3,
	(ULONG) _FakeEntryPoint4,
	(ULONG) _FakeEntryPoint5,
	(ULONG) _FakeEntryPoint6,
	(ULONG) _FakeEntryPoint7,
	(ULONG) _FakeEntryPoint8,
	(ULONG) _FakeEntryPoint9,
	NULL
};


struct _IAT_ENTRY {
	char	*szName;
	DWORD	Offset;
};

DWORD lookup_iat_symbol(PIMAGE_DOS_HEADER pDOSDescriptor, PIMAGE_NT_HEADERS32 pImageNtHeaders, PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor, DWORD dwRVA, CPeAssembly *pTarget)
{	// return 0
	const char *szSymbolName = NULL;
	const char *szModuleName = NULL;
	DWORD dwResult = 0;

	while(pImportDescriptor->Characteristics != 0 && szModuleName == NULL)
	{
		PULONG rvaName = (PULONG) rva2addr(pDOSDescriptor, pImageNtHeaders, (LPVOID) pImportDescriptor->Characteristics);
		PULONG iatRVA = (PULONG) rva2addr(pDOSDescriptor, pImageNtHeaders, (LPVOID) pImportDescriptor->FirstThunk);
		PULONG iat = (PULONG) rva2addr(pDOSDescriptor, pImageNtHeaders, (LPVOID) pImportDescriptor->FirstThunk);

		while(*rvaName != 0)
		{
			char *name = (char *) rva2addr(pDOSDescriptor, pImageNtHeaders, (LPVOID) ((*rvaName & 0x7fffffff) + 2));

			if (dwRVA == (DWORD) iat)
			{	// found!
				szModuleName = (const char *) rva2addr(pDOSDescriptor, pImageNtHeaders, (LPVOID) pImportDescriptor->Name);
				szSymbolName = name;
				break;
			}

			rvaName++;
			iatRVA++;
			iat++;
		}

		pImportDescriptor++;
	}

	if (szSymbolName == NULL && szModuleName == NULL)
	{	// exit!
		return dwResult;
	}

	PIMAGE_DATA_DIRECTORY pTargetDataDirectory = pTarget->DataDirectory();
	PIMAGE_IMPORT_DESCRIPTOR pTargetImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) pTarget->RawPointer(pTargetDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while(pTargetImportDescriptor->Characteristics != 0)
	{
		if (strcmp((const char *) pTarget->RawPointer(pTargetImportDescriptor->Name), szModuleName) == 0)
		{	// look into this module

			//std::cout << "\tEntries: " << std::endl;
			PULONG rvaName = (PULONG) pTarget->RawPointer(pTargetImportDescriptor->Characteristics);
			PULONG iatRVA = (PULONG) pTarget->RawPointer(pTargetImportDescriptor->FirstThunk);
			PULONG iat = (PULONG) pTargetImportDescriptor->FirstThunk;

			while(*rvaName != 0 && dwResult == 0)
			{
				char *name = (char *) pTarget->RawPointer((*rvaName & 0x7fffffff) + 2);

				if (name != NULL && strcmp(name, szSymbolName) == 0)
				{
					//std::cout << "\t " << std::hex << CALC_DISP(LPVOID, iatRVA, pInfectMe) << " " << std::hex << *iatRVA << " " << name << std::endl;
					
					dwResult = (DWORD) iat;
				}

			rvaName++;
			iatRVA++;
			iat++;
			}

		}

		pTargetImportDescriptor++;
	}

	return dwResult;
}


void fix_iat_symbol(LPVOID hProcessModule, PIMAGE_NT_HEADERS32 pSelf, PIMAGE_SECTION_HEADER pSection, DWORD dwNewVirtualAddress, CPeAssembly *destination)
{
	DWORD dwSize = 0;

	relocation_block_t *reloc = CALC_OFFSET(relocation_block_t *, hProcessModule, pSelf->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	DWORD dwImageBase = pSelf->OptionalHeader.ImageBase;

	if (dwImageBase != (DWORD) hProcessModule)
		dwImageBase = (DWORD) hProcessModule;
	DWORD dummy = 0;

	PIMAGE_IMPORT_DESCRIPTOR pImageDosDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) rva2addr((PIMAGE_DOS_HEADER) hProcessModule, pSelf, (LPVOID)(pSelf->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));

	LPVOID lpSection = rva2addr((PIMAGE_DOS_HEADER) hProcessModule, pSelf, (LPVOID) pSection->VirtualAddress);
	VirtualProtect(lpSection, pSection->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &dummy);	// enable RWX on original page!

	DWORD dwSelfImageBase = pSelf->OptionalHeader.ImageBase;
	DWORD dwTargetImageBase = (DWORD) destination->getBaseAddress();


	while(reloc != NULL)
	{
		if (reloc->PageRVA >= pSection->VirtualAddress && reloc->PageRVA < (pSection->VirtualAddress + pSection->Misc.VirtualSize))
		{	// good! add this page!
			DWORD blocksize = reloc->BlockSize - 8;
			relocation_entry *entry = CALC_OFFSET(relocation_entry *, reloc, 8);
			
			while(blocksize > 0)
			{	// fetch instruction and patch!
				short type = ((*entry & 0xf000) >> 12);
				long offset = (*entry & 0x0fff);

				ULONG *ptr = (PULONG) rva2addr((PIMAGE_DOS_HEADER) hProcessModule, pSelf, (LPVOID) (offset + reloc->PageRVA));
				ULONG value = *ptr;// - dwSelfImageBase;
				LPBYTE prefix = CALC_OFFSET(LPBYTE, ptr, -2);	//

				ULONG dwNewValue = 0;

				if (type == 0x03 &&	// 32bit offset
					prefix[0] == 0xFF &&
					prefix[1] == 0x15)
				{	// require fix!!!
					DWORD dwNewSymbol = lookup_iat_symbol((PIMAGE_DOS_HEADER) hProcessModule, pSelf, pImageDosDescriptor, value, destination);

					if (dwNewSymbol != 0)
						*ptr = dwNewSymbol + dwSelfImageBase;
				}

				entry++;
				blocksize -= 2;
			}

			dwSize += reloc->BlockSize;
		}

		reloc = CALC_OFFSET(relocation_block_t *, reloc, reloc->BlockSize);
		if (reloc->BlockSize == 0) reloc = NULL;
	}
}

void compare_iat_value(struct _IAT_ENTRY *module, int size, char *name, PULONG iat)
{
	while(size > 0)
	{

		if (strcmp(name, module->szName) == 0)
		{	// found!
			module->Offset = (DWORD) iat;
			return;	// exit!
		}

		module++;
		size--;
	}
}

DWORD get_iat_value(struct _IAT_ENTRY *module, int size, char *name)
{
	while(size > 0)
	{
		if (strcmp(name, module->szName) == 0)
		{	// found!
			return module->Offset;
		}

		module++;
		size--;
	}

	return 0;
}

void Patch_EXPORT_SYMBOL(LPVOID lpBaseBlock, LPBYTE lpInitialMem, DWORD dwSize, LPVOID lpSignature, DWORD newOffset, DWORD oldOffset)
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

int main32(int argc, char *argv[])
{
	srand(GetTickCount());	// initialize for (rand)

	if (argc == 1)
	{
		std::cout << "packer32 infile outfile" << std::endl;
		std::cout << "packer32 in/outfile" << std::endl;
	}

	HMODULE hModule = GetModuleHandle(NULL);

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER) hModule;
	PIMAGE_NT_HEADERS32 pImageNtHeaders32 = CALC_OFFSET(PIMAGE_NT_HEADERS32, pImageDosHeader, pImageDosHeader->e_lfanew);

	if (pImageNtHeaders32->Signature != IMAGE_NT_SIGNATURE)
	{	
		std::cout << "Sorry! I can't check myself!";
		return FALSE;	
	}

	
	CPeAssembly *pTarget = new CPeAssembly();

	pTarget->Load(argv[1]);

	CPeAssembly *morph = NULL;

	if (argc > 3)
		morph = load_random(argv[3]);
	else
		morph = load_random(NULL);
	
	// check "morph" object
		// find patterns!
	//PIMAGE_DOS_HEADER pTarget = (PIMAGE_DOS_HEADER) InternalLoadLibrary(argv[1], 0);
	//PIMAGE_NT_HEADERS pTargetNtHeader = CALC_OFFSET(PIMAGE_NT_HEADERS, pTarget, pTarget->e_lfanew);
	
	PIMAGE_SECTION_HEADER pUnpackerCode = NULL;
	
	if (pTarget->IsDLL())
	{	// it's a DLL?!?!?
		std::cout << "Input file is DLL!" << std::endl;

		pUnpackerCode = lookup_core_section(pImageDosHeader, pImageNtHeaders32, TRUE);
	}
	else if (pTarget->IsEXE())
	{
		std::cout << "Input file is EXECUTABLE!" << std::endl;
		pUnpackerCode = lookup_core_section(pImageDosHeader, pImageNtHeaders32, FALSE);
	}
	else
	{
		std::cout << "Unsupported input file!" << std::endl;
		return 0;
	}

	if (pUnpackerCode == NULL)
	{	//  break!
		std::cout << "Cannot find <PACKER> in sections" << std::endl;
		return 0;
	}

	size_t required_reloc_space = SizeOfRelocSection(pImageDosHeader, pImageNtHeaders32, pUnpackerCode);

	CPeSection *relocSection = pTarget->LookupSectionByName(".reloc");

	if (relocSection != NULL)
	{
		size_t relocsize = relocSection->VirtualSize();
		
		if (relocsize + required_reloc_space > relocSection->SizeOfRawData())
		{	// expande
			relocSection->AddSize(required_reloc_space);
		}
	}


	char passKey[16];

	for(int i =0; i < sizeof(passKey); i++)
		passKey[i] = rand() % 256;

	BYTE rc4sbox[256];
	
	PIMAGE_DATA_DIRECTORY DataDir = pTarget->DataDirectory();

	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) pTarget->RawPointer(DataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	
	PIMAGE_SECTION_HEADER pDestSection = NULL;

	const char *szSectionName = random_section_name();
	
	if (argc > 4)
	{	// test mode -- SET SECTION NAME
		szSectionName = argv[4];
	}

	CPeSection *pTargetSection = NULL;

	int newVirtualSize = RoundUp(pUnpackerCode->Misc.VirtualSize + ((rand() % 16) * 1024), 1024);

	if (newVirtualSize < (4096+1024))
		newVirtualSize = 4096+1024;

	if (argc > 5)
	{	// test mode -- SET VIRTUAL SIZE
		newVirtualSize = atoi(argv[5]);
	}


	if (pTarget->IsDLL())
	{
		pTargetSection = pTarget->AddSection(szSectionName, 0x0, newVirtualSize);	// move section in "head"
	}
	else if (pTarget->IsEXE())
	{
		//morph->setBaseAddress(pTarget->getBaseAddress());
		CPeSection *pMorphSection = morph->getSection(0);
		
		if (pMorphSection->SizeOfRawData() < newVirtualSize)
		{	// skip!
			std::cout << "[ERROR] Cannot build this file! " << std::endl;
			return -1;
		}
		// 2013.04.18 -  modified "virtualSize" to "pMorphSection"
		/*if (newVirtualSize < pMorphSection->SizeOfRawData())
		{	//
			newVirtualSize = pMorphSection->SizeOfRawData();
		}*/

		pTargetSection = pTarget->AddSection(szSectionName, 0x1000, newVirtualSize);	// move section in "head"
		
		memset(pTargetSection->RawData(), 0x90, newVirtualSize);
		
		// 2013.04.19 - transfer a "view"
		
		int raw_offset = 0;

		// randomize _raw_offset
		if (pMorphSection->SizeOfRawData() > newVirtualSize)
		{
			raw_offset = morph->NtHeader()->OptionalHeader.AddressOfEntryPoint - pMorphSection->VirtualAddress();
		}

		LPVOID lpOffsetCurrent = CALC_OFFSET(LPVOID, pMorphSection->RawData(), raw_offset);
		LPVOID lpOffsetEnd = CALC_OFFSET(LPVOID, pMorphSection->RawData(), pMorphSection->SizeOfRawData());
		LPVOID lpDestination = pTargetSection->RawData();

		virtualaddress_t size = newVirtualSize;

		while(size > 0)
		{
			int diff = ((int) lpOffsetEnd - (int) lpOffsetCurrent);

			if (diff < size)
			{
				memcpy(lpDestination, lpOffsetCurrent, diff);
				lpDestination = CALC_OFFSET(LPVOID, lpDestination, diff);
				size -= diff;
				lpOffsetCurrent = pMorphSection->RawData();	// reset to begin
			}
			else
			{
				memcpy(lpDestination, lpOffsetCurrent, size);
				size = 0;
			}
		}

	}
	
	struct _IAT_ENTRY	kernel32_iat[] = {
		{	"LoadLibraryA",		0	},
		{	"GetProcAddress",	0	},
		{	"CreateFileA",		0	},
		{	"GetModuleFileNameA",	0 },
		{	"ReadFile",			0	},
		{	"SetFilePointer",	0	},
		{	"CloseHandle",		0	}
	};


	fix_iat_symbol(pImageDosHeader, pImageNtHeaders32,  pUnpackerCode, 0x0, pTarget);

	#define KERNEL32_IAT_LENGTH	sizeof(kernel32_iat) / sizeof(_IAT_ENTRY)

	while(pImportDescriptor->Characteristics != 0)
	{
		//std::cout << "Name " << (char *) pInfectMe->RawPointer(pImportDescriptor->Name) << std::endl;
		
		//std::cout << "\tEntries: " << std::endl;
		PULONG rvaName = (PULONG) pTarget->RawPointer(pImportDescriptor->Characteristics);
		PULONG iatRVA = (PULONG) pTarget->RawPointer(pImportDescriptor->FirstThunk);
		PULONG iat = (PULONG) pImportDescriptor->FirstThunk;

		while(*rvaName != 0)
		{
			char *name = (char *) pTarget->RawPointer((*rvaName & 0x7fffffff) + 2);

			if (name != NULL)
			{
				//std::cout << "\t " << std::hex << CALC_DISP(LPVOID, iatRVA, pInfectMe) << " " << std::hex << *iatRVA << " " << name << std::endl;

				compare_iat_value(kernel32_iat, sizeof(kernel32_iat) / sizeof(struct _IAT_ENTRY), name, iat);
			}
			else
			{	// by ordinal
				//LPDWORD sticazzi = (LPDWORD) pInfectMe->RawPointer((*rvaName & 0x7fffffff) + 2);
				//std::cout << "\t [ORDINAL] " << std::hex << CALC_DISP(LPVOID, iatRVA, pInfectMe) << " " << std::hex << *x << " " << std::endl;
			}

			rvaName++;
			iatRVA++;
			iat++;
		}

		pImportDescriptor++;
	}
	
	for(int i = 0; i < pTarget->NumberOfSections(); i++)
	{	// each section must be packed
		if (pTarget->IsDLL())
		{
			init_sbox(rc4sbox);
			init_sbox_key(rc4sbox, (BYTE *) passKey, 16);
		}
		else
		{
			uint32_t *key = (uint32_t *) rc4sbox;
			memcpy(key, passKey, 16);
		}

		CPeSection *pProcessSection = pTarget->getSection(i);
		PIMAGE_SECTION_HEADER pSectionHeader = pProcessSection->GetSectionHeader();

		if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_SHARED) == IMAGE_SCN_MEM_SHARED)
		{	// skip current section
		}
		else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE)
		{
			//pSectionHeader->Characteristics |= 0x02;
			
			if (pTarget->IsDLL())
				cypher_msg(rc4sbox, (PBYTE) pProcessSection->RawData(), pProcessSection->SizeOfRawData());
			else
			{
				uint32_t *key = (uint32_t *) rc4sbox;
				LPDWORD encptr = (LPDWORD) pProcessSection->RawData();

				for(DWORD dwPtr = 0; dwPtr < pProcessSection->SizeOfRawData(); dwPtr += 8, encptr += 2)
					tea_encrypt((uint32_t *) encptr, key);
			}

			//pSectionHeader->Characteristics ^= IMAGE_SCN_MEM_EXECUTE;
			if (strcmp((char *) pSectionHeader->Name, ".text") == 0)
			{	// text section!
				//pSectionHeader->Misc.VirtualSize = pSectionHeader->SizeOfRawData;
			}

		}
		else if (memcmp(pSectionHeader->Name, ".data", 5) == 0)
		{
			//pSectionHeader->Characteristics |= 0x02;

			if (pTarget->IsDLL())
				cypher_msg(rc4sbox, (PBYTE) pProcessSection->RawData(), pProcessSection->SizeOfRawData());
			else
			{
				uint32_t *key = (uint32_t *) rc4sbox;
				LPDWORD encptr = (LPDWORD) pProcessSection->RawData();

				for(DWORD dwPtr = 0; dwPtr < pProcessSection->SizeOfRawData(); dwPtr += 8, encptr += 2)
					tea_encrypt((uint32_t *) encptr, key);
			}

		}

		//else if (memcmp(pSectionHeader->Name, ".rdata", 6) == 0)
		//{
		//	pSectionHeader->Characteristics |= 0x03;

		//	/*DWORD sizeOfSection = 
		//		pTargetNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress 
		//			- pProcessSection->VirtualAddress 
		//			- pTargetNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
		//				
		//	LPVOID sectionAddress = rva2addr(pTarget, pTargetNtHeader, (LPVOID) (pProcessSection->VirtualAddress + pTargetNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size));*/

		//	if (pTarget->IsDLL())
		//		cypher_msg(rc4sbox, (PBYTE) sectionAddress, sizeOfSection);
		//	else
		//	{
		//		uint32_t *key = (uint32_t *) rc4sbox;
		//		LPDWORD encptr = (LPDWORD) sectionAddress;

		//		for(DWORD dwPtr = 0; dwPtr < sizeOfSection; dwPtr += 8, encptr += 2)
		//			tea_encrypt((uint32_t *) encptr, key);
		//	}
		//}

	}
	
	//memcpy(pTargetSection->Name, szHermitName, 8);
	
	//PIMAGE_SECTION_HEADER pTargetSection = IMAGE_FIRST_SECTION(pTargetNtHeader);
	
	if (pTarget->IsDLL())
	{	// DLL stub .. SECTION RWX
		pTargetSection->GetSectionHeader()->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE;
	}
	else
	{	// EXE STUB ... SECTION RX
		pTargetSection->GetSectionHeader()->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;
	}

	// Laod Config Data <-> REMOVE!!!
	if (DataDir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress != 0 && pTarget->IsDLL() == FALSE)
	{
		std::cout << "\t**WARNING**\tLOAD_CONFIG Data Directory isn't NULL! Removing! " << std::endl;

		DataDir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
		DataDir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
	}

	PIMAGE_EXPORT_DIRECTORY ExportDirectory =  
		(PIMAGE_EXPORT_DIRECTORY) pTarget->RawPointer(DataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		

	LPDWORD AddressOfFunctions = NULL;
	
	if (ExportDirectory != NULL)
	{
		 AddressOfFunctions = (LPDWORD) pTarget->RawPointer(ExportDirectory->AddressOfFunctions);
	}
	else
	{
		ExportDirectory = NULL;
	}


	ULONG *table = NULL;

	if (pTarget->IsDLL()) 
		table = dll32_FakeExport;
	else
		table = exe32_FakeExport;

	LPVOID lpRawSource = rva2addr(pImageDosHeader, pImageNtHeaders32, CALC_OFFSET(LPVOID, pImageDosHeader, pUnpackerCode->VirtualAddress));
	
	int maxoffset = (pTargetSection->VirtualSize() - pUnpackerCode->SizeOfRawData);
	
	int basesize  = 0;

	if (maxoffset == 0)
		basesize = 0;
	else
		basesize = rand() % maxoffset;	// offset

	if (argc > 6)
	{	// test!!!
		basesize = atoi(argv[6]);
	}

	//---- TO FIX!!! ----
	/* 
	 *	Transfer_Reloc_Process -> PageRVA 
	*/
	basesize = basesize & 0xfffff000;	// bugfix
	//---- TO FIX!!! ----

	std::cout << "[CONFIG] Section Name: " << szSectionName << std::endl;
	std::cout << "[CONFIG]         base: " << std::hex << basesize << std::endl;
	std::cout << "[CONFIG]         size: " << std::hex << pTargetSection->VirtualSize() << std::endl;

	LPVOID lpRawDestin = CALC_OFFSET(LPVOID, pTargetSection->RawData(), basesize);	// an offset inside acceptable range


	/*******************************************************************************************
	 * WARNING!!!
	 *	The next memcpy transfer section from our binary into target!
	 *	All patch/modification must be done after next line!
	 ******************************************************************************************/
	memcpy(lpRawDestin, lpRawSource, pUnpackerCode->SizeOfRawData);

	/**
	 *	Decryption routine
	 **/
	if (pTarget->IsDLL())
	{	// process code for encryption of "RC4"
	
	}
	else
	{	// process code for encryption of TEA
		void *start = static_cast<void *>(&tea_decrypt);
		void *end = static_cast<void *>(&tea_decrypt_end_marker);
		int size = static_cast<int>((int) end - (int) start);

		char *encrypt = (char *) FindBlockMem((LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, start, size);

		while(size-- > 0) 
		{
			*encrypt++ ^= 0x66;
		}

	}

	/**
	 *	EXPORT SYMBOLS
	 **/
	if (pTarget->IsDLL())
	{	// DLL - Patch 
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
	else
	{	// EXE - overwrite "export"
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

	DWORD dwOffset = RoundUp(pUnpackerCode->SizeOfRawData, 16);

	ULONG offsetEntryPoint = (ULONG) (DllEntryPoint);

	ULONG rvaEntryPoint = offsetEntryPoint - ((ULONG) pImageDosHeader) - pUnpackerCode->VirtualAddress; // - pImageNtHeaders64->OptionalHeader.SectionAlignment); // 
	
	DWORD AddressOfEntryPoint = pTarget->NtHeader()->OptionalHeader.AddressOfEntryPoint;
	
	if (pTarget->IsDLL() == FALSE)
	{	// it's a dll!!
		offsetEntryPoint = (ULONG) (__crt0Startup);
		rvaEntryPoint = offsetEntryPoint - ((ULONG) pImageDosHeader) - pUnpackerCode->VirtualAddress; // - pImageNtHeaders64->OptionalHeader.SectionAlignment); // 
	}
	

	//////////////////////
	// write new entry point!
	pTarget->NtHeader()->OptionalHeader.AddressOfEntryPoint = pTargetSection->VirtualAddress() + basesize + rvaEntryPoint; // - pTargetNtHeader->OptionalHeader.SectionAlignment;
	///////////////////////
	
	if (!get_iat_value(kernel32_iat, KERNEL32_IAT_LENGTH, "GetProcAddress") || !get_iat_value(kernel32_iat, KERNEL32_IAT_LENGTH, "LoadLibraryA"))
	{
		std::cout << "Error! KERNEL32!GetProcAddress/LoadLibraryA not found in IAT" << std::endl;
		return 0;
	}

	ULONG64 *passKeyPtr = (ULONG64*) &passKey;

	//Patch_MARKER(pTarget, (LPBYTE) lpRawDestin, pSectionInput->SizeOfRawData, &_EntryPoint, 9, AddressOfEntryPoint);

	/**
	 *	patch code
	 **/
	if (pTarget->IsDLL())
	{	// DLL ! FIX entry point
		Patch_Entry(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_EntryPoint, 0x10, AddressOfEntryPoint-0x1000);
		Patch_MARKER(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_dll32_LoadLibraryA, 0x12, get_iat_value(kernel32_iat, KERNEL32_IAT_LENGTH, "LoadLibraryA"));
		Patch_MARKER(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_dll32_GetProcAddress, 0x12, get_iat_value(kernel32_iat, KERNEL32_IAT_LENGTH, "GetProcAddress"));
		Patch_MARKER(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_GetModuleFileNameA, 0x12, get_iat_value(kernel32_iat, KERNEL32_IAT_LENGTH, "GetModuleFileNameA"));
	}
	else
	{	// EXE ! FIX entry point
		Patch_Entry(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_CrtStartup, 0x0A, AddressOfEntryPoint, 0x0a);
		Patch_Entry(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_GETBASE, 0x0a, pTargetSection->VirtualAddress() + basesize, 0x01);
		//Patch_MARKER(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_exe_LoadLibraryA, 0x0c, get_iat_value(kernel32_iat, KERNEL32_IAT_LENGTH, "LoadLibraryA"));
		//Patch_MARKER(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_exe_GetProcAddress, 0x0c, get_iat_value(kernel32_iat, KERNEL32_IAT_LENGTH, "GetProcAddress"));
		Patch_MARKER(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_exe_GetModuleFileNameA, 0x0c, get_iat_value(kernel32_iat, KERNEL32_IAT_LENGTH, "GetModuleFileNameA"));
	}

	
	if (get_iat_value(kernel32_iat, KERNEL32_IAT_LENGTH, "CreateFileA") == 0)
	{
		ULONG exportRVA = (pTarget->IsDLL()) ? (ULONG) _CreateFileA : (ULONG) _exe_CreateFileA;

		ULONG exportSymbolEntryPoint = exportRVA - ((ULONG) pImageDosHeader) - pUnpackerCode->VirtualAddress; // - pImageNtHeaders64->OptionalHeader.SectionAlignment); // 
		
		exportSymbolEntryPoint = pTargetSection->VirtualAddress() + basesize + exportSymbolEntryPoint; // - pInfectMeNtHeader->OptionalHeader.SectionAlignment;
		LPBYTE lp = (LPBYTE) FindBlockMem((LPBYTE)lpRawDestin, pTargetSection->SizeOfRawData(), (pTarget->IsDLL()) ? (LPVOID) _CreateFileA : (LPVOID) _exe_CreateFileA, 0x12);
		char symbolname[17] = { '~', 'C', 'r', 'e', 'a', 't', 'e', 0x01, 0x01, 0x01, 0x01, 'F', 'i', 'l','e','A',0x00};

		memcpy(lp, symbolname, 7);
		memcpy(lp+0x0b, symbolname+0x0b,6);

	}
	else
	{	// applying patch!!!
		Patch_MARKER(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, (pTarget->IsDLL()) ? &_CreateFileA : &_exe_CreateFileA, 0x12, get_iat_value(kernel32_iat, KERNEL32_IAT_LENGTH, "CreateFileA"));
	}

	Patch_MARKER(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, (pTarget->IsDLL()) ? &_SetFilePointer : &_exe_SetFilePointer, 0x12, get_iat_value(kernel32_iat, KERNEL32_IAT_LENGTH, "SetFilePointer"));
	Patch_MARKER(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, (pTarget->IsDLL()) ? &_ReadFile : &_exe_ReadFile, 0x12, get_iat_value(kernel32_iat, KERNEL32_IAT_LENGTH, "ReadFile"));
	Patch_MARKER(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, (pTarget->IsDLL()) ? &_CloseHandle : &_exe_CloseHandle, 0x12, get_iat_value(kernel32_iat, KERNEL32_IAT_LENGTH, "CloseHandle"));

	Patch_MARKER_QWORD(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_rc4key0, passKeyPtr[0]);
	Patch_MARKER_QWORD(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_rc4key1, passKeyPtr[1]);
	Patch_MARKER_DWORD(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &dwRelocSize, DataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	Patch_MARKER_DWORD(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &lpRelocAddress, DataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	
	if (pTarget->IsDLL())
	{	// nothing!!!
	}
	else
	{	// save preferred image base
		Patch_MARKER_DWORD(pTarget, (LPBYTE) lpRawDestin, pUnpackerCode->SizeOfRawData, &_baseAddress, pTarget->NtHeader()->OptionalHeader.ImageBase);
	}

	// Transfer our .reloc into .reloc of target
	
	DWORD dwNewRelocSize = 0;
	DWORD dwNewRelocOffset = 0;
	
	if (relocSection != NULL)
	{	// there are a relocation
		// space available into section!
		dwOffset = RoundUp(relocSection->VirtualSize(), 0x10);
		dwNewRelocOffset = relocSection->VirtualAddress() + dwOffset;
		LPVOID lpWriteInto = CALC_OFFSET(LPVOID, relocSection->RawData(), dwOffset);
		DWORD newVirtualAddress = pTargetSection->VirtualAddress() + basesize;
		PIMAGE_NT_HEADERS32 pTargetNtHeader = pTarget->NtHeader();
		dwNewRelocSize = Transfer_Reloc_Table(pImageDosHeader, pImageNtHeaders32, pUnpackerCode, lpWriteInto, newVirtualAddress, pTarget, pTargetNtHeader);
		relocSection->GetSectionHeader()->Misc.VirtualSize = dwOffset + dwNewRelocSize;
	}
	else
	{	// allocate new section inside ".text" section
		// cannot process this object!!!!!
		//dwOffset = RoundUp(pUnpackerCode->Misc.VirtualSize, 16);
		//dwNewRelocSize = Transfer_Reloc_Table(pImageDosHeader, pImageNtHeaders32, pUnpackerCode, CALC_OFFSET(LPVOID, lpRawDestin, dwOffset + basesize ), pTargetSection->VirtualAddress(), pTarget, pTarget->NtHeader());
		//dwNewRelocOffset = pTargetSection->VirtualAddress() + dwOffset;

		// no relocation required?
		//Patch_Reloc(pImageDosHeader, pImageNtHeaders32, pUnpackerCode, NULL, pTargetSection->VirtualAddress() + basesize, pTarget, pTarget->NtHeader());
	}

	pTarget->NtHeader()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = dwNewRelocSize;
	pTarget->NtHeader()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = dwNewRelocOffset;

	//pTarget->MergeSection(pTargetSection, pTarget->getSection(1));

	//pTargetSection->

	if (argc > 2)
	{
		char tmpName[MAX_PATH];

		strcpy_s(tmpName, argv[2]);
		int lentmp = strlen(tmpName);

		if (tmpName[lentmp-1] == '\\')
		{	// random name!
			SYSTEMTIME time;
			GetSystemTime(&time);
			sprintf_s(tmpName, "%s%04i%02i%02i_%02i%02i.exe", argv[2], time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute);
		}
		pTarget->Save(tmpName);
	}
	else
		pTarget->Save(argv[1]);

	delete pTarget;	// destroy and release memory!
	delete morph;		// destroy and release memory!

	return 0;
}

#endif
