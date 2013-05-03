#include <Windows.h>
#include "macro.h"
#include "melt_reloc.h"
#include "peasm/peasm.h"
#include "peasm/pesection.h"

//#include "rva.h"

//#include "symbols.h"
//
//
//#ifdef _BUILD32
//	#include "dll32.h"
//#endif
//
//#pragma section(".hermit", read, execute)
//
//// Parse reloc table
//#ifdef _BUILD64
//#pragma code_seg(".hermit")
//void Reloc_Process(LPVOID pModule, PIMAGE_NT_HEADERS64 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionPointer, LPVOID lpRelocAddress, DWORD dwRelocSize)
//{
//	if (dwRelocSize == 0 || lpRelocAddress == NULL)
//		return;	// no reloc table here!
//
//	base_relocation_block_t *relocation_page = (base_relocation_block_t *) lpRelocAddress;
//
//	if (relocation_page == NULL)
//		return;	// no relocation page available!
//
//	// for each page!
//	while(relocation_page->BlockSize > 0)
//	{
//		if (relocation_page->PageRVA < pSectionPointer->VirtualAddress || relocation_page->PageRVA > (pSectionPointer->VirtualAddress + pSectionPointer->Misc.VirtualSize))
//		{	// skip current page!
//			relocation_page = CALC_OFFSET(base_relocation_block_t *, relocation_page, relocation_page->BlockSize);
//		}
//		else
//		{	// ok.. we can process this page!
//			typedef short relocation_entry;
//
//			int BlockSize = relocation_page->BlockSize - 8;
//			relocation_entry *entries = CALC_OFFSET(relocation_entry *, relocation_page, 8);
//
//			while(BlockSize > 0)
//			{
//				short type = ((*entries & 0xf000) >> 12);
//				long offset = (*entries & 0x0fff);
//
//				ULONG64 *ptr = CALC_OFFSET(PULONG64, pModule, offset + relocation_page->PageRVA);
//				ULONG64 value = *ptr;
//				ULONG64 dwNewValue = 0;
//
//				switch(type)
//				{
//					case IMAGE_REL_BASED_HIGHLOW:
//						value = value - pImageNtHeader->OptionalHeader.ImageBase;
//						value = value + (DWORD) pModule;
//						*ptr = value;
//						break;
//					case IMAGE_REL_BASED_DIR64:
//						dwNewValue = value - pImageNtHeader->OptionalHeader.ImageBase + (ULONG64) pModule;
//						*ptr = dwNewValue;
//						break;
//				}
//
//				entries++;
//				BlockSize -= 2;
//			}
//
//			relocation_page = CALC_OFFSET(base_relocation_block_t *, relocation_page, relocation_page->BlockSize);
//		}
//	}
//
//}
//#endif
//
//#ifdef _BUILD32
//
//#pragma code_seg(".hermit")
//BOOL reloc_is_text(PIMAGE_NT_HEADERS32 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionText, DWORD offset)
//{
//	DWORD ImageBase = (DWORD) _baseAddress;
//
//	DWORD minVirtualAddress = pSectionText->VirtualAddress;
//	DWORD maxVirtualAddress = pSectionText->VirtualAddress + pSectionText->Misc.VirtualSize;
//
//	offset -= ImageBase;
//	
//	if (minVirtualAddress <= offset && offset < maxVirtualAddress)
//		return TRUE;
//
//	return FALSE;
//}
//
//#pragma code_seg(".hermit")
//void reloctext(LPVOID pModule, PIMAGE_NT_HEADERS32 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionPointer, LPVOID lpRelocAddress, DWORD dwRelocSize, LPVOID lpTextAddr)
//{
//	DWORD ImageBase = (DWORD) _baseAddress;
//
//	base_relocation_block_t *relocation_page = (base_relocation_block_t *) lpRelocAddress;
//
//	if (dwRelocSize == 0 || relocation_page == NULL)
//		return;	// no reloc table here!
//
//	// for each page!
//	while(relocation_page->BlockSize > 0)
//	{
//		if (relocation_page->PageRVA < pSectionPointer->VirtualAddress || relocation_page->PageRVA > (pSectionPointer->VirtualAddress + pSectionPointer->Misc.VirtualSize))
//		{	// skip current page!
//			relocation_page = CALC_OFFSET(base_relocation_block_t *, relocation_page, relocation_page->BlockSize);
//		}
//		else
//		{	// ok.. we can process this page!
//			typedef short relocation_entry;
//
//			int BlockSize = relocation_page->BlockSize - 8;
//			relocation_entry *entries = CALC_OFFSET(relocation_entry *, relocation_page, 8);
//
//			while(BlockSize > 0)
//			{
//				short type = ((*entries & 0xf000) >> 12);
//				long offset = (*entries & 0x0fff);
//
//				//ULONG *ptr = CALC_OFFSET(PULONG, pModule, offset + relocation_page->PageRVA);
//				ULONG *ptr = CALC_OFFSET(PULONG, lpTextAddr, offset + relocation_page->PageRVA - 0x1000);	// base address of .text
//				ULONG value = *ptr;
//				ULONG dwNewValue = 0;
//
//				if (reloc_is_text(pImageNtHeader, pSectionPointer, (DWORD) value) == FALSE)
//				{
//					switch(type)
//					{
//						case IMAGE_REL_BASED_HIGHLOW:
//							value = value - ImageBase;
//							value = value + (DWORD) pModule;
//							*ptr = value;
//							break;
//						case IMAGE_REL_BASED_DIR64:
//							dwNewValue = value - ImageBase + (ULONG) pModule;
//							*ptr = dwNewValue;
//							break;
//						default:
//							break;
//					}
//				}
//				else
//				{	// applying different patch!
//					if (type == IMAGE_REL_BASED_HIGHLOW) 
//					{
//							value = value - ImageBase - 0x1000;
//							value = value + (DWORD) lpTextAddr;
//							*ptr = value;
//					}
//				}
//				
//				entries++;
//
//				BlockSize -= 2;
//			}
//
//			relocation_page = CALC_OFFSET(base_relocation_block_t *, relocation_page, relocation_page->BlockSize);
//		}
//	}
//
//}
//
//#pragma code_seg(".hermit")
//void Reloc_Process(LPVOID pModule, PIMAGE_NT_HEADERS32 pImageNtHeader, PIMAGE_SECTION_HEADER pSectionPointer, LPVOID lpRelocAddress, DWORD dwRelocSize, PIMAGE_SECTION_HEADER pTextPointer, LPVOID lpTextAddr)
//{
//	DWORD ImageBase = (DWORD) _baseAddress;
//
//	if (dwRelocSize == 0 || lpRelocAddress == NULL)
//		return;	// no reloc table here!
//
//	base_relocation_block_t *relocation_page = (base_relocation_block_t *) lpRelocAddress;
//
//	if (relocation_page == NULL)
//		return;	// no relocation page available!
//
//	// for each page!
//	while(relocation_page->BlockSize > 0)
//	{
//		if (relocation_page->PageRVA < pSectionPointer->VirtualAddress || relocation_page->PageRVA > (pSectionPointer->VirtualAddress + pSectionPointer->Misc.VirtualSize))
//		{	// skip current page!
//			relocation_page = CALC_OFFSET(base_relocation_block_t *, relocation_page, relocation_page->BlockSize);
//		}
//		else
//		{	// ok.. we can process this page!
//			typedef short relocation_entry;
//
//			int BlockSize = relocation_page->BlockSize - 8;
//			relocation_entry *entries = CALC_OFFSET(relocation_entry *, relocation_page, 8);
//
//			while(BlockSize > 0)
//			{
//				short type = ((*entries & 0xf000) >> 12);
//				long offset = (*entries & 0x0fff);
//
//				ULONG *ptr = CALC_OFFSET(PULONG, pModule, offset + relocation_page->PageRVA);
//				ULONG value = *ptr;
//				ULONG dwNewValue = 0;
//
//				if (reloc_is_text(pImageNtHeader, pTextPointer, (DWORD) value) == FALSE)
//				{
//					switch(type)
//					{
//						case IMAGE_REL_BASED_HIGHLOW:
//							value = value - ImageBase;
//							value = value + (DWORD) pModule;
//							*ptr = value;
//							break;
//						case IMAGE_REL_BASED_DIR64:
//							dwNewValue = value - ImageBase + (ULONG) pModule;
//							*ptr = dwNewValue;
//							break;
//						default:
//							break;
//					}
//				}
//				else
//				{	// applying different patch!
//					if (type == IMAGE_REL_BASED_HIGHLOW) 
//					{
//							value = value - ImageBase - 0x1000;
//							value = value + (DWORD) lpTextAddr;
//							*ptr = value;
//					}
//				}
//
//
//				/*switch(type)
//				{
//					case IMAGE_REL_BASED_HIGHLOW:
//						value = value - pImageNtHeader->OptionalHeader.ImageBase;
//						value = value + (DWORD) pModule;
//						*ptr = value;
//						break;
//					case IMAGE_REL_BASED_DIR64:
//						dwNewValue = value - pImageNtHeader->OptionalHeader.ImageBase + (ULONG) pModule;
//						*ptr = dwNewValue;
//						break;
//				}*/
//				entries++;
//				BlockSize -= 2;
//			}
//
//			relocation_page = CALC_OFFSET(base_relocation_block_t *, relocation_page, relocation_page->BlockSize);
//		}
//	}
//
//}
//
//#endif

BOOL page_in_range(DWORD PageRVA, DWORD va, DWORD size)
{
	if (PageRVA >= va && PageRVA < (va + size))
		return TRUE;

	return FALSE;
}

DWORD Transfer_Reloc_Table(LPVOID hProcessModule, PIMAGE_NT_HEADERS32 pSelf, PIMAGE_SECTION_HEADER pSection, LPVOID lpOutput, DWORD dwNewVirtualAddress, CPeAssembly *destination, PIMAGE_NT_HEADERS32 pNewFile)
{
	DWORD dwSize = 0;

	relocation_block_t *reloc = CALC_OFFSET(relocation_block_t *, hProcessModule, pSelf->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	DWORD dwImageBase = pSelf->OptionalHeader.ImageBase;

	if (dwImageBase != (DWORD) hProcessModule)
		dwImageBase = (DWORD) hProcessModule;

	DWORD dwNewVABASE = 0;

	while(reloc != NULL)
	{
		if (page_in_range(reloc->PageRVA, pSection->VirtualAddress, pSection->Misc.VirtualSize))
		{	// good! add this page!
			memcpy(lpOutput, reloc, reloc->BlockSize);
			
			relocation_block_t *newReloc= CALC_OFFSET(relocation_block_t *, lpOutput, 0);

			newReloc->PageRVA = (reloc->PageRVA - pSection->VirtualAddress + dwNewVirtualAddress) & 0xfffff000;
			
			if (dwNewVABASE == 0) // 
				dwNewVABASE = dwNewVirtualAddress;
			else	//
				dwNewVABASE += 0x1000;

			DWORD blocksize = newReloc->BlockSize - 8;
			relocation_entry *entry = CALC_OFFSET(relocation_entry *, newReloc, 8);
			
			while(blocksize > 0)	// latest two bytes are "reloc terminator"
			{	// fetch instruction and patch!
				short type = ((*entry & 0xf000) >> 12);
				long offset = (*entry & 0x0fff);
				
				if (blocksize == 2 && type == 0) // ABSOLUTE RELOC? PAGE ALIGNMENT!
				{
					blocksize -= 2;
					entry++;
					continue;
				}

				offset = (dwNewVirtualAddress & 0x0fff) + offset;

				*entry = (type << 12) | offset;

				ULONG *ptr = (PULONG) destination->RawPointer(offset + newReloc->PageRVA);
				
				ULONG value = *ptr;
				ULONG dwNewValue = 0;
				DWORD dwRVA = (value - dwImageBase) & 0xfffff000;

				switch(type)
				{
					case 0x03:
						if (page_in_range(dwRVA, pSection->VirtualAddress, pSection->Misc.VirtualSize) == FALSE)
						{
							value = value - dwImageBase;
							value = value + pNewFile->OptionalHeader.ImageBase;
						}
						else
						{
							value = value - dwImageBase - reloc->PageRVA;
							value = value + pNewFile->OptionalHeader.ImageBase + newReloc->PageRVA;
						}
						*ptr = value;
						break;
					case 0x0a:
						//dwNewValue = value - pImageNtHeader->OptionalHeader.ImageBase + (ULONG64) pModule;
						//*ptr = dwNewValue;
						break;
					case 0x00:
						
						break;
				}
				entry++;
				blocksize -= 2;
			}

			lpOutput = CALC_OFFSET(LPVOID, lpOutput, reloc->BlockSize);

			dwSize += reloc->BlockSize;
			//dwNewVirtualAddress += 0x1000;
		}

		reloc = CALC_OFFSET(relocation_block_t *, reloc, reloc->BlockSize);
		if (reloc->BlockSize == 0) reloc = NULL;
	}
	return dwSize;
}


DWORD Patch_Reloc(LPVOID hProcessModule, PIMAGE_NT_HEADERS32 pSelf, PIMAGE_SECTION_HEADER pSection, LPVOID lpOutput, DWORD dwNewVirtualAddress, CPeAssembly *destination, PIMAGE_NT_HEADERS32 pNewFile)
{
	//DWORD dwSize = 0;

	//relocation_block_t *reloc = CALC_OFFSET(relocation_block_t *, hProcessModule, pSelf->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	//DWORD dwImageBase = pSelf->OptionalHeader.ImageBase;

	//if (dwImageBase != (DWORD) hProcessModule)
	//	dwImageBase = (DWORD) hProcessModule;

	//while(reloc != NULL)
	//{
	//	if (reloc->PageRVA >= pSection->VirtualAddress && reloc->PageRVA < (pSection->VirtualAddress + pSection->Misc.VirtualSize))
	//	{	// good! add this page!
	//		//memcpy(lpOutput, reloc, reloc->BlockSize);
	//		
	//		relocation_block_t *newReloc= CALC_OFFSET(relocation_block_t *, reloc, 0);

	//		//newReloc->PageRVA = reloc->PageRVA - pSection->VirtualAddress + dwNewVirtualAddress;
	//		
	//		DWORD blocksize = newReloc->BlockSize - 8;
	//		relocation_entry *entry = CALC_OFFSET(relocation_entry *, newReloc, 8);
	//		
	//		while(blocksize > 0)
	//		{	// fetch instruction and patch!
	//			short type = ((*entry & 0xf000) >> 12);
	//			long offset = (*entry & 0x0fff);

	//			ULONG *ptr = (PULONG) destination->RawPointer(offset + newReloc->PageRVA);
	//			ULONG value = *ptr;
	//			ULONG dwNewValue = 0;

	//			switch(type)
	//			{
	//				case 0x03:
	//					value = value - dwImageBase - reloc->PageRVA;
	//					//value = value + pNewFile->OptionalHeader.ImageBase + pSection->VirtualAddress;
	//					*ptr = value;
	//					break;
	//				case 0x0a:
	//					//dwNewValue = value - pImageNtHeader->OptionalHeader.ImageBase + (ULONG64) pModule;
	//					//*ptr = dwNewValue;
	//					break;
	//			}
	//			entry++;
	//			blocksize -= 2;
	//		}

	//		//lpOutput = CALC_OFFSET(LPVOID, lpOutput, reloc->BlockSize);

	//		dwSize += reloc->BlockSize;
	//	}

	//	reloc = CALC_OFFSET(relocation_block_t *, reloc, reloc->BlockSize);
	//	if (reloc->BlockSize == 0) reloc = NULL;
	//}
	//return dwSize;

	return 0;
}


/**
 *	Return size required for relocation
 **/
size_t SizeOfRelocSection(LPVOID hProcessModule, PIMAGE_NT_HEADERS32 pSelf, PIMAGE_SECTION_HEADER pSection)
{
	size_t size = 0;

	relocation_block_t *reloc = CALC_OFFSET(relocation_block_t *, hProcessModule, pSelf->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	DWORD dwImageBase = pSelf->OptionalHeader.ImageBase;

	if (dwImageBase != (DWORD) hProcessModule)
		dwImageBase = (DWORD) hProcessModule;
	
	while(reloc != NULL)
	{
		if (page_in_range(reloc->PageRVA, pSection->VirtualAddress, pSection->Misc.VirtualSize))
		{	// good! add this page!
			size+= reloc->BlockSize;
		}

		reloc = CALC_OFFSET(relocation_block_t *, reloc, reloc->BlockSize);
		if (reloc->BlockSize == 0) reloc = NULL;
	}
	return size;
}

/**
 *	Return size required for relocation
 **/
size_t SizeOfRelocSection(LPVOID hProcessModule, PIMAGE_NT_HEADERS64 pSelf, PIMAGE_SECTION_HEADER pSection)
{
	size_t size = 0;

	relocation_block_t *reloc = CALC_OFFSET(relocation_block_t *, hProcessModule, pSelf->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	ULONGLONG dwImageBase = pSelf->OptionalHeader.ImageBase;

	if (dwImageBase != (ULONGLONG) hProcessModule)
		dwImageBase = (ULONGLONG) hProcessModule;


	while(reloc != NULL)
	{
		if (page_in_range(reloc->PageRVA, pSection->VirtualAddress, pSection->Misc.VirtualSize))
		{	// good! add this page!
			size+= reloc->BlockSize;
		}

		reloc = CALC_OFFSET(relocation_block_t *, reloc, reloc->BlockSize);
		if (reloc->BlockSize == 0) reloc = NULL;
	}
	return size;
}