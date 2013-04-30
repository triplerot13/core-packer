/**
 *	PACKER32/64	- get .text section from random files
 *	(c) ]HackingTeam[ 2013
 *	http://www.hackingteam.com
 *
 *	cod
 **/
#include <Windows.h>
#include <iostream>

#include "peasm/peasm.h"
#include "peasm/pesection.h"

static BOOL check_blacklist(PWIN32_FIND_DATA lpFindData)
{
	if (_strcmpi(lpFindData->cFileName, "compobj.dll") == 0)
		return TRUE;
	return FALSE;
}

static int count_rand_file()
{
	char szWindirPath[MAX_PATH];

	DWORD dwIgnore = GetEnvironmentVariableA("windir", szWindirPath, MAX_PATH);

	if (dwIgnore == 0)
	{	// try default c:\windows
		strcpy_s(szWindirPath, "C:\\windows\\");
	}
	else
	{
		int i = strlen(szWindirPath);

		if (szWindirPath[i-1] != '\\')
			strcat_s(szWindirPath, "\\");
	}

	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;

	fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(GetModuleHandle("kernel32"),"IsWow64Process");

	if(NULL != fnIsWow64Process)
    {
		BOOL bIsWow64 = FALSE;

		fnIsWow64Process(GetCurrentProcess(),&bIsWow64);

		if (bIsWow64)
			strcat_s(szWindirPath, "syswow64\\");
		else
			strcat_s(szWindirPath, "system32\\");
    }
	else
	{
		strcat_s(szWindirPath, "system32\\");
	}

	char szFindPath[MAX_PATH];
	sprintf_s(szFindPath, "%s*.dll", szWindirPath);

	WIN32_FIND_DATA findfiledata;
	HANDLE hLook = FindFirstFileA(szFindPath, &findfiledata);

	if (hLook == INVALID_HANDLE_VALUE)
		return 0;

	int count=0;

	do
	{	// perform a backup!
		count++;
	} while(FindNextFileA(hLook, &findfiledata));

	FindClose(hLook);

	return count;
}

static BOOL lookup_rand_file(char *szOutFile, int maxsize)
{
	memset(szOutFile, 0, maxsize);
	
	char szWindirPath[MAX_PATH];

	DWORD dwIgnore = GetEnvironmentVariableA("windir", szWindirPath, MAX_PATH);

	if (dwIgnore == 0)
	{	// try default c:\windows
		strcpy_s(szWindirPath, "C:\\windows\\");
	}
	else
	{
		int i = strlen(szWindirPath);

		if (szWindirPath[i-1] != '\\')
			strcat_s(szWindirPath, "\\");
	}

	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;

	fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(GetModuleHandle("kernel32"),"IsWow64Process");

	if(NULL != fnIsWow64Process)
    {
		BOOL bIsWow64 = FALSE;

		fnIsWow64Process(GetCurrentProcess(),&bIsWow64);

		if (bIsWow64)
			strcat_s(szWindirPath, "syswow64\\");
		else
			strcat_s(szWindirPath, "system32\\");
    }
	else
	{
		strcat_s(szWindirPath, "system32\\");
	}

	char szFindPath[MAX_PATH];
	sprintf_s(szFindPath, "%s*.dll", szWindirPath);

	WIN32_FIND_DATA findfiledata;
	WIN32_FIND_DATA _previous_findfiledata;
	HANDLE hLook = FindFirstFileA(szFindPath, &findfiledata);

	int l = rand() % 256;

	if (hLook == INVALID_HANDLE_VALUE)
		return FALSE;

	do
	{	// perform a backup!
		if (check_blacklist(&findfiledata) == TRUE)	// file in blacklist
			continue;

		memcpy(&_previous_findfiledata, &findfiledata, sizeof(WIN32_FIND_DATA));
		if (l  == 0)
			break;

		l--;
	} while(FindNextFileA(hLook, &findfiledata));

	FindClose(hLook);

	strcat_s(szWindirPath, _previous_findfiledata.cFileName);

	strcpy_s(szOutFile, MAX_PATH, szWindirPath);

	return TRUE;
}

CPeAssembly *load_random(char *param)
{
	if (param != NULL)
	{
		CPeAssembly *obj = new CPeAssembly();
		obj->Load(param);
		return obj;
	}
	else
	{
		char randfile[MAX_PATH];

		CPeAssembly *obj = NULL;

		while(obj == NULL)
		{
			lookup_rand_file(randfile, MAX_PATH);

			obj = new CPeAssembly();

			if (obj->Load(randfile) == false)
			{	// failed!
				std::cout << "Error loading " << randfile << std::endl;
				delete obj;
				obj = NULL;
			}

			if (obj->NumberOfSections() == 0)
			{	// failed!
				std::cout << "Error loading " << randfile << std::endl;
				delete obj;
				obj = NULL;
			}
		}

		std::cout << "[CONFIG] random file section: " << randfile << std::endl;
		return obj;
	}

	return NULL;
}


#define SECTION_RANDOM_NAME	15

static char *szSectionNames[SECTION_RANDOM_NAME] = 
{
	".textbss",
	".pages",
	".visical",
	".inferno",
	".calc",
	".notepad",
	".word",
	".viper0",
	".venom",
	".text0",
	".uspack0",
	".hermit",
	".locals",
	".stack1",
	".GLOBAL"
};

/**
 *	\!random_section_name
 *
 **/
const char	*random_section_name()
{
	return	szSectionNames[rand() % 15];
}
