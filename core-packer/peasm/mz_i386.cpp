/****************************************************************************
 * PE dos routine
 *	i386 routine
 ***************************************************************************/

#include <Windows.h>

#include "peasm.h"
#include "pesection.h"

static BOOL load_image(CPeAssembly *pe, HANDLE hFile, SECTION_ARRAY *sections)
{
	return FALSE;
}

static BOOL write_image(CPeAssembly *pe, HANDLE hFile, SECTION_ARRAY *sections)
{
	return FALSE;
}

struct _file_support mz_i386 = 
{
	IMAGE_FILE_MACHINE_UNKNOWN,
	load_image,
	write_image
};
