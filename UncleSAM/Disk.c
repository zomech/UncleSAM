

#include "Includes.h"

FILE_CLUSTER_LAYOUT* GetFileClusters(const wchar_t* filename)
{

	BOOL success = FALSE;
	STARTING_VCN_INPUT_BUFFER inputVcn = { 0 };
	RETRIEVAL_POINTERS_BUFFER rpBuf = { 0 };
	DWORD bytes_out = 0;
	FILE_CLUSTER_LAYOUT* fcl = (FILE_CLUSTER_LAYOUT*)malloc(sizeof(FILE_CLUSTER_LAYOUT));

	fcl->vcn_count = 0;
	fcl->lcn_list[0] = 0;

	/*
	void* old;
	Wow64DisableWow64FsRedirection(&old);
	*/

	HANDLE hFile = CreateFileW(filename, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		DeviceIoControl(hFile, FSCTL_GET_RETRIEVAL_POINTERS, &inputVcn, sizeof(STARTING_VCN_INPUT_BUFFER), &rpBuf, sizeof(RETRIEVAL_POINTERS_BUFFER), &bytes_out, NULL);
	}


	while (/*INPUTVCN.STARTINGVCN.QUADPART != RPBUF.EXTENTS[0].NEXTVCN.QUADPART*/ GetLastError() != 0x26 && bytes_out != 0)
	{

		/*wprintf(L"\nVcn %d - Vcn %d --> Lcn %d - Lcn %d", inputVcn.StartingVcn.LowPart, rpBuf.Extents[0].NextVcn.LowPart - 1,
			rpBuf.Extents[0].Lcn.LowPart, rpBuf.Extents[0].Lcn.LowPart + (rpBuf.Extents[0].NextVcn.LowPart - inputVcn.StartingVcn.LowPart) - 1);*/

		fcl = (FILE_CLUSTER_LAYOUT*)realloc(fcl, sizeof(FILE_CLUSTER_LAYOUT) + rpBuf.Extents[0].NextVcn.LowPart * sizeof(DWORD64)); //needs ifdef win32
		for (unsigned int i = fcl->vcn_count; i < rpBuf.Extents[0].NextVcn.LowPart; i++)
		{
			fcl->lcn_list[i] = rpBuf.Extents[0].Lcn.QuadPart + (i - inputVcn.StartingVcn.QuadPart);
		}

		fcl->vcn_count = rpBuf.Extents[0].NextVcn.QuadPart; //ifdef win32

		inputVcn.StartingVcn = rpBuf.Extents[0].NextVcn; //ifdef win32

		DeviceIoControl(hFile, FSCTL_GET_RETRIEVAL_POINTERS, &inputVcn, sizeof(STARTING_VCN_INPUT_BUFFER), &rpBuf, sizeof(RETRIEVAL_POINTERS_BUFFER), &bytes_out, NULL);
	}

	//fcl->vcn_count = inputVcn.StartingVcn.QuadPart; //ifdef win32

	CloseHandle(hFile);
	return fcl;
}

BYTE* DumpFileFromDisk(FILE_CLUSTER_LAYOUT* fcl)
{
	
	BOOL success = TRUE;
	BYTE buf[4096];
	DWORD out = 0;
	LARGE_INTEGER li = { 0 };
	HANDLE hDisk = -1;
	BYTE* data = 0;


	if (fcl->vcn_count == 0)
	{
		success = FALSE;
	}

	if (success)
	{
		hDisk = CreateFileW(L"\\\\.\\C:", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
		data = (BYTE*)malloc(fcl->vcn_count * 4096);
	}

	if (hDisk == INVALID_HANDLE_VALUE)
	{
		success = FALSE;
	}

	for (DWORD i = 0; i < fcl->vcn_count && success; i++)
	{
		li.QuadPart = fcl->lcn_list[i] * 4096;
		out = SetFilePointerEx(hDisk, li, NULL, FILE_BEGIN);
		success = ReadFile(hDisk, buf, 4096, &out, NULL);
		//WriteFile(hFileOut, buf, 4096, &out, NULL);

		memcpy(data + i * 4096, buf, 4096);
	}

	if (success == FALSE)
	{
		free(data);
		data = 0;
	}

	return data;
}