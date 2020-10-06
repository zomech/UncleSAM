#pragma once

typedef struct FILE_CLUSTER_LAYOUT {

	unsigned long long vcn_count;
	DWORD64 lcn_list[1];

}FILE_CLUSTER_LAYOUT, * PFILE_CLUSTER_LAYOUT;

BYTE* DumpFileFromDisk(FILE_CLUSTER_LAYOUT* fcl);
FILE_CLUSTER_LAYOUT* GetFileClusters(const wchar_t* filename);