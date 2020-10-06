#pragma once

#include <Windows.h>


// All offsets are relative to the start of the hbin

typedef struct REG_HIVE_HEADER {

	char signature[4];
	DWORD primary_seq_num;
	DWORD secondary_seq_num;
	FILETIME last_write_timestamp;
	DWORD major_version;
	DWORD minor_version;
	DWORD file_type;
	DWORD file_format;
	DWORD relative_root_cell_offset;
	DWORD hbins_size;
	DWORD clustering_factor;
	wchar_t filename[32];
	BYTE reserved[396];
	DWORD checksum;
	BYTE reserved2[3576];
	DWORD boot_type;
	DWORD boot_recover;

}REG_HIVE_HEADER, *PREG_HIVE_HEADER;

typedef struct REG_HBIN_HEADER {

	char signature[4];
	DWORD relative_offset;
	DWORD size;
	BYTE reserved[8];
	FILETIME timestamp;
	DWORD spare;

}REG_HBIN_HEADER;

typedef struct REG_CELL_HEADER {

	DWORD size;
	union
	{
		char signature[2];
		BYTE data[1];
	};


}REG_CELL_HEADER, *PREG_CELL_HEADER;

typedef struct REG_CELL_NK {

	char signature[2];
	WORD flags;
	FILETIME last_write_timestamp;
	DWORD access_bits;
	DWORD parent_cell_offset;
	DWORD subkey_count;
	DWORD volatile_subkey_count;
	DWORD subkey_list_offset;
	DWORD volatile_subkey_list_offset;
	DWORD key_value_count;
	DWORD key_value_list_offset;
	DWORD key_security_list_offset;
	DWORD class_name_offset;
	DWORD largest_subkey_name_size;
	DWORD largest_subkey_class_name_size;
	DWORD largest_value_name_size;
	DWORD largest_value_data_size;
	DWORD workvar;
	WORD name_len;
	WORD class_name_len;
	char name[1];

}REG_CELL_NK, *PREG_CELL_NK;

typedef enum _NK_RECORDS
{

	NK_Signature,
	NK_Flags,
	NK_LastWriteTimestamp,
	NK_AccessBits,
	NK_ParentCellOffset,
	NK_SubkeyCount,
	NK_VolatileSubkeyCount,
	NK_SubkeyListOffset,
	NK_VolatileSubkeyListOffset,
	NK_KeyValueCount,
	NK_KeyValueListOffset,
	NK_KeySecurityListOffset,
	NK_ClassNameOffset,
	NK_LargestSubkeyNameSize,
	NK_LargestSubkeyClassNameSize,
	NK_LargestValueNameSize,
	NK_LargestValueDataSize,
	NK_WorkVar,
	NK_NameLength,
	NK_ClassNameLength,
	NK_Name,
	NK_CellStruct

}NK_RECORDS;

typedef enum _VK_RECORD
{

	VK_Signature,
	VK_NameLength,
	VK_DataSize,
	VK_DataOffset,
	VK_DataType,
	VK_Flags,
	VK_Spare,
	VK_Name,
	VK_CellStruct

}VK_RECORD;

typedef struct REG_KEYLIST_LI
{

	DWORD key_offset;

}REG_KEYLIST_LI, *PREG_KEYLIST_LI;

typedef struct REG_KEYLIST_LF
{

	DWORD key_offset;
	DWORD name_hint;

}REG_KEYLIST_LF, *PREG_KEYLIST_LF;

typedef struct REG_KEYLIST_LH
{

	DWORD key_offset;
	DWORD name_hash;

}REG_KEYLIST_LH, *PREG_KEYLIST_LH;

typedef struct REG_KEYLIST_RI
{

	DWORD key_offset;
	DWORD name_hint;

}REG_KEYLIST_RI, *PREG_KEYLIST_RI;

typedef union
{
	REG_KEYLIST_LI li;
	REG_KEYLIST_LF lf;
	REG_KEYLIST_LH lh;
	REG_KEYLIST_RI ri;
}key_lists;

typedef struct REG_KEYLIST_HEADER
{
	DWORD size;
	char signature[2];
	WORD number_of_elements;
	key_lists list[1];

}REG_KEYLIST_HEADER, *PREG_KEYLIST_HEADER;

typedef struct REG_VALUE_LIST
{
	DWORD size;
	DWORD value_offset[1];

}REG_VALUE_LIST, *PREG_VALUE_LIST;

typedef struct REG_CELL_VK
{

	char signature[2];
	WORD name_len;
	DWORD data_size;
	DWORD data_offset;
	DWORD data_type;
	WORD flags;
	WORD spare;
	char name[1];

}REG_CELL_VK, *PREG_CELL_VK;

typedef struct REG_CELL_VK_DATA
{

	DWORD cell_size;
	BYTE data[1];

}REG_CELL_VK_DATA, REG_CELL_CLASS_NAME, *PREG_CELL_VK_DATA, *PREG_CELL_CLASS_NAME;


void* GetNKRecord(
	BYTE* hive,
	char* reg_path,
	NK_RECORDS record);

unsigned int split(
	char* str,
	char delim,
	char*** arr_ptr);

REG_CELL_NK* GetSubkeyNK(
	REG_HBIN_HEADER* hbin_header,
	REG_CELL_NK* parent_cell,
	char* subkey_name);

BOOL GetVKValue(
	BYTE* hive,
	char* reg_path,
	char* value_name,
	BYTE* buf,
	DWORD buf_size,
	DWORD* data_size);

DWORD GetSubkeyNamesList(
	BYTE* hive,
	char* reg_path,
	char*** keys);

void* GetVKRecord(
	BYTE* hive,
	char* reg_path,
	char* value_name,
	VK_RECORD record);

BOOL GetNKClassName(BYTE* hive,
	char* reg_path,
	BYTE* buf,
	DWORD buf_size,
	DWORD* data_size);