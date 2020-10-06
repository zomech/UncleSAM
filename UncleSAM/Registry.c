
#include "Registry.h"

// Copies the value of a registry path through hive to buffer, or query the size of the value
BOOL GetVKValue(BYTE* hive, char* reg_path, char* value_name, BYTE* buf, DWORD buf_size, DWORD* data_size)
{
	BOOL success = FALSE;
	BOOL is_name_equal = FALSE;
	REG_CELL_VK* vk = 0;
	REG_CELL_VK_DATA* vk_data = 0;

	// Parameters will be checkes in the function
	vk = (REG_CELL_VK*)GetVKRecord(hive, reg_path, value_name, VK_CellStruct);

	REG_HBIN_HEADER* hbin_header = (REG_HBIN_HEADER*)((BYTE*)hive + 0x1000);

	// If We Found a VK Cell for the value name given
	if (vk && _strnicmp(vk->signature, "vk", 2) == 0)
	{

		// Checks if the data stored in the VK structure 
		if (vk->data_size & 0x80000000)
		{
			*data_size = vk->data_size - 0x80000000;

			// If the buffer is large enough we copy the data
			if (buf_size >= vk->data_size - 0x80000000 && buf != 0)
			{
				memcpy(buf, &(vk->data_offset), vk->data_size - 0x80000000);
			}
		}

		// Data Stored in Another Cell
		else
		{
			*data_size = vk->data_size;
			vk_data = (REG_CELL_VK_DATA*)((BYTE*)hbin_header + vk->data_offset);

			// If the buffer is large enough we copy the data
			if (buf_size >= vk->data_size && buf != 0)
			{
				memcpy(buf, vk_data->data, vk->data_size);
			}
		}
		success = TRUE;
	}


	return success;
}

// Returns a record from the VK Cell Structure
void* GetVKRecord(BYTE* hive, char* reg_path, char* value_name, VK_RECORD record)
{
	void* ret = 0;
	BOOL is_name_equal = FALSE;

	REG_CELL_VK* vk = 0;
	REG_CELL_VK_DATA* vk_data = 0;
	REG_CELL_HEADER* cell = 0;
	DWORD value_count = 0;
	DWORD vk_list_offset = 0;
	REG_VALUE_LIST* vk_list = 0;

	if (hive == 0 || reg_path == NULL || value_name == NULL)
	{
		return FALSE;
	}

	REG_HBIN_HEADER* hbin_header = (REG_HBIN_HEADER*)((BYTE*)hive + 0x1000);

	// Get the NK Cell Structure from the Registry Path
	REG_CELL_NK* nk = (REG_CELL_NK*)GetNKRecord(hive, reg_path, NK_CellStruct);

	if (nk != 0 && _strnicmp(nk->signature, "nk", 2) == 0)
	{
		value_count = nk->key_value_count;
		vk_list_offset = nk->key_value_list_offset;

		vk_list = (REG_VALUE_LIST*)((BYTE*)hbin_header + vk_list_offset);
	}


	// Get all VK Cells
	for (unsigned int i = 0; i < value_count && is_name_equal == FALSE; i++)
	{

		cell = (REG_CELL_HEADER*)((BYTE*)hbin_header + vk_list->value_offset[i]);
		if (strncmp(cell->signature, "vk", 2) == 0)
		{
			vk = (REG_CELL_VK*)cell->data;

			// If the Default value than name length will be zero
			if (vk->name_len == 0 && (_strnicmp(value_name, "Default", 7) == 0))
			{
				is_name_equal = TRUE;
			}

			// Compares name in VK cell to the value name given
			else if (vk->name_len != 0 && _strnicmp(value_name, vk->name, vk->name_len) == 0)
			{
				is_name_equal = TRUE;
			}
		}

	}

	// If We Found a VK Cell for the value name given
	if (is_name_equal)
	{

		// Return The specified VK Record from the Cell Structure
		switch (record)
		{
		case VK_Signature:
			ret = &(vk->signature);
			break;
		case VK_NameLength:
			ret = &(vk->name_len);
			break;
		case VK_DataSize:
			ret = &(vk->data_size);
			break;
		case VK_DataOffset:
			ret = &(vk->data_offset);
			break;
		case VK_DataType:
			ret = &(vk->data_type);
			break;
		case VK_Flags:
			ret = &(vk->flags);
			break;
		case VK_Spare:
			ret = &(vk->spare);
			break;
		case VK_Name:
			ret = &(vk->name);
			break;
		case VK_CellStruct:
			ret = vk;
			break;
		default:
			break;
		}
	}

	return ret;
}


// Returns the Class Name record from the NK Cell Structure
BOOL GetNKClassName(BYTE* hive, char* reg_path, BYTE* buf, DWORD buf_size, DWORD* data_size)
{

	BOOL success = FALSE;
	REG_CELL_NK* nk = 0;
	REG_CELL_CLASS_NAME* class_name_cell = 0;

	REG_HBIN_HEADER* hbin_header = (REG_HBIN_HEADER*)((BYTE*)hive + 0x1000);

	nk = (REG_CELL_NK*)GetNKRecord(hive, reg_path, NK_CellStruct);

	if (nk && _strnicmp(nk->signature, "nk", 2) == 0)
	{
		*data_size = nk->class_name_len;

		if (buf_size >= nk->class_name_len && buf != 0)
		{
			class_name_cell = (REG_CELL_CLASS_NAME*)((BYTE*)hbin_header + nk->class_name_offset);
			memcpy(buf, class_name_cell->data, nk->class_name_len);
		}

		success = TRUE;
	}

	return success;
}



// Returns a record from the NK Cell Structure
void* GetNKRecord(BYTE* hive, char* reg_path, NK_RECORDS record)
{
	BOOL success = FALSE;
	void* ret = 0;

	if (hive == 0 || reg_path == NULL)
	{
		return ret;
	}

	REG_CELL_NK* root_nk = 0;
	REG_CELL_NK* cell_nk = 0;

	// Gets the Root Cell of the Registry Hive
	REG_HBIN_HEADER* hbin_header = (REG_HBIN_HEADER*)((BYTE*)hive + 0x1000);
	REG_CELL_HEADER* root_cell = (REG_CELL_HEADER*)(((REG_HIVE_HEADER*)hive)->relative_root_cell_offset + (BYTE*)hbin_header);


	if (strncmp(root_cell->signature, "nk", 2) == 0)
	{
		root_nk = (REG_CELL_NK*)root_cell->data;
		success = TRUE;
	}

	cell_nk = root_nk;

	char** keys = 0;
	DWORD hops = split(reg_path, '\\', &keys);
	for (unsigned int i = 0; i < hops && success; i++)
	{
		// Get the subkey by name from the parent subkey
		cell_nk = GetSubkeyNK(hbin_header, cell_nk, keys[i]);
	}

	if (success && cell_nk)
	{
		// Return The specified NK Record from the Cell Structure
		switch (record)
		{

		case NK_Signature:
			ret = &(cell_nk->signature);
			break;
		case NK_Flags:
			ret = &(cell_nk->flags);
			break;
		case NK_LastWriteTimestamp:
			ret = &(cell_nk->last_write_timestamp);
			break;
		case NK_AccessBits:
			ret = &(cell_nk->access_bits);
			break;
		case NK_ParentCellOffset:
			ret = &(cell_nk->parent_cell_offset);
			break;
		case NK_SubkeyCount:
			ret = &(cell_nk->subkey_count);
			break;
		case NK_VolatileSubkeyCount:
			ret = &(cell_nk->volatile_subkey_count);
			break;
		case NK_SubkeyListOffset:
			ret = &(cell_nk->subkey_list_offset);
			break;
		case NK_VolatileSubkeyListOffset:
			ret = &(cell_nk->volatile_subkey_list_offset);
			break;
		case NK_KeyValueCount:
			ret = &(cell_nk->key_value_count);
			break;
		case NK_KeyValueListOffset:
			ret = &(cell_nk->key_value_list_offset);
			break;
		case NK_KeySecurityListOffset:
			ret = &(cell_nk->key_security_list_offset);
			break;
		case NK_ClassNameOffset:
			ret = &(cell_nk->class_name_offset);
			break;
		case NK_LargestSubkeyNameSize:
			ret = &(cell_nk->largest_subkey_name_size);
			break;
		case NK_LargestSubkeyClassNameSize:
			ret = &(cell_nk->largest_subkey_class_name_size);
			break;
		case NK_LargestValueNameSize:
			ret = &(cell_nk->largest_value_name_size);
			break;
		case NK_LargestValueDataSize:
			ret = &(cell_nk->largest_value_data_size);
			break;
		case NK_WorkVar:
			ret = &(cell_nk->workvar);
			break;
		case NK_NameLength:
			ret = &(cell_nk->name_len);
			break;
		case NK_ClassNameLength:
			ret = &(cell_nk->class_name_len);
			break;
		case NK_Name:
			ret = &(cell_nk->name);
			break;
		case NK_CellStruct:
			ret = cell_nk;
			break;
		default:
			success = FALSE;
			break;
		}
	}

	// frees the registry key list
	for (unsigned int i = 0; i < hops; i++)
	{
		free(keys[i]);
	}
	free(keys);

	return ret;
}

// Return the subkey from his parent cell, by name
REG_CELL_NK* GetSubkeyNK(REG_HBIN_HEADER* hbin_header, REG_CELL_NK* parent_cell, char* subkey_name)
{

	REG_CELL_NK* cell = 0;
	REG_CELL_NK* subkey_cell = 0;
	REG_KEYLIST_HEADER* subkey_list = 0;

	unsigned int subkey_count = -1;
	DWORD subkey_list_offset = 0;
	DWORD nk_offset = 0;

	if (hbin_header == 0 || parent_cell == 0 || subkey_name == NULL)
	{
		return 0;
	}

	subkey_count = parent_cell->subkey_count;
	subkey_list_offset = parent_cell->subkey_list_offset;

	subkey_list = (REG_KEYLIST_HEADER*)((BYTE*)hbin_header + subkey_list_offset);

	// Runs over all the subkeys from the subkeys list (li, lh, ri, lf) and compares the subkey name to the subkey name given
	for (unsigned int i = 0; i < subkey_count && cell == 0; i++)
	{

		if (strncmp(subkey_list->signature, "li", 2) == 0)
		{
			nk_offset = subkey_list->list[i].li.key_offset;
		}

		else if (strncmp(subkey_list->signature, "lh", 2) == 0)
		{
			nk_offset = subkey_list->list[i].lh.key_offset;
		}

		else if (strncmp(subkey_list->signature, "lf", 2) == 0)
		{
			nk_offset = subkey_list->list[i].lf.key_offset;
		}

		else if (strncmp(subkey_list->signature, "ri", 2) == 0)
		{
			nk_offset = subkey_list->list[i].ri.key_offset;
		}

		subkey_cell = (REG_CELL_NK*)(((REG_CELL_HEADER*)((BYTE*)hbin_header + nk_offset))->data);

		if (_strnicmp(subkey_cell->name, subkey_name, subkey_cell->name_len) == 0)
		{
			cell = subkey_cell;
		}

	}

	return cell;
}

// Creates an array with the names of all the subkey of specified registry path, and returns the number of entries in the array
DWORD GetSubkeyNamesList(BYTE* hive, char* reg_path, char*** keys)
{

	REG_HBIN_HEADER* hbin_header = (REG_HBIN_HEADER*)((BYTE*)hive + 0x1000);
	DWORD nk_offset = 0;
	REG_CELL_NK* child = 0;

	if (hive == 0 || reg_path == 0 || keys == 0)
	{
		return 0;
	}

	// Gets the NK Cell of the specified registry path
	REG_CELL_NK* nk = (REG_CELL_NK*)GetNKRecord((BYTE*)hive, reg_path, NK_CellStruct);
	/*if (nk == 0)
	{
		return 0;
	}*/
	if (nk == 0 || _strnicmp(nk->signature, "nk", 2) != 0)
	{
		return 0;
	}

	// Getting the subkey list
	REG_KEYLIST_HEADER* keylist = (REG_KEYLIST_HEADER*)((BYTE*)hbin_header + nk->subkey_list_offset);

	char** arr = (char**)malloc(nk->subkey_count * sizeof(char*));

	// Going through the subkeys and appending thier name to the names array
	for (size_t i = 0; i < nk->subkey_count; i++)
	{

		if (strncmp(keylist->signature, "li", 2) == 0)
		{
			nk_offset = keylist->list[i].li.key_offset;
		}

		else if (strncmp(keylist->signature, "lh", 2) == 0)
		{
			nk_offset = keylist->list[i].lh.key_offset;
		}

		else if (strncmp(keylist->signature, "lf", 2) == 0)
		{
			nk_offset = keylist->list[i].lf.key_offset;
		}

		else if (strncmp(keylist->signature, "ri", 2) == 0)
		{
			nk_offset = keylist->list[i].ri.key_offset;
		}

		child = (REG_CELL_NK*)(((REG_CELL_HEADER*)((BYTE*)hbin_header + nk_offset))->data);

		arr[i] = (char*)calloc(child->name_len + 1, sizeof(char));
		memcpy_s(arr[i], child->name_len + 1, child->name, child->name_len);

	}


	*keys = arr;

	return nk->subkey_count;

}

// split a string by delimiter and return a char array of all strings and the array size 
unsigned int split(char* str, char delim, char*** arr_ptr)
{
	unsigned int elements_count = 0;
	unsigned int delim_count = 0;

	unsigned int full_len = strlen(str);

	char* index = 0;
	char* dup = _strdup(str);
	char** arr = 0;

	char* start = dup;
	char* end = dup + full_len;

	for (unsigned int i = 0; dup[i]; i++)
	{
		if (dup[i] == delim)
		{
			delim_count++;
			dup[i] = 0;
		}
	}

	if (delim_count)
	{
		index = start;
		while (index < end)
		{
			if (*index != 0)
			{
				elements_count++;
			}
			index += strlen(index) + 1;
		}
		index = start;
		arr = (char**)malloc(elements_count * sizeof(char*));
	}


	for (unsigned int i = 0; i < elements_count; i++)
	{
		if (*index != 0)
		{
			arr[i] = _strdup(index);
		}
		else
		{
			i--;
		}
		index += strlen(index) + 1;
	}

	*arr_ptr = arr;
	free(dup);
	return elements_count;
}