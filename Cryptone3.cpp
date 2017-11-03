// 
// https://github.com/oxfemale/Cryptone3/
// twitter: @oxfemale
// email: alice.eas7@gmail.com
// telegram: @BelousovaAlisa
//
#include "stdafx.h"
#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>


// Link with the Advapi32.lib file.
#pragma comment (lib, "advapi32")

#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_RC4 
#define ENCRYPT_BLOCK_SIZE 8 

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}



extern "C" __declspec(dllexport) bool MyEncryptFile(
	LPTSTR pszSourceFile,
	LPTSTR pszDestinationFile,
	LPTSTR pszPassword)
{
	bool fReturn = false;
	HANDLE hSourceFile = INVALID_HANDLE_VALUE;
	HANDLE hDestinationFile = INVALID_HANDLE_VALUE;

	HCRYPTPROV hCryptProv = NULL;
	HCRYPTKEY hKey = NULL;
	HCRYPTKEY hXchgKey = NULL;
	HCRYPTHASH hHash = NULL;

	PBYTE pbKeyBlob = NULL;
	DWORD dwKeyBlobLen;

	PBYTE pbBuffer = NULL;
	DWORD dwBlockLen;
	DWORD dwBufferLen;
	DWORD dwCount;


	#ifdef _DEBUG
	_tprintf(TEXT("MyEncryptFile() loaded:\n"));
	_tprintf(TEXT("SourceFile: %s\nDestinationFile: %s\nPassword: %s\n"), pszSourceFile, pszDestinationFile, pszPassword);
	#endif

	// Open the source file. 
	hSourceFile = CreateFileW(
		pszSourceFile,
		FILE_READ_DATA,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE == hSourceFile)
	{
		#ifdef _DEBUG	
		_tprintf(TEXT("Error(%d):  Open the source file[%s]. CreateFile()\n"), GetLastError(), pszSourceFile);
		#endif
		goto Exit_MyEncryptFile;
	}

	//---------------------------------------------------------------
	// Open the destination file. 
	hDestinationFile = CreateFile(
		pszDestinationFile,
		FILE_WRITE_DATA,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE == hDestinationFile)
	{
#ifdef _DEBUG	
		_tprintf(TEXT("Error(%d): //hDestinationFile = CreateFile\n"), GetLastError());
#endif
		goto Exit_MyEncryptFile;
	}

	//---------------------------------------------------------------
	// Get the handle to the default provider. 
	if (CryptAcquireContext(
		&hCryptProv,
		NULL,
		MS_ENHANCED_PROV,
		PROV_RSA_FULL,
		0))
	{
#ifdef _DEBUG	
		_tprintf(TEXT("OK: Get the handle to the default provider. CryptAcquireContext()\n"));
#endif
	}
	else
	{
#ifdef _DEBUG	
_tprintf(TEXT("Error(%d): Get the handle to the default provider. CryptAcquireContext()\n"), GetLastError());
#endif
		goto Exit_MyEncryptFile;
	}

	//---------------------------------------------------------------
	// Create the session key.
	if (!pszPassword || !pszPassword[0])
	{
		//-----------------------------------------------------------
		// No password was passed.
		// Encrypt the file with a random session key, and write the 
		// key to a file. 

		//-----------------------------------------------------------
		// Create a random session key. 
		if (CryptGenKey(
			hCryptProv,
			ENCRYPT_ALGORITHM,
			KEYLENGTH | CRYPT_EXPORTABLE,
			&hKey))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("OK: Create a random session key. CryptGenKey()\n"));
#endif
		}
		else
		{
#ifdef _DEBUG	
			_tprintf(TEXT("Error(%d): Create a random session key. CryptGenKey()\n"), GetLastError());
#endif
			goto Exit_MyEncryptFile;
		}

		//-----------------------------------------------------------
		// Get the handle to the exchange public key. 
		if (CryptGetUserKey(
			hCryptProv,
			AT_KEYEXCHANGE,
			&hXchgKey))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("OK: Get the handle to the exchange public key. CryptGetUserKey()\n"));
#endif
		}
		else
		{
			if (NTE_NO_KEY == GetLastError())
			{
				// No exchange key exists. Try to create one.
				if (!CryptGenKey(
					hCryptProv,
					AT_KEYEXCHANGE,
					CRYPT_EXPORTABLE,
					&hXchgKey))
				{
#ifdef _DEBUG	
					_tprintf(TEXT("Error(%d): Get the handle to the exchange public key.\n"), GetLastError());
#endif
					goto Exit_MyEncryptFile;
				}
			}
			else
			{
#ifdef _DEBUG	
				_tprintf(TEXT("Error(%d): NTE_NO_KEY != GetLastError(), wtf\n"), GetLastError());
#endif
				goto Exit_MyEncryptFile;
			}
		}

		//-----------------------------------------------------------
		// Determine size of the key BLOB, and allocate memory. 
		if (CryptExportKey(
			hKey,
			hXchgKey,
			SIMPLEBLOB,
			0,
			NULL,
			&dwKeyBlobLen))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("OK: Determine size of the key BLOB, and allocate memory.  CryptExportKey()\n"));
#endif
		}
		else
		{
#ifdef _DEBUG	
			_tprintf(TEXT("Error(%d): Determine size of the key BLOB, and allocate memory. CryptExportKey()\n"), GetLastError());
#endif
			goto Exit_MyEncryptFile;
		}

		if (pbKeyBlob = (BYTE *)malloc(dwKeyBlobLen))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("OK: malloc(dwKeyBlobLen)\n"));
#endif
		}
		else
		{
#ifdef _DEBUG	
			_tprintf(TEXT("Error(%d): malloc(dwKeyBlobLen)\n"), GetLastError());
#endif
			goto Exit_MyEncryptFile;
		}

		//-----------------------------------------------------------
		// Encrypt and export the session key into a simple key 
		// BLOB. 
		if (CryptExportKey(
			hKey,
			hXchgKey,
			SIMPLEBLOB,
			0,
			pbKeyBlob,
			&dwKeyBlobLen))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("OK: Encrypt and export the session key into a simple key CryptExportKey()\n"));
#endif
		}
		else
		{
#ifdef _DEBUG	
			_tprintf(TEXT("Error(%d):  Encrypt and export the session key into a simple key CryptExportKey()\n"), GetLastError());
#endif
			goto Exit_MyEncryptFile;
		}

		//-----------------------------------------------------------
		// Release the key exchange key handle. 
		if (hXchgKey)
		{
			if (!(CryptDestroyKey(hXchgKey)))
			{
#ifdef _DEBUG	
				_tprintf(TEXT("Error(%d): Release the key exchange key handle. CryptDestroyKey()\n"), GetLastError());
#endif
				goto Exit_MyEncryptFile;
			}

			hXchgKey = 0;
		}

		//-----------------------------------------------------------
		// Write the size of the key BLOB to the destination file. 
		if (!WriteFile(
			hDestinationFile,
			&dwKeyBlobLen,
			sizeof(DWORD),
			&dwCount,
			NULL))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("Error(%d): Write the size of the key BLOB to the destination file\n"), GetLastError());
#endif
			goto Exit_MyEncryptFile;
		}

		//-----------------------------------------------------------
		// Write the key BLOB to the destination file. 
		if (!WriteFile(
			hDestinationFile,
			pbKeyBlob,
			dwKeyBlobLen,
			&dwCount,
			NULL))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("Error(%d): Write the key BLOB to the destination file.\n"), GetLastError());
#endif
			goto Exit_MyEncryptFile;
		}

		// Free memory.
		free(pbKeyBlob);
	}
	else
	{

		//-----------------------------------------------------------
		// The file will be encrypted with a session key derived 
		// from a password.
		// The session key will be recreated when the file is 
		// decrypted only if the password used to create the key is 
		// available. 

		//-----------------------------------------------------------
		// Create a hash object. 
		if (CryptCreateHash(
			hCryptProv,
			CALG_MD5,
			0,
			0,
			&hHash))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("OK: Create a hash object. CryptCreateHash()\n"));
#endif
		}
		else
		{
#ifdef _DEBUG	
			_tprintf(TEXT("Error(%d): Create a hash object. CryptCreateHash()\n"), GetLastError());
#endif
			goto Exit_MyEncryptFile;
		}

		//-----------------------------------------------------------
		// Hash the password. 
		if (CryptHashData(
			hHash,
			(BYTE *)pszPassword,
			lstrlen(pszPassword),
			0))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("OK: Hash the password.  CryptHashData()\n"));
#endif
		}
		else
		{
#ifdef _DEBUG	
			_tprintf(TEXT("Error(%d): Hash the password.  CryptHashData()\n"), GetLastError());
#endif
			goto Exit_MyEncryptFile;
		}

		//-----------------------------------------------------------
		// Derive a session key from the hash object. 
		if (CryptDeriveKey(
			hCryptProv,
			ENCRYPT_ALGORITHM,
			hHash,
			KEYLENGTH,
			&hKey))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("OK: Derive a session key from the hash object.  CryptDeriveKey()\n"));
#endif
		}
		else
		{
#ifdef _DEBUG	
			_tprintf(TEXT("Error(%d): Derive a session key from the hash object.  CryptDeriveKey()\n"), GetLastError());
#endif
			goto Exit_MyEncryptFile;
		}
	}

	//---------------------------------------------------------------
	// The session key is now ready. If it is not a key derived from 
	// a  password, the session key encrypted with the private key 
	// has been written to the destination file.

	//---------------------------------------------------------------
	// Determine the number of bytes to encrypt at a time. 
	// This must be a multiple of ENCRYPT_BLOCK_SIZE.
	// ENCRYPT_BLOCK_SIZE is set by a #define statement.
	dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;

	//---------------------------------------------------------------
	// Determine the block size. If a block cipher is used, 
	// it must have room for an extra block. 
	if (ENCRYPT_BLOCK_SIZE > 1)
	{
		dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE;
	}
	else
	{
		dwBufferLen = dwBlockLen;
	}

	//---------------------------------------------------------------
	// Allocate memory. 
	if (pbBuffer = (BYTE *)malloc(dwBufferLen))
	{
#ifdef _DEBUG	
		_tprintf(TEXT("OK: Allocate memory.  malloc(dwBufferLen)\n"));
#endif
	}
	else
	{
#ifdef _DEBUG	
		_tprintf(TEXT("Error(%d):  Allocate memory. malloc(dwBufferLen)\n"), GetLastError());
#endif
		goto Exit_MyEncryptFile;
	}

	//---------------------------------------------------------------
	// In a do loop, encrypt the source file, and write to the source file. 
	bool fEOF = FALSE;
	do
	{
		if (!ReadFile(
			hSourceFile,
			pbBuffer,
			dwBlockLen,
			&dwCount,
			NULL))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("Error(%d): In a do loop, encrypt the source file, and write to the source file. ReadFile()\n"), GetLastError());
#endif
			goto Exit_MyEncryptFile;
		}

		if (dwCount < dwBlockLen)
		{
			fEOF = TRUE;
		}

		//-----------------------------------------------------------
		// Encrypt data. 
		if (!CryptEncrypt(
			hKey,
			NULL,
			fEOF,
			0,
			pbBuffer,
			&dwCount,
			dwBufferLen))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("Error(%d): Encrypt data.  CryptEncrypt\n"), GetLastError());
#endif
			goto Exit_MyEncryptFile;
		}

		//-----------------------------------------------------------
		// Write the encrypted data to the destination file. 
		if (!WriteFile(
			hDestinationFile,
			pbBuffer,
			dwCount,
			&dwCount,
			NULL))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("Error(%d): Write the encrypted data to the destination file.\n"), GetLastError());
#endif
			goto Exit_MyEncryptFile;
		}

		//-----------------------------------------------------------
		// End the do loop when the last block of the source file 
		// has been read, encrypted, and written to the destination 
		// file.
	} while (!fEOF);

	fReturn = true;

Exit_MyEncryptFile:
	//---------------------------------------------------------------
	// Close files.
	if (hSourceFile)
	{
		CloseHandle(hSourceFile);
	}

	if (hDestinationFile)
	{
		CloseHandle(hDestinationFile);
	}

	//---------------------------------------------------------------
	// Free memory. 
	if (pbBuffer)
	{
		free(pbBuffer);
	}


	//-----------------------------------------------------------
	// Release the hash object. 
	if (hHash)
	{
		CryptDestroyHash(hHash);
		hHash = NULL;
	}

	//---------------------------------------------------------------
	// Release the session key. 
	if (hKey)
	{
		CryptDestroyKey(hKey);
	}

	//---------------------------------------------------------------
	// Release the provider handle. 
	if (hCryptProv)
	{
		CryptReleaseContext(hCryptProv, 0);
	}

	return fReturn;
}

extern "C" __declspec(dllexport) bool MyDecryptFile(
	LPTSTR pszSourceFile,
	LPTSTR pszDestinationFile,
	LPTSTR pszPassword)
{
	bool fReturn = false;
	HANDLE hSourceFile = INVALID_HANDLE_VALUE;
	HANDLE hDestinationFile = INVALID_HANDLE_VALUE;
	HCRYPTKEY hKey = NULL;
	HCRYPTHASH hHash = NULL;

	HCRYPTPROV hCryptProv = NULL;

	DWORD dwCount;
	PBYTE pbBuffer = NULL;
	DWORD dwBlockLen;
	DWORD dwBufferLen;

#ifdef _DEBUG	
	_tprintf(TEXT("MyDecryptFile() loaded:\n"));
	_tprintf(TEXT("SourceFile: %s\nDestinationFile: %s\nPassword: %s\n"), pszSourceFile, pszDestinationFile, pszPassword);
#endif

	// Open the source file. 
	hSourceFile = CreateFile(
		pszSourceFile,
		FILE_READ_DATA,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE == hSourceFile)
	{
#ifdef _DEBUG	
		_tprintf(TEXT("Error[%d]: Open the source file. CreateFile(%s)\n"),GetLastError(), pszSourceFile);
#endif
		goto Exit_MyDecryptFile;
	}


	// Open the destination file. 
	hDestinationFile = CreateFile(
		pszDestinationFile,
		FILE_WRITE_DATA,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE == hDestinationFile)
	{
#ifdef _DEBUG	
		_tprintf(TEXT("Error[%d]: Open the destination file. CreateFile(%s)\n"), GetLastError(), pszDestinationFile);
#endif
		goto Exit_MyDecryptFile;
	}

	//---------------------------------------------------------------
	// Get the handle to the default provider. 
	if (CryptAcquireContext(
		&hCryptProv,
		NULL,
		MS_ENHANCED_PROV,
		PROV_RSA_FULL,
		0))
	{
#ifdef _DEBUG	
		_tprintf(TEXT("OK: Get the handle to the default provider. CryptAcquireContext()\n"));
#endif
	}
	else
	{
#ifdef _DEBUG	
		_tprintf(TEXT("Error[%d] Get the handle to the default provider. CryptAcquireContext\n"), GetLastError());
#endif
		goto Exit_MyDecryptFile;
	}

	// Create the session key.
	if (!pszPassword || !pszPassword[0])
	{

		// Decrypt the file with the saved session key. 

		DWORD dwKeyBlobLen;
		PBYTE pbKeyBlob = NULL;

		// Read the key BLOB length from the source file. 
		if (!ReadFile(
			hSourceFile,
			&dwKeyBlobLen,
			sizeof(DWORD),
			&dwCount,
			NULL))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("Error[%d] Read the key BLOB length from the source file.  ReadFile()\n"), GetLastError());
#endif
			goto Exit_MyDecryptFile;
		}

		// Allocate a buffer for the key BLOB.
		if (!(pbKeyBlob = (PBYTE)malloc(dwKeyBlobLen)))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("Error[%d] Allocate a buffer for the key BLOB.  malloc()\n"), GetLastError());
#endif
			//MyHandleError(TEXT("Memory allocation error.\n"),E_OUTOFMEMORY);
			goto Exit_MyDecryptFile;
		}


		//-----------------------------------------------------------
		// Read the key BLOB from the source file. 
		if (!ReadFile(
			hSourceFile,
			pbKeyBlob,
			dwKeyBlobLen,
			&dwCount,
			NULL))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("Error[%d] Read the key BLOB from the source file.  ReadFile()\n"), GetLastError());
#endif
			goto Exit_MyDecryptFile;
		}

		//-----------------------------------------------------------
		// Import the key BLOB into the CSP. 
		if (!CryptImportKey(
			hCryptProv,
			pbKeyBlob,
			dwKeyBlobLen,
			0,
			0,
			&hKey))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("Error[%d] Import the key BLOB into the CSP.  CryptImportKey()\n"), GetLastError());
#endif
			goto Exit_MyDecryptFile;
		}

		if (pbKeyBlob)
		{
			free(pbKeyBlob);
		}
	}
	else
	{
		//-----------------------------------------------------------
		// Decrypt the file with a session key derived from a 
		// password. 

		//-----------------------------------------------------------
		// Create a hash object. 
		if (!CryptCreateHash(
			hCryptProv,
			CALG_MD5,
			0,
			0,
			&hHash))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("Error[%d] Create a hash object.  CryptCreateHash()\n"), GetLastError());
#endif
			goto Exit_MyDecryptFile;
		}

		//-----------------------------------------------------------
		// Hash in the password data. 
		if (!CryptHashData(
			hHash,
			(BYTE *)pszPassword,
			lstrlen(pszPassword),
			0))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("Error[%d] Hash in the password data.  CryptHashData()\n"), GetLastError());
#endif
			goto Exit_MyDecryptFile;
		}

		//-----------------------------------------------------------
		// Derive a session key from the hash object. 
		if (!CryptDeriveKey(
			hCryptProv,
			ENCRYPT_ALGORITHM,
			hHash,
			KEYLENGTH,
			&hKey))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("Error[%d] Derive a session key from the hash object.   CryptDeriveKey()\n"), GetLastError());
#endif
			goto Exit_MyDecryptFile;
		}
	}

	//---------------------------------------------------------------
	// The decryption key is now available, either having been 
	// imported from a BLOB read in from the source file or having 
	// been created by using the password. This point in the program 
	// is not reached if the decryption key is not available.

	//---------------------------------------------------------------
	// Determine the number of bytes to decrypt at a time. 
	// This must be a multiple of ENCRYPT_BLOCK_SIZE. 
	
	dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;
	dwBufferLen = dwBlockLen;

	//---------------------------------------------------------------
	// Allocate memory for the file read buffer. 
	if (!(pbBuffer = (PBYTE)malloc(dwBufferLen)))
	{
#ifdef _DEBUG	
		_tprintf(TEXT("Error[%d] Allocate memory for the file read buffer.  malloc()\n"), GetLastError());
#endif
		goto Exit_MyDecryptFile;
	}

	//---------------------------------------------------------------
	// Decrypt the source file, and write to the destination file. 
	//DWORD offsetCount = offsetSrc;
	bool fEOF = false;
	do
	{
		//-----------------------------------------------------------
		// Read up to dwBlockLen bytes from the source file. 
		if (!ReadFile(
			hSourceFile,
			pbBuffer,
			dwBlockLen,
			&dwCount,
			NULL))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("Error[%d] Read up to dwBlockLen bytes from the source file.  ReadFile()\n"), GetLastError());
#endif
			goto Exit_MyDecryptFile;
		}
		//offsetCount = offsetCount - dwCount;
		if (dwCount < dwBlockLen)
		{
			fEOF = TRUE;
		}

		//-----------------------------------------------------------
		// Decrypt the block of data. 
		if (!CryptDecrypt(
			hKey,
			0,
			fEOF,
			0,
			pbBuffer,
			&dwCount))
		{
#ifdef _DEBUG
			_tprintf(TEXT("Error[%d] Decrypt the block of data. CryptDecrypt()\n"), GetLastError());
#endif
			goto Exit_MyDecryptFile;
		}

		//-----------------------------------------------------------
		// Write the decrypted data to the destination file. 
		if (!WriteFile(
			hDestinationFile,
			pbBuffer,
			dwCount,
			&dwCount,
			NULL))
		{
#ifdef _DEBUG
			_tprintf(TEXT("Error[%d] Write the decrypted data to the destination file. WriteFile()\n"), GetLastError());
#endif
			goto Exit_MyDecryptFile;
		}

		//-----------------------------------------------------------
		// End the do loop when the last block of the source file 
		// has been read, encrypted, and written to the destination 
		// file.
	} while (!fEOF);

	fReturn = true;

Exit_MyDecryptFile:

	//---------------------------------------------------------------
	// Free the file read buffer.
	if (pbBuffer)
	{
		free(pbBuffer);
	}

	//---------------------------------------------------------------
	// Close files.
	if (hSourceFile)
	{
		CloseHandle(hSourceFile);
	}

	if (hDestinationFile)
	{
		CloseHandle(hDestinationFile);
	}

	//-----------------------------------------------------------
	// Release the hash object. 
	if (hHash)
	{
		if (!(CryptDestroyHash(hHash)))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("OK: Release the hash object.  CryptDestroyHash()\n"));
#endif
		}

		hHash = NULL;
	}

	//---------------------------------------------------------------
	// Release the session key. 
	if (hKey)
	{
		if (!(CryptDestroyKey(hKey)))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("OK: Release the session key.   CryptDestroyKey()\n"));
#endif
		}
	}

	//---------------------------------------------------------------
	// Release the provider handle. 
	if (hCryptProv)
	{
		if (!(CryptReleaseContext(hCryptProv, 0)))
		{
#ifdef _DEBUG	
			_tprintf(TEXT("OK: Release the provider handle.  CryptReleaseContext()\n"));
#endif
		}
	}

	return fReturn;
}


