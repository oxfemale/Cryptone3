// 
// https://github.com/oxfemale/Cryptone3/
// twitter: @oxfemale
// email: alice.eas7@gmail.com
// telegram: @BelousovaAlisa
//
#include "stdafx.h"
#include <Windows.h>

int _tmain(int argc, TCHAR* argv[])
{
	typedef BOOL ( *MyEncryptFileExp )( wchar_t*, wchar_t*, wchar_t* );
	typedef BOOL ( *MyDecryptFileExp )( wchar_t*, wchar_t*, wchar_t* );

	wchar_t* todo = argv[1];
	wchar_t* payload_path = argv[2];
	wchar_t* target_path = argv[3];
	wchar_t* password = argv[4];
	
	BOOL result = false;
	MyEncryptFileExp MyEncryptFile = 0;
	MyDecryptFileExp MyDecryptFile = 0;

	
	HMODULE hModule = LoadLibrary(L"Cryptone3.dll");

	if(argc < 4) 
	{
		printf("usage: sourcefile outputfile password\r\n");
		return 0;
	}

	if(hModule != 0)
    {
		if(todo[0] == 'c')
		{
			MyEncryptFile = (MyEncryptFileExp)GetProcAddress(hModule, "MyEncryptFile");
			if (MyEncryptFile != 0) 
			{
				result = MyEncryptFile(payload_path, target_path, password);
				printf("Crypt result: %d\r\n", result);
				FreeLibrary(hModule);
				return 0;
			}else printf("error load API ProtectFile\r\n");
		}
		if(todo[0] == 'u')
		{
			MyDecryptFile = (MyDecryptFileExp)GetProcAddress(hModule, "MyDecryptFile");
			if (MyDecryptFile != 0) 
			{
				result = MyDecryptFile(payload_path, target_path, password);
				printf("Decrypt result: %d\r\n", result);
				FreeLibrary(hModule);
				return 0;
			}else printf("error load API UnProtectFile\r\n");
		}
		
		printf("wrong parametrs: use c or u");
		FreeLibrary(hModule);
    } else 
		printf("error load lib\r\n");

	return 0;
}
