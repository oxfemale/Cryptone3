# Cryptone3
This is crypto lib example for MSVC 15.
After build we are got crypton3.dll

crypton3.dll use 2 function for encript and dectryp:

//Encrypt file with Password 
//If all ok, return true and false if no.
bool MyEncryptFile(LPTSTR pszSourceFile,LPTSTR pszDestinationFile,LPTSTR pszPassword);

//Dencrypt file with Password 
//If all ok, return true and false if no.
bool MyDecryptFile(LPTSTR pszSourceFile,LPTSTR pszDestinationFile,LPTSTR pszPassword);
	
 
 Example use:

typedef BOOL ( *MyEncryptFileExp )( wchar_t*, wchar_t*, wchar_t* );
typedef BOOL ( *MyDecryptFileExp )( wchar_t*, wchar_t*, wchar_t* );

BOOL result = false;

MyEncryptFileExp MyEncryptFile = 0;
MyDecryptFileExp MyDecryptFile = 0;

HMODULE hModule = LoadLibraryExA("Cryptone3.dll", 0, 0x00000100);
	
 MyEncryptFile = (MyEncryptFileExp)GetProcAddress(hModule, "MyEncryptFile");
MyDecryptFile = (MyDecryptFileExp)GetProcAddress(hModule, "MyDecryptFile");

result = MyEncryptFile(payload_path, target_path, password);
result = MyDecryptFile(payload_path, target_path, password);

FreeLibrary(hModule);
 
 
 twitter: @oxfemale
 telegram: @BelousovaAlisa
 email: alice.eas7@gmail.com
