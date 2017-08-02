# IsFileSigned

C Win32 API code segment. Utilizes kernel level API calls to achieve similiar functionality to that of WinVerifyTrust.

## Getting Started

Make a pull request, download the file as a zip file, or copy the code from IsFileSigned.c. This code segment is meant to act as an extension to another application. 


### Prerequisites

User must import NtReadFile, NtWaitForSingleObject, and Wdm.h. 

An example of importing NtReadFile:
```
typedef NTSTATUS (NTAPI *NTREADFILE)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
HMODULE hMod = LoadLibrary(L"Ntdll.dll");
NTREADFILE NtReadFile = GetProcAddress(hMod, "NtReadFile");

```

## Deployment

Add additional notes about how to deploy this on a live system

## Built With

* [Dev C++](https://sourceforge.net/projects/orwelldevcpp/)
* [Microsoft Windows API](https://msdn.microsoft.com/en-us/library/aa383723(VS.85).aspx)


## Authors

* **Mathew A. Stefanowich** - *Initial work*

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
