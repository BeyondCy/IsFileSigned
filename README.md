IsFileSigned
========

This application is a raw user-level implementation of WinVerifyTrust using limited function calls.

## Usage

* Prior to usage functions: NtCreateFile, NtReadFile, RtlDosPathNameToNtPathName_U, RtlInitUnicodeString, NtWaitForSingleObject must be imported.
* VxSetFilePointer is a custom implemention of SetFilePointer. VxSetFilePointer can easily be replaced with SetFilePointer by simply changing the function name from VxSetFilePointer to SetFilePointer.
* An example of usage is commented at the top of the source code.
