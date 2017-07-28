/*
Prior to function call + function call

WCHAR *szPath = "C:\\Users\\...\\Desktop\\TestFile.exe";

DWORD dwCount = ERROR_SUCCESS;
HANDLE hHandle;

NTSTATUS Status;
OBJECT_ATTRIBUTES Attributes;
IO_STATUS_BLOCK IoBlock;
LARGE_INTEGER Integer;
UNICODE_STRING uString;
    
VxZeroMemory(&Attributes, sizeof(OBJECT_ATTRIBUTES));
VxZeroMemory(&IoBlock, sizeof(IO_STATUS_BLOCK));
VxZeroMemory(&Integer, sizeof(LARGE_INTEGER));
Integer.QuadPart = 2048;
VxZeroMemory(&uString, sizeof(UNICODE_STRING));
    
if(szPath[0] != L'\\')
    RtlDosPathNameToNtPathName_U(szPath, &uString, NULL, NULL);
else
    RtlInitUnicodeString(&uString, szPath);
    	
InitializeObjectAttributes(&Attributes, &uString, OBJ_CASE_INSENSITIVE, NULL, NULL);

if(NtCreateFile(&hHandle, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &Attributes, &IoBlock, &Integer, FILE_ATTRIBUTE_NORMAL, 
		FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 
		0, 0) != 0x00000000){     return;     }


if((!VxIsTargetSigned(hHandle, CERT_SECTION_TYPE_ANY, &dwCount, NULL, 0)) && (dwCount == ERROR_SUCCESS))
    	return;

*/
BOOL VxIsTargetSigned(HANDLE FileHandle, DWORD TypeFilter, PDWORD CertificateCount, PDWORD Indices, DWORD IndexCount) //NOT
{
	DWORD dwSize, dwCount, dwAddress, dwIndex, dwOffset;
	WIN_CERTIFICATE Hdr;
	BOOL bFlag;
	IO_STATUS_BLOCK IoBlock;
	NTSTATUS Status;
	CONST SIZE_T CertHdrSize = sizeof(Hdr) - sizeof(Hdr.bCertificate);

	if(!VxGetSecurityDirectoryOffsetEx(FileHandle, &dwAddress, &dwSize))
		goto FAILURE;
		
	dwOffset 			= ERROR_SUCCESS;
	dwIndex 			= ERROR_SUCCESS;
	*CertificateCount 	= ERROR_SUCCESS;
	
	VxZeroMemory(&IoBlock, sizeof(IO_STATUS_BLOCK));
	
	while(dwOffset < dwSize)
	{
		if(VxSetFilePointer(FileHandle, dwAddress + dwOffset, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
			goto FAILURE;
			
		Status = NtReadFile(FileHandle, NULL, NULL, NULL, &IoBlock, &Hdr, CertHdrSize, NULL, NULL);
		if(Status == 0x00000103)
		{
			Status = NtWaitForSingleObject(FileHandle, FALSE, NULL);
			if(Status == ERROR_SUCCESS)
				Status = IoBlock.Status;
		}
		
		if(Status == ERROR_SUCCESS)
			dwCount = IoBlock.Information;
		else
			goto FAILURE;
			
		if((dwCount != CertHdrSize) || (Hdr.dwLength < CertHdrSize) || (Hdr.dwLength > (dwSize - dwOffset)))
			goto FAILURE;
			
		if((TypeFilter == CERT_SECTION_TYPE_ANY) || (TypeFilter == Hdr.wCertificateType))
		{
			(*CertificateCount)++;
			if(Indices && *CertificateCount <= IndexCount)
				*Indices++ = dwIndex;
		}
		
		dwOffset += Hdr.dwLength;
		
		if(Hdr.dwLength % 0x08)
			dwOffset += 8 - (Hdr.dwLength % 0x08);
			
		dwIndex++;
	}

	return TRUE;
	
FAILURE:
	
	return FALSE;
}

BOOL VxGetSecurityDirectoryOffsetEx(HANDLE hHandle, PDWORD dwOffset, PDWORD dwSize) //pi
{
	IMAGE_NT_HEADERS32 Hdr32;
	IMAGE_NT_HEADERS64 Hdr64;
	PIMAGE_DATA_DIRECTORY Data;
	INT dwReturn = VxGetCertificateNtHeaders(hHandle, NULL, &Hdr32, &Hdr64);
	
	switch(dwReturn)
	{
		case -1:
			return FALSE;
		case 0:
			Data = &Hdr32.OptionalHeader.DataDirectory[IMAGE_FILE_SECURITY_DIRECTORY];
			break;
		case 1:
			Data = &Hdr64.OptionalHeader.DataDirectory[IMAGE_FILE_SECURITY_DIRECTORY];
	}
	
	*dwSize = Data->Size;
	*dwOffset = Data->VirtualAddress;
	
	return TRUE;	
}

INT VxGetCertificateNtHeaders(HANDLE hHandle, PDWORD Offset, PIMAGE_NT_HEADERS32 Nt32, PIMAGE_NT_HEADERS64 Nt64) //pe
{
	IMAGE_DOS_HEADER Dos;
	DWORD dwCount = ERROR_SUCCESS;
	IO_STATUS_BLOCK IoBlock;
	VxZeroMemory(&IoBlock, sizeof(IO_STATUS_BLOCK));
	NTSTATUS Status;
		
	if(VxSetFilePointer(hHandle, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
		goto FAILURE;
		
	Status = NtReadFile(hHandle, NULL, NULL, NULL, &IoBlock, &Dos, sizeof(Dos), NULL, NULL);
	if(Status == 0x00000103)
	{
		Status = NtWaitForSingleObject(hHandle, FALSE, NULL);
		if(Status == ERROR_SUCCESS)
			Status = IoBlock.Status;
	}
	
	if(Status == ERROR_SUCCESS)
		dwCount = IoBlock.Information;
	else
		goto FAILURE;
		
	if((dwCount != sizeof(Dos)) || (Dos.e_magic != IMAGE_DOS_SIGNATURE))
		goto FAILURE;
		
	if(VxSetFilePointer(hHandle, Dos.e_lfanew, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
		goto FAILURE;

	dwCount = ERROR_SUCCESS;
	if(Dos.e_magic != IMAGE_DOS_SIGNATURE)
		*Offset = Dos.e_lfanew;
		
	Status = ERROR_SUCCESS;
	VxZeroMemory(&IoBlock, sizeof(IO_STATUS_BLOCK));
	
	Status = NtReadFile(hHandle, NULL, NULL, NULL, &IoBlock, Nt32, sizeof(IMAGE_NT_HEADERS32), NULL, NULL);
	if(Status == 0x00000103)
	{
		Status = NtWaitForSingleObject(hHandle, FALSE, NULL);
		if(Status == ERROR_SUCCESS)
			Status = IoBlock.Status;
	}
	
	if(Status == ERROR_SUCCESS)
		dwCount = IoBlock.Information;
	else
		goto FAILURE;
	
	if((dwCount != sizeof(IMAGE_NT_HEADERS32)) || (Nt32->Signature != IMAGE_NT_SIGNATURE))
		goto FAILURE;

	switch(Nt32->OptionalHeader.Magic)
	{
		case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
			return 0;
		case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		{
			if(VxSetFilePointer(hHandle, Dos.e_lfanew, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
				goto FAILURE;
				
			Status = ERROR_SUCCESS;
			VxZeroMemory(&IoBlock, sizeof(IO_STATUS_BLOCK));
			
			Status = NtReadFile(hHandle, NULL, NULL, NULL, &IoBlock, Nt64, sizeof(IMAGE_NT_HEADERS64), NULL, NULL);
			if(Status == 0x00000103)
			{
				Status = NtWaitForSingleObject(hHandle, FALSE, NULL);
				if(Status == ERROR_SUCCESS)
					Status = IoBlock.Status;
			}
	
			if(Status == ERROR_SUCCESS)
				dwCount = IoBlock.Information;
			else
				goto FAILURE;
				
			if((dwCount != sizeof(IMAGE_NT_HEADERS64)) || (Nt64->Signature != IMAGE_NT_SIGNATURE))
				goto FAILURE;
			else
				return 1;
		}
		default:
			goto FAILURE;
	}
		
FAILURE:
	
	return -1;
}

