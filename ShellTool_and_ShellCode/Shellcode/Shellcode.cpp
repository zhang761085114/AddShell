#include "Shellcode.h"




void* __cdecl mymemcpy(
    void* dst,
    const void* src,
    size_t count
) {

    void* ret = dst;

    while (count--) {

        *(char*)dst = *(char*)src;
        dst = (char*)dst + 1;
        src = (char*)src + 1;
    }

    return(ret);
}

#define VirtualProtect pEnv->pfnVirtualProtect
DWORD MyLoadLibrary(LPBYTE pPEBuff, Environment* pEnv, LPBYTE pTableBuf, LPBYTE pMyImpBuf) {

    DWORD dwImageBase;
    HANDLE hFile;
    HANDLE hFileMap;
    LPVOID pPEBuf;
    IMAGE_DOS_HEADER* pDosHdr;
    IMAGE_NT_HEADERS* pNTHdr;
    IMAGE_SECTION_HEADER* pSecHdr;
    DWORD dwNumOfSecs;
    IMAGE_IMPORT_DESCRIPTOR* pImpHdr;
    DWORD dwSizeOfHeaders;
    IMAGE_IMPORT_DESCRIPTOR hdrZeroImp;
    HMODULE hDll;
    DWORD dwOep;
    DWORD dwOldProc;
    IMAGE_BASE_RELOCATION* pReloc;
    DWORD dwOfReloc;
    DWORD dwOff;

    //RtlZeroMemory(&hdrZeroImp, sizeof(IMAGE_IMPORT_DESCRIPTOR));

    pPEBuf = pPEBuff;

    //����
    //dos ͷ
    pDosHdr = (IMAGE_DOS_HEADER*)pPEBuf;

    //ntͷ
    pNTHdr = (IMAGE_NT_HEADERS*)(pDosHdr->e_lfanew + (DWORD)pPEBuf);

    //��ԭ�ڱ�
    DWORD nSecNum = *(DWORD*)pTableBuf;
    mymemcpy((void*)((DWORD)&pNTHdr->OptionalHeader + pNTHdr->FileHeader.SizeOfOptionalHeader), 
        pTableBuf + 4, nSecNum * 40);

    //��ԭ�����
    mymemcpy(&(pNTHdr->OptionalHeader.DataDirectory[1].VirtualAddress),
        pTableBuf + 4 + nSecNum * 40, 4);
    mymemcpy(&(pNTHdr->OptionalHeader.DataDirectory[1].Size),
        pTableBuf + 4 + nSecNum * 40 + 4, 4);

    //��ԭ�ض�λ��
    mymemcpy(&(pNTHdr->OptionalHeader.DataDirectory[5].VirtualAddress),
        pTableBuf + 4 + nSecNum * 40 + 4 + 4, 4);
    mymemcpy(&(pNTHdr->OptionalHeader.DataDirectory[5].Size),
        pTableBuf + 4 + nSecNum * 40 + 4 + 4 + 4, 4);

    //ѡ��ͷ��Ϣ
    dwSizeOfHeaders = pNTHdr->OptionalHeader.SizeOfHeaders;


    //�Լ���ģ���ַ
    dwImageBase = (DWORD)GetModuleBase();

    dwOff = dwImageBase - pNTHdr->OptionalHeader.ImageBase; //�¾�ImageBase��ƫ�Ʋ�

    dwOep = pNTHdr->OptionalHeader.AddressOfEntryPoint + dwImageBase;
    //�ڱ�
    dwNumOfSecs = pNTHdr->FileHeader.NumberOfSections;
    pSecHdr = (IMAGE_SECTION_HEADER*)((DWORD)&pNTHdr->OptionalHeader + pNTHdr->FileHeader.SizeOfOptionalHeader);


    

    //����PEͷ
    VirtualProtect((LPVOID)dwImageBase, pNTHdr->OptionalHeader.SizeOfHeaders, PAGE_EXECUTE_READWRITE, &dwOldProc);
    mymemcpy((void*)dwImageBase, pPEBuf, dwSizeOfHeaders);
    VirtualProtect((LPVOID)dwImageBase, pNTHdr->OptionalHeader.SizeOfHeaders, dwOldProc, &dwOldProc);


    //���սڱ�������������
    int i = 0;
    IMAGE_SECTION_HEADER* dwSecTmp = pSecHdr;
    while (i < dwNumOfSecs) {

        //Ŀ��
        DWORD dwDstMem = dwImageBase;
        dwDstMem += dwSecTmp->VirtualAddress;

        //Դ
        DWORD dwSrcFile = (DWORD)pPEBuf + dwSecTmp->PointerToRawData;

        //����
        VirtualProtect((LPVOID)dwDstMem, dwSecTmp->SizeOfRawData, PAGE_EXECUTE_READWRITE, &dwOldProc);
        mymemcpy((void*)dwDstMem, (void*)dwSrcFile, dwSecTmp->SizeOfRawData);
        VirtualProtect((LPVOID)dwImageBase, pNTHdr->OptionalHeader.SizeOfHeaders, dwOldProc, &dwOldProc);

        i++;
        dwSecTmp = (IMAGE_SECTION_HEADER*)((char*)dwSecTmp + sizeof(IMAGE_SECTION_HEADER));
    }


    //��ȡ�����
    if (pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0) {

        pImpHdr = (IMAGE_IMPORT_DESCRIPTOR*)(dwImageBase + pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);


        //�������
        IMAGE_IMPORT_DESCRIPTOR* pImpHdrTmp = pImpHdr;
        DWORD dwNum = 0;
        int nImpNum = 0;

        while (true) {

            //�жϽ�����ȫ0�����
            if (memcmp(pImpHdrTmp, &hdrZeroImp, sizeof(IMAGE_IMPORT_DESCRIPTOR)) == 0) {

                break;
            }

            //�ж��ֶ�, Ϊ�������
            if (pImpHdrTmp->Name == NULL || pImpHdrTmp->FirstThunk == NULL) {

                break;
            }

            //����dll
            hDll = pEnv->pfnLoadLibraryA((LPCSTR)(dwImageBase + pImpHdrTmp->Name));

            //��ȡ�����ַ��, IAT
            DWORD dwIAT = pImpHdrTmp->FirstThunk + dwImageBase;
            DWORD dwINT = dwIAT;
            //��ȡ�������Ʊ�, INT
            if (pImpHdrTmp->OriginalFirstThunk != NULL) {

                dwINT = pImpHdrTmp->OriginalFirstThunk + dwImageBase;
            }

            //�����������Ʊ�
            while (*(DWORD*)(dwINT) != 0) {

                if ((*(DWORD*)pImpHdrTmp) >> 31) {

                    //��ŵ���, ��ȡ���
                    dwNum = *(DWORD*)pImpHdrTmp;
                    dwNum = (dwNum << 16) >> 16;

                }
                else {

                    //���Ƶ���
                    dwNum = *(DWORD*)pImpHdrTmp;
                    dwNum += dwImageBase;
                    dwNum += 2;

                }

                //��ȡ������ַ���Ȳ�Ҫ�ѵ�ֱַ��д��IAT
                //�����Ƚ�.imp�ڵ�ַд��IAT(ÿ16���ֽ�дһ��)
                //��.imp����д����ָ��push ������ַ retn
                //�����������_acmdln����ô����Ͳ�Ҫ���������
                if (((LPCSTR)((*(DWORD*)(dwINT)) + dwImageBase + 2))[0] == '_' && ((LPCSTR)((*(DWORD*)(dwINT)) + dwImageBase + 2))[1] == 'a' &&
                    ((LPCSTR)((*(DWORD*)(dwINT)) + dwImageBase + 2))[2] == 'c' && ((LPCSTR)((*(DWORD*)(dwINT)) + dwImageBase + 2))[3] == 'm' &&
                    ((LPCSTR)((*(DWORD*)(dwINT)) + dwImageBase + 2))[4] == 'd' && ((LPCSTR)((*(DWORD*)(dwINT)) + dwImageBase + 2))[5] == 'l' &&
                    ((LPCSTR)((*(DWORD*)(dwINT)) + dwImageBase + 2))[6] == 'n') {

                    *(DWORD*)dwIAT = (DWORD)pEnv->pfnGetProcAddress(hDll, (LPCSTR)((*(DWORD*)(dwINT)) + dwImageBase + 2));
                }
                else {

                    DWORD dwMyAddr = (DWORD)pMyImpBuf + nImpNum * 0x10;
                    DWORD dwFuncAddr = (DWORD)pEnv->pfnGetProcAddress(hDll, (LPCSTR)((*(DWORD*)(dwINT)) + dwImageBase + 2));
                    *(DWORD*)dwIAT = dwMyAddr;
                    *(BYTE*)dwMyAddr = 0x68;    //push
                    *(DWORD*)(dwMyAddr + 1) = dwFuncAddr;  //��ʵ������ַ
                    *(BYTE*)(dwMyAddr + 5) = 0xC3;  //retn
                }
                

                dwIAT += 4;
                dwINT += 4;
                nImpNum++;

            }


            pImpHdrTmp = (IMAGE_IMPORT_DESCRIPTOR*)((char*)pImpHdrTmp + sizeof(IMAGE_IMPORT_DESCRIPTOR));
        }
    }

    if (pNTHdr->OptionalHeader.DataDirectory[5].VirtualAddress != 0) {

        //��λ�ض�λ��
        pReloc = (IMAGE_BASE_RELOCATION*)(pNTHdr->OptionalHeader.DataDirectory[5].VirtualAddress + dwImageBase);
        dwOfReloc = pNTHdr->OptionalHeader.DataDirectory[5].Size;


        int nSize = 0;

        while (nSize < dwOfReloc) {

            //�����׵�ַ
            int nOff = (DWORD)pReloc + 8;

            //����Ԫ�ظ���
            int nCnt = (pReloc->SizeOfBlock - 8) >> 1;

            //��������
            int j = 0;
            while (j < nCnt) {

                //ȡ��һ��
                int nDataOff = *(WORD*)(nOff + j * 2);

                //�ж��Ƿ�����Ч�ض�λ��
                if (nDataOff & 0x00003000) {

                    //����
                    nDataOff = nDataOff & 0x0fff;  //ҳƫ��
                    nDataOff = nDataOff + pReloc->VirtualAddress;
                    nDataOff = nDataOff + dwImageBase;

                    *(int*)nDataOff = *(int*)nDataOff + dwOff;
                }

                j++;
            }

            //������һ����ҳ
            nSize += pReloc->SizeOfBlock;
            pReloc = (IMAGE_BASE_RELOCATION*)((char*)pReloc + pReloc->SizeOfBlock);

        }
    }



    

    
    return dwOep;
}

FARPROC MyGetProcAddress(HMODULE hMod, LPCSTR lpProcName) {

    IMAGE_DOS_HEADER* pDosHdr;
    IMAGE_NT_HEADERS* pNTHdr;
    IMAGE_EXPORT_DIRECTORY* pExpDir;
    DWORD pAddrTbl;
    DWORD pNameTbl;
    DWORD pOrdTbl;

    //����dosͷ
    pDosHdr = (IMAGE_DOS_HEADER*)hMod;

    //ntͷ
    pNTHdr = (IMAGE_NT_HEADERS*)(pDosHdr->e_lfanew + (DWORD)hMod);

    //��ȡ�����
    pExpDir = (IMAGE_EXPORT_DIRECTORY*)(pNTHdr->OptionalHeader.DataDirectory[0].VirtualAddress + (DWORD)hMod);

    //���뺯����ַ��
    pAddrTbl = (DWORD)(pExpDir->AddressOfFunctions + (DWORD)hMod);

    //���뺯�����Ʊ�
    pNameTbl = (DWORD)(pExpDir->AddressOfNames + (DWORD)hMod);

    //������ű�
    pOrdTbl = (DWORD)(pExpDir->AddressOfNameOrdinals + (DWORD)hMod);

    //�ж�����Ż�������
    if ((int)lpProcName & 0xffff0000) {

        //����
        int i = 0;
        while (i < pExpDir->NumberOfNames) {

            //��ȡ���Ƶ�ַ
            int nNameOff = (int)(*(DWORD*)(pNameTbl + i * 4) + (DWORD)hMod);

            //�ַ����Ƚ�
            if (((char*)nNameOff)[0] == 'G'&& ((char*)nNameOff)[1] == 'e'&& ((char*)nNameOff)[2] == 't'&&
                ((char*)nNameOff)[3] == 'P'&& ((char*)nNameOff)[4] == 'r'&& ((char*)nNameOff)[5] == 'o'&&
                ((char*)nNameOff)[6] == 'c'&& ((char*)nNameOff)[7] == 'A'&& ((char*)nNameOff)[8] == 'd'&&
                ((char*)nNameOff)[9] == 'd'&& ((char*)nNameOff)[10] == 'r'&& ((char*)nNameOff)[11] == 'e'&&
                ((char*)nNameOff)[12] == 's'&& ((char*)nNameOff)[13] == 's') {

                //�ҵ���, �ӵ�����ű�ȡ��������ַ�±�
                int nOrdinal = *(WORD*)(pOrdTbl + i * 2);

                //�ӵ����ַ���±�Ѱַ����ȡ����������ַ
                int nFuncAddr = *(DWORD*)(pAddrTbl + nOrdinal * 4);

                

                //����ת��
                nFuncAddr += (int)hMod;


               

                //���ص�ַ
                if (nFuncAddr != NULL) {

                    return (FARPROC)nFuncAddr;
                }
            }

            i++;

        }
    }

    else {

        //���
        int nOrdinal = (DWORD)lpProcName - pExpDir->Base;

        //�ӵ����ַ���±�Ѱַ����ȡ����������ַ
        int nFuncAddr = *(DWORD*)(pAddrTbl + nOrdinal * 4);

        //���ص�ַ
        if (nFuncAddr != NULL) {

            return (FARPROC)(nFuncAddr + (DWORD)hMod);
        }

    }


    return 0;
}



void Entry() {

	Environment env;
	InitEnvironment(&env);

	//��ʱPE�����ؽ����ڴ��У���ģ���ַ��ʼ������ѹ�����ݽ�λ��
	LPBYTE pImgBase = (LPBYTE)GetModuleBase();
	auto pDosHdr = (PIMAGE_DOS_HEADER)pImgBase;
	auto pNtHdr = (PIMAGE_NT_HEADERS)(pImgBase + pDosHdr->e_lfanew);
	auto pSecHdr = (PIMAGE_SECTION_HEADER)
		((LPBYTE)&pNtHdr->OptionalHeader + pNtHdr->FileHeader.SizeOfOptionalHeader);

	LPBYTE pComData = pImgBase + pSecHdr[1].VirtualAddress;

	DWORD dwComSize = pSecHdr[1].PointerToRelocations;
	DWORD dwDeComSize = pSecHdr[1].PointerToLinenumbers;

	//��ѹ��

	LPBYTE pPEBuff = (LPBYTE)env.pfnVirtualAlloc(NULL, dwDeComSize, MEM_COMMIT, PAGE_READWRITE);

	DECOMPRESSOR_HANDLE hDecompressor;
	BOOL bSuccess = env.pfnCreateDecompressor(
		COMPRESS_ALGORITHM_XPRESS_HUFF,
		NULL,
		&hDecompressor
	);

	DWORD dwDecompressedBufferSize = 0;
	bSuccess = env.pfnDecompress(
		hDecompressor,
		pComData,
		dwComSize,
		pPEBuff,
		dwDeComSize,
		&dwDecompressedBufferSize
	);

	//�õ���ѹ��������ݣ����俽������ǰImageBase�����൱�ڸ�����PEͷ�Ϳսڲ���
    //��ԭ�ڱ�������ض�λ�������ݷ����˵�4������
    LPBYTE pTableBuf = pSecHdr[3].VirtualAddress + pImgBase;
    LPBYTE pMyImpBuf = pSecHdr[4].VirtualAddress + pImgBase;
	DWORD dwOep = MyLoadLibrary(pPEBuff, &env, pTableBuf, pMyImpBuf);

    


	__asm jmp dwOep;

}

void InitEnvironment(Environment* pEnv) {

    //��ȡkernel32��ַ
    HMODULE hKer = GetKernel32();

    //��kernel32�������л�ȡLoadLibrary��GetProcAddress��ַ
    char szGetProcAddress[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s', '\0' };
    pEnv->pfnGetProcAddress = (PFN_GetProcAddress)MyGetProcAddress(hKer, szGetProcAddress);

    char szLoadLibrary[] = { 'L', 'o','a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };
    pEnv->pfnLoadLibraryA = (PFN_LoadLibraryA)pEnv->pfnGetProcAddress(hKer, szLoadLibrary);

    //����LoadLibrary��GetProcAddress���Ϳ���ʹ�����⺯����
    //��ȡ��ѹ����غ���

    char szCab[] = { 'C','a','b','i','n','e','t', '\0' };
    HMODULE hCab = pEnv->pfnLoadLibraryA(szCab);

    char szCreateDecompressor[] = { 'C','r','e','a','t','e','D','e','c','o','m','p','r','e','s','s','o','r', '\0' };
    pEnv->pfnCreateDecompressor = (PFN_CreateDecompressor)pEnv->pfnGetProcAddress(hCab, szCreateDecompressor);

    char szDecompress[] = { 'D','e','c','o','m','p','r','e','s','s', '\0' };
    pEnv->pfnDecompress = (PFN_Decompress)pEnv->pfnGetProcAddress(hCab, szDecompress);

    char szVirtualAlloc[] = { 'V','i','r','t','u','a','l','A','l','l','o','c', '\0' };
    pEnv->pfnVirtualAlloc = (PFN_VirtualAlloc)pEnv->pfnGetProcAddress(hKer, szVirtualAlloc);

    char szVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t','\0' };
    pEnv->pfnVirtualProtect = (PFN_VirtualProtect)pEnv->pfnGetProcAddress(hKer, szVirtualProtect);



}

HMODULE GetKernel32()
{
    HMODULE hKer;
    __asm {

        mov eax, dword ptr fs:[0x30]
        mov eax, dword ptr[eax + 0x0C]
        mov eax, dword ptr[eax + 0x0C]
        mov eax, dword ptr[eax]
        mov eax, dword ptr[eax]
        mov eax, dword ptr[eax + 0x18]
        mov hKer, eax
    }

    return hKer;
}

HMODULE GetModuleBase()
{
    HMODULE hKer;
    __asm {

        mov eax, dword ptr fs : [0x30]
        mov eax, dword ptr[eax + 0x0C]
        mov eax, dword ptr[eax + 0x0C]
        mov eax, dword ptr[eax + 0x18]
        mov hKer, eax
    }

    return hKer;
}

