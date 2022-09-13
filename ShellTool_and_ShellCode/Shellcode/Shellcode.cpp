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

    //解析
    //dos 头
    pDosHdr = (IMAGE_DOS_HEADER*)pPEBuf;

    //nt头
    pNTHdr = (IMAGE_NT_HEADERS*)(pDosHdr->e_lfanew + (DWORD)pPEBuf);

    //还原节表
    DWORD nSecNum = *(DWORD*)pTableBuf;
    mymemcpy((void*)((DWORD)&pNTHdr->OptionalHeader + pNTHdr->FileHeader.SizeOfOptionalHeader), 
        pTableBuf + 4, nSecNum * 40);

    //还原导入表
    mymemcpy(&(pNTHdr->OptionalHeader.DataDirectory[1].VirtualAddress),
        pTableBuf + 4 + nSecNum * 40, 4);
    mymemcpy(&(pNTHdr->OptionalHeader.DataDirectory[1].Size),
        pTableBuf + 4 + nSecNum * 40 + 4, 4);

    //还原重定位表
    mymemcpy(&(pNTHdr->OptionalHeader.DataDirectory[5].VirtualAddress),
        pTableBuf + 4 + nSecNum * 40 + 4 + 4, 4);
    mymemcpy(&(pNTHdr->OptionalHeader.DataDirectory[5].Size),
        pTableBuf + 4 + nSecNum * 40 + 4 + 4 + 4, 4);

    //选项头信息
    dwSizeOfHeaders = pNTHdr->OptionalHeader.SizeOfHeaders;


    //自己的模块基址
    dwImageBase = (DWORD)GetModuleBase();

    dwOff = dwImageBase - pNTHdr->OptionalHeader.ImageBase; //新旧ImageBase的偏移差

    dwOep = pNTHdr->OptionalHeader.AddressOfEntryPoint + dwImageBase;
    //节表
    dwNumOfSecs = pNTHdr->FileHeader.NumberOfSections;
    pSecHdr = (IMAGE_SECTION_HEADER*)((DWORD)&pNTHdr->OptionalHeader + pNTHdr->FileHeader.SizeOfOptionalHeader);


    

    //拷贝PE头
    VirtualProtect((LPVOID)dwImageBase, pNTHdr->OptionalHeader.SizeOfHeaders, PAGE_EXECUTE_READWRITE, &dwOldProc);
    mymemcpy((void*)dwImageBase, pPEBuf, dwSizeOfHeaders);
    VirtualProtect((LPVOID)dwImageBase, pNTHdr->OptionalHeader.SizeOfHeaders, dwOldProc, &dwOldProc);


    //按照节表，拷贝节区数据
    int i = 0;
    IMAGE_SECTION_HEADER* dwSecTmp = pSecHdr;
    while (i < dwNumOfSecs) {

        //目标
        DWORD dwDstMem = dwImageBase;
        dwDstMem += dwSecTmp->VirtualAddress;

        //源
        DWORD dwSrcFile = (DWORD)pPEBuf + dwSecTmp->PointerToRawData;

        //拷贝
        VirtualProtect((LPVOID)dwDstMem, dwSecTmp->SizeOfRawData, PAGE_EXECUTE_READWRITE, &dwOldProc);
        mymemcpy((void*)dwDstMem, (void*)dwSrcFile, dwSecTmp->SizeOfRawData);
        VirtualProtect((LPVOID)dwImageBase, pNTHdr->OptionalHeader.SizeOfHeaders, dwOldProc, &dwOldProc);

        i++;
        dwSecTmp = (IMAGE_SECTION_HEADER*)((char*)dwSecTmp + sizeof(IMAGE_SECTION_HEADER));
    }


    //获取导入表
    if (pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0) {

        pImpHdr = (IMAGE_IMPORT_DESCRIPTOR*)(dwImageBase + pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);


        //处理导入表
        IMAGE_IMPORT_DESCRIPTOR* pImpHdrTmp = pImpHdr;
        DWORD dwNum = 0;
        int nImpNum = 0;

        while (true) {

            //判断结束，全0项结束
            if (memcmp(pImpHdrTmp, &hdrZeroImp, sizeof(IMAGE_IMPORT_DESCRIPTOR)) == 0) {

                break;
            }

            //判断字段, 为空则结束
            if (pImpHdrTmp->Name == NULL || pImpHdrTmp->FirstThunk == NULL) {

                break;
            }

            //加载dll
            hDll = pEnv->pfnLoadLibraryA((LPCSTR)(dwImageBase + pImpHdrTmp->Name));

            //获取导入地址表, IAT
            DWORD dwIAT = pImpHdrTmp->FirstThunk + dwImageBase;
            DWORD dwINT = dwIAT;
            //获取导入名称表, INT
            if (pImpHdrTmp->OriginalFirstThunk != NULL) {

                dwINT = pImpHdrTmp->OriginalFirstThunk + dwImageBase;
            }

            //遍历导入名称表
            while (*(DWORD*)(dwINT) != 0) {

                if ((*(DWORD*)pImpHdrTmp) >> 31) {

                    //序号导入, 获取序号
                    dwNum = *(DWORD*)pImpHdrTmp;
                    dwNum = (dwNum << 16) >> 16;

                }
                else {

                    //名称导入
                    dwNum = *(DWORD*)pImpHdrTmp;
                    dwNum += dwImageBase;
                    dwNum += 2;

                }

                //获取函数地址后，先不要把地址直接写入IAT
                //而是先将.imp节地址写入IAT(每16个字节写一次)
                //在.imp节里写代码指令push 函数地址 retn
                //如果函数名是_acmdln，那么这里就不要混淆导入表
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
                    *(DWORD*)(dwMyAddr + 1) = dwFuncAddr;  //真实函数地址
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

        //定位重定位表
        pReloc = (IMAGE_BASE_RELOCATION*)(pNTHdr->OptionalHeader.DataDirectory[5].VirtualAddress + dwImageBase);
        dwOfReloc = pNTHdr->OptionalHeader.DataDirectory[5].Size;


        int nSize = 0;

        while (nSize < dwOfReloc) {

            //数组首地址
            int nOff = (DWORD)pReloc + 8;

            //数组元素个数
            int nCnt = (pReloc->SizeOfBlock - 8) >> 1;

            //遍历数组
            int j = 0;
            while (j < nCnt) {

                //取出一项
                int nDataOff = *(WORD*)(nOff + j * 2);

                //判断是否是有效重定位项
                if (nDataOff & 0x00003000) {

                    //修正
                    nDataOff = nDataOff & 0x0fff;  //页偏移
                    nDataOff = nDataOff + pReloc->VirtualAddress;
                    nDataOff = nDataOff + dwImageBase;

                    *(int*)nDataOff = *(int*)nDataOff + dwOff;
                }

                j++;
            }

            //处理下一个分页
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

    //解析dos头
    pDosHdr = (IMAGE_DOS_HEADER*)hMod;

    //nt头
    pNTHdr = (IMAGE_NT_HEADERS*)(pDosHdr->e_lfanew + (DWORD)hMod);

    //获取导入表
    pExpDir = (IMAGE_EXPORT_DIRECTORY*)(pNTHdr->OptionalHeader.DataDirectory[0].VirtualAddress + (DWORD)hMod);

    //导入函数地址表
    pAddrTbl = (DWORD)(pExpDir->AddressOfFunctions + (DWORD)hMod);

    //导入函数名称表
    pNameTbl = (DWORD)(pExpDir->AddressOfNames + (DWORD)hMod);

    //导入序号表
    pOrdTbl = (DWORD)(pExpDir->AddressOfNameOrdinals + (DWORD)hMod);

    //判断是序号还是名称
    if ((int)lpProcName & 0xffff0000) {

        //名称
        int i = 0;
        while (i < pExpDir->NumberOfNames) {

            //获取名称地址
            int nNameOff = (int)(*(DWORD*)(pNameTbl + i * 4) + (DWORD)hMod);

            //字符串比较
            if (((char*)nNameOff)[0] == 'G'&& ((char*)nNameOff)[1] == 'e'&& ((char*)nNameOff)[2] == 't'&&
                ((char*)nNameOff)[3] == 'P'&& ((char*)nNameOff)[4] == 'r'&& ((char*)nNameOff)[5] == 'o'&&
                ((char*)nNameOff)[6] == 'c'&& ((char*)nNameOff)[7] == 'A'&& ((char*)nNameOff)[8] == 'd'&&
                ((char*)nNameOff)[9] == 'd'&& ((char*)nNameOff)[10] == 'r'&& ((char*)nNameOff)[11] == 'e'&&
                ((char*)nNameOff)[12] == 's'&& ((char*)nNameOff)[13] == 's') {

                //找到了, 从导出序号表取出函数地址下标
                int nOrdinal = *(WORD*)(pOrdTbl + i * 2);

                //从导入地址表，下标寻址，获取导出函数地址
                int nFuncAddr = *(DWORD*)(pAddrTbl + nOrdinal * 4);

                

                //不是转发
                nFuncAddr += (int)hMod;


               

                //返回地址
                if (nFuncAddr != NULL) {

                    return (FARPROC)nFuncAddr;
                }
            }

            i++;

        }
    }

    else {

        //序号
        int nOrdinal = (DWORD)lpProcName - pExpDir->Base;

        //从导入地址表，下标寻址，获取导出函数地址
        int nFuncAddr = *(DWORD*)(pAddrTbl + nOrdinal * 4);

        //返回地址
        if (nFuncAddr != NULL) {

            return (FARPROC)(nFuncAddr + (DWORD)hMod);
        }

    }


    return 0;
}



void Entry() {

	Environment env;
	InitEnvironment(&env);

	//此时PE被加载进了内存中，从模块基址起始，计算压缩数据节位置
	LPBYTE pImgBase = (LPBYTE)GetModuleBase();
	auto pDosHdr = (PIMAGE_DOS_HEADER)pImgBase;
	auto pNtHdr = (PIMAGE_NT_HEADERS)(pImgBase + pDosHdr->e_lfanew);
	auto pSecHdr = (PIMAGE_SECTION_HEADER)
		((LPBYTE)&pNtHdr->OptionalHeader + pNtHdr->FileHeader.SizeOfOptionalHeader);

	LPBYTE pComData = pImgBase + pSecHdr[1].VirtualAddress;

	DWORD dwComSize = pSecHdr[1].PointerToRelocations;
	DWORD dwDeComSize = pSecHdr[1].PointerToLinenumbers;

	//解压缩

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

	//得到解压缩后的数据，将其拷贝到当前ImageBase处，相当于覆盖了PE头和空节部分
    //还原节表、导入表、重定位表，表数据放在了第4个节里
    LPBYTE pTableBuf = pSecHdr[3].VirtualAddress + pImgBase;
    LPBYTE pMyImpBuf = pSecHdr[4].VirtualAddress + pImgBase;
	DWORD dwOep = MyLoadLibrary(pPEBuff, &env, pTableBuf, pMyImpBuf);

    


	__asm jmp dwOep;

}

void InitEnvironment(Environment* pEnv) {

    //获取kernel32基址
    HMODULE hKer = GetKernel32();

    //从kernel32导出表中获取LoadLibrary和GetProcAddress地址
    char szGetProcAddress[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s', '\0' };
    pEnv->pfnGetProcAddress = (PFN_GetProcAddress)MyGetProcAddress(hKer, szGetProcAddress);

    char szLoadLibrary[] = { 'L', 'o','a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };
    pEnv->pfnLoadLibraryA = (PFN_LoadLibraryA)pEnv->pfnGetProcAddress(hKer, szLoadLibrary);

    //有了LoadLibrary和GetProcAddress，就可以使用任意函数了
    //获取解压缩相关函数

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

