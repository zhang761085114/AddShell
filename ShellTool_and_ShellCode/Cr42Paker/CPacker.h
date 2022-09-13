#pragma once
class CPacker
{
public:
	bool Pack(CString strSrc, CString strDst);

	//保存节表、导入表、重定位表
private:
	IMAGE_SECTION_HEADER m_pSaveSecHdr[10];		//节表
	int nSecNum;								//节表个数

	DWORD m_pImportAddr;						//导入表RVA
	int nImpSize;								//导入表大小

	DWORD m_pRelocAddr;						//重定位表RVA
	int nRelocSize;								//重定位表大小

private:
	DWORD GetAlign(DWORD dwValue, DWORD dwAlign);

private:
	HANDLE m_hFile;
	HANDLE m_hFileMap;
	LPBYTE m_pSrcPe;
	DWORD m_dwSrcPeSize;
	PIMAGE_DOS_HEADER m_pDosHdr;
	PIMAGE_NT_HEADERS m_pNtHdr;
	PIMAGE_SECTION_HEADER m_pSecHdr;
	bool AnalyzePe(CString strSrc);

private:
	LPBYTE m_pComData;//压缩后的数据缓冲区
	DWORD m_dwComSize;//压缩后的数据的大小
	bool GetCompressData();

private:
	LPBYTE m_pCode; //壳代码(解压缩代码)
	DWORD m_dwCodeSize;//代码大小
	bool GetCode();

private:
	LPBYTE m_pTable; //表数据
	DWORD m_dwTableSize;//表数据大小
	bool GetTable();

private:
	LPBYTE m_pComSec; //数据节
	DWORD m_dwComSecSize; //数据节大小
	void GetComSec();

private:
	LPBYTE m_pCodeSec; //代码节
	DWORD m_dwCodeSecSize; //代码节大小
	void GetCodeSec();

private:
	LPBYTE m_pTableSec; //存放表的节
	DWORD m_dwTableSecSize; //代码节大小
	void GetTableSec();

private:
	IMAGE_SECTION_HEADER m_newSecHdr[5];
	void GetNewSectionHeaders();

private:
	LPBYTE m_pNewPeHdr;
	DWORD m_dwNewPeHdrSize;
	void GetNewPeHdr();

private:
	bool WriteNewPe(CString	strNewPe);
};

