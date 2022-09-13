#pragma once
class CPacker
{
public:
	bool Pack(CString strSrc, CString strDst);

	//����ڱ�������ض�λ��
private:
	IMAGE_SECTION_HEADER m_pSaveSecHdr[10];		//�ڱ�
	int nSecNum;								//�ڱ����

	DWORD m_pImportAddr;						//�����RVA
	int nImpSize;								//������С

	DWORD m_pRelocAddr;						//�ض�λ��RVA
	int nRelocSize;								//�ض�λ���С

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
	LPBYTE m_pComData;//ѹ��������ݻ�����
	DWORD m_dwComSize;//ѹ��������ݵĴ�С
	bool GetCompressData();

private:
	LPBYTE m_pCode; //�Ǵ���(��ѹ������)
	DWORD m_dwCodeSize;//�����С
	bool GetCode();

private:
	LPBYTE m_pTable; //������
	DWORD m_dwTableSize;//�����ݴ�С
	bool GetTable();

private:
	LPBYTE m_pComSec; //���ݽ�
	DWORD m_dwComSecSize; //���ݽڴ�С
	void GetComSec();

private:
	LPBYTE m_pCodeSec; //�����
	DWORD m_dwCodeSecSize; //����ڴ�С
	void GetCodeSec();

private:
	LPBYTE m_pTableSec; //��ű�Ľ�
	DWORD m_dwTableSecSize; //����ڴ�С
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

