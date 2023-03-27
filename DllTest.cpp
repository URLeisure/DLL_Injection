#include <windows.h>
#include <iostream>
#include <Tlhelp32.h>
#include <stdio.h>
#include <tchar.h>
using namespace std;

/// <summary>
/// ���ݽ������ƻ�ȡ������Ϣ
/// </summary>
/// <param name="info"></param>
/// <param name="processName"></param>
/// <returns></returns>
BOOL getProcess32Info(PROCESSENTRY32* info, const TCHAR processName[])
{
    HANDLE handle; //����CreateToolhelp32Snapshotϵͳ���վ��
    handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);//���ϵͳ���վ��
    //PROCESSENTRY32 �ṹ�� dwSize ��Ա���ó� sizeof(PROCESSENTRY32)
    info->dwSize = sizeof(PROCESSENTRY32);
    //����һ�� Process32First �������ӿ����л�ȡ�����б�
    Process32First(handle, info);
    //�ظ����� Process32Next��ֱ���������� FALSE Ϊֹ
    
    while (Process32Next(handle, info) != FALSE)
    {
        if (wcscmp(processName, info->szExeFile) == 0)
        {
            return TRUE;
        }
    }
    return FALSE;
}

/// <summary>
/// ע��DLL�ļ�
/// </summary>
/// <param name="DllFullPath">DLL�ļ���ȫ·��</param>
/// <param name="dwRemoteProcessId">Ҫע��ĳ����PID</param>
/// <returns></returns>
int InjectDLL(const wchar_t* DllFullPath, const DWORD pid)
{
   
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);//Ȩ�� ���̳д˾�� Ҫ�򿪵�Ŀ��-----����ָ�����̵Ĵ򿪾��
    if (hProc == 0) return -1;

    // ����·�����ֽ���
    int pathSize = (wcslen(DllFullPath) + 1) * sizeof(wchar_t);
    cout << "pathSize" << pathSize << endl;
    //ָ�����̵������ַ�ռ��б����򿪱�һ�����򣨳�ʼ���ڴ棩
    //������ָ�� LPVOID
    //�����ڴ����ڵĽ��̾��
    // NULL�Զ�����
    //��������ڴ��С
    LPVOID buffer = VirtualAllocEx(hProc, 0, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (buffer == 0) return -2;

    //���Զ����dll�ļ�ע��Ŀ����̣����ж��Ƿ�д��ɹ�
    if (!WriteProcessMemory(hProc, buffer, DllFullPath, pathSize, NULL)) return -3;

    //����Kernel32.dll�е�LoadLibraryW�������Լ���DLL�ļ�
    LPVOID pFunc = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryW");

    //����һ������һ�����̵������ַ�ռ������е��߳�
    CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)pFunc, buffer, 0, 0);
}



int main()
{
    
    system("start %windir%\\system32\\notepad.exe");//��

    PROCESSENTRY32 info;//TIHelp32.h
    if (getProcess32Info(&info, L"notepad.exe"))
    {
        InjectDLL(L"E:\\Dll1.dll", info.th32ProcessID);//���dll����Ҫע���dll�ļ������"����"������ע��Ľ��̵�PID��
    }
    else {
        cout << "����ʧ��" << endl;
    }
    return 0;
}
