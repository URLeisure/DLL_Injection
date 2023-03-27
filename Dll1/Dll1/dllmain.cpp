// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "stdlib.h"
#include <iostream>

using namespace std;

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)

{
	switch (ul_reason_for_call) {

	case DLL_PROCESS_ATTACH: {
		// 当DLL被进程 <<第一次>> 调用时，导致DllMain函数被调用，
		HWND hwnd = GetActiveWindow();
		MessageBox(hwnd, L"DLL已进入目标进程。", L"信息", MB_ICONINFORMATION); //弹出一个模态对话框
	}
	}
	return TRUE;
}
