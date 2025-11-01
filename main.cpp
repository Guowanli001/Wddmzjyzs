#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
using namespace std;
/*
    0 = 黑色       8 = 灰色
    1 = 蓝色       9 = 淡蓝色
    2 = 绿色       A = 淡绿色
    3 = 浅绿色     B = 淡浅绿色
    4 = 红色       C = 淡红色
    5 = 紫色       D = 淡紫色
    6 = 黄色       E = 淡黄色
    7 = 白色       F = 亮白色
*/
enum Color {
    BLACK = 0,
    BLUE = 1,
    GREEN = 2,
    Q_GREEN = 3,
    RED = 4,
    MAGENTA = 5,
    YELLOW = 6,
    WHITE = 7,
    GRAY = 8,
    D_BLUE = 9,
    D_GREEN = 10,
    DQ_GREEN = 11,
    D_RED = 12,
    D_MAGENTA = 13,
    D_YELLOW = 14,
    L_WHITE = 15
};

// 设置控制台颜色
void setColor(Color foreground, Color background = BLACK) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), foreground + background * 16);
}
// 控制台窗口居中
void CenterConsoleWindow() {
    HWND hConsole = GetConsoleWindow();
    if (hConsole == NULL) return;
    
    // 获取屏幕尺寸
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    
    // 获取窗口尺寸
    RECT rect;
    GetWindowRect(hConsole, &rect);
    int windowWidth = rect.right - rect.left;
    int windowHeight = rect.bottom - rect.top;
    
    // 计算居中位置
    int x = (screenWidth - windowWidth) / 2;
    int y = (screenHeight - windowHeight) / 2;
    
    // 移动窗口到屏幕中心
    SetWindowPos(hConsole, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////
// 检查是否以管理员权限运行
bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(adminGroup);
    }
    
    return isAdmin == TRUE;
}

// 以管理员权限重新启动自身
bool RestartAsAdmin(const wchar_t* parameters = L"") {
    wchar_t modulePath[MAX_PATH];
    GetModuleFileNameW(NULL, modulePath, MAX_PATH);
    
    SHELLEXECUTEINFOW shellInfo;
    shellInfo.cbSize = sizeof(SHELLEXECUTEINFOW);
    shellInfo.lpVerb = L"runas";
    shellInfo.lpFile = modulePath;
    shellInfo.lpParameters = parameters;
    shellInfo.nShow = SW_SHOWNORMAL;
    shellInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shellInfo.hwnd = NULL;
    shellInfo.lpDirectory = NULL;
    shellInfo.hInstApp = NULL;
    shellInfo.lpIDList = NULL;
    shellInfo.lpClass = NULL;
    shellInfo.hkeyClass = NULL;
    shellInfo.dwHotKey = 0;
    shellInfo.hIcon = NULL;
    shellInfo.hProcess = NULL;
    
    if (ShellExecuteExW(&shellInfo)) {
        if (shellInfo.hProcess) {
            CloseHandle(shellInfo.hProcess);
        }
        return true;
    } else {
        DWORD error = GetLastError();
        if (error == ERROR_CANCELLED) {
            cout << "用户拒绝了UAC提权请求" << endl;
        }
        return false;
    }
}

// 自动提权函数 - 主函数
bool EnsureAdminPrivileges(bool autoRestart = true) {
    if (IsRunningAsAdmin()) {
    	setColor(RED);
        cout << "当前已以管理员权限运行" << endl;
        return true;
    }
    
    cout << "需要管理员权限..." << endl;
    
    if (!autoRestart) {
        cout << "自动重启已禁用，请手动以管理员权限运行程序" << endl;
        return false;
    }
    
    cout << "正在请求管理员权限..." << endl;
    if (RestartAsAdmin()) {
        cout << "提权成功，程序将重新启动" << endl;
        exit(0); // 退出当前非管理员进程
    } else {
        cout << "提权失败，请手动以管理员权限运行程序" << endl;
        return false;
    }
}

// 带参数重启的提权函数
bool EnsureAdminPrivilegesWithParams(const wchar_t* parameters) {
    if (IsRunningAsAdmin()) {
        return true;
    }
    
    cout << "需要管理员权限，正在重启..." << endl;
    if (RestartAsAdmin(parameters)) {
        cout << "程序将以管理员权限重新启动" << endl;
        exit(0);
    }
    return false;
}

// 静默提权（不显示提示信息）
bool EnsureAdminPrivilegesSilent() {
    if (IsRunningAsAdmin()) {
        return true;
    }
    
    return RestartAsAdmin();
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////
class BrutalProcessKiller {
public:
    // 最强暴力结束 - 多管齐下
    static bool KillProcessBrutally(DWORD pid) {
        bool success = false;
        
        // 方法1: 直接终止进程
        success = TerminateProcessForce(pid);
        
        // 方法2: 如果失败，使用远程线程注入
        if (!success) {
            success = RemoteExitProcess(pid);
        }
        
        // 方法3: 如果还失败，终止所有线程
        if (!success) {
            success = TerminateAllThreads(pid);
        }
        
        // 方法4: 最后尝试挂起所有线程后终止
        if (!success) {
            success = SuspendAndKill(pid);
        }
        
        return success;
    }
    
    // 暴力按进程名结束
    static bool KillProcessByNameBrutally(const char* processName) {
        DWORD pid = FindProcessID(processName);
        if (pid == 0) return false;
		setColor(RED);
        std::cout << "暴力结束进程: " << processName << " (PID: " << pid << ")" << std::endl;
        setColor(WHITE);
        return KillProcessBrutally(pid);
    }

private:
    // 方法1: 强制终止进程
    static bool TerminateProcessForce(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess == NULL) {
            // 尝试提升权限
            EnableDebugPrivilege();
            hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            if (hProcess == NULL) return false;
        }
        
        BOOL result = TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
        return result != FALSE;
    }
    
    // 方法2: 远程线程注入强制退出 - 修复版本
    static bool RemoteExitProcess(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | 
                                     PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, 
                                     FALSE, pid);
        if (!hProcess) return false;
        
        // 获取kernel32.dll模块在目标进程中的地址
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        
        // 首先在远程进程中加载kernel32.dll
        DWORD dwSize = strlen("kernel32.dll") + 1;
        LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
        if (!pDllPath) {
            CloseHandle(hProcess);
            return false;
        }
        
        WriteProcessMemory(hProcess, pDllPath, "kernel32.dll", dwSize, NULL);
        
        // 获取LoadLibraryA地址
        FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
        
        // 在远程进程中加载kernel32.dll
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                           (LPTHREAD_START_ROUTINE)pLoadLibrary, 
                                           pDllPath, 0, NULL);
        if (!hThread) {
            VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        
        WaitForSingleObject(hThread, INFINITE);
        
        // 获取ExitProcess地址
        FARPROC pExitProcess = GetProcAddress(hKernel32, "ExitProcess");
        
        // 创建远程线程调用ExitProcess
        HANDLE hThread2 = CreateRemoteThread(hProcess, NULL, 0, 
                                            (LPTHREAD_START_ROUTINE)pExitProcess, 
                                            (LPVOID)0, 0, NULL);
        
        if (hThread2) {
            WaitForSingleObject(hThread2, 5000);
            CloseHandle(hThread2);
        }
        
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        
        return true;
    }
    
    // 方法3: 终止进程的所有线程
    static bool TerminateAllThreads(DWORD pid) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        
        bool found = false;
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, te.th32ThreadID);
                    if (hThread != NULL) {
                        TerminateThread(hThread, 0);
                        CloseHandle(hThread);
                        found = true;
                    }
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        
        CloseHandle(hSnapshot);
        return found;
    }
    
    // 方法4: 挂起所有线程后终止 - 修复版本
    static bool SuspendAndKill(DWORD pid) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        
        // 先挂起所有线程
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                    if (hThread != NULL) {
                        // 使用SuspendThread函数挂起线程
                        SuspendThread(hThread);
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        
        CloseHandle(hSnapshot);
        
        // 等待一会确保线程都被挂起
        Sleep(100);
        
        // 然后终止进程
        return TerminateProcessForce(pid);
    }
    
    // 提升调试权限
    static bool EnableDebugPrivilege() {
        HANDLE hToken;
        TOKEN_PRIVILEGES tp;
        
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            return false;
        }
        
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        
        BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        CloseHandle(hToken);
        
        return result != FALSE;
    }
    
    // 查找进程ID
    static DWORD FindProcessID(const char* processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
        
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        
        if (!Process32First(hSnapshot, &pe)) {
            CloseHandle(hSnapshot);
            return 0;
        }
        
        do {
            if (_stricmp(pe.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe));
        
        CloseHandle(hSnapshot);
        return 0;
    }
};

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//杀极域
void kill() {
	setColor(GRAY);
    for (int i = 0; i <= 10; i++) {
        BrutalProcessKiller::KillProcessByNameBrutally("StudentMain.exe");
    }
}
using namespace std;
string processName;
string command;

// 查找任务管理器窗口并置顶
void SetTaskManagerTopMost() {
    // 查找任务管理器窗口
    HWND taskmgrWindow = FindWindow("TaskManagerWindow", NULL);
    if (taskmgrWindow == NULL) {
        // 如果上面的类名找不到，尝试其他可能的类名
        taskmgrWindow = FindWindow("#32770", "Windows 任务管理器");
        if (taskmgrWindow == NULL) {
            taskmgrWindow = FindWindow(NULL, "任务管理器");
            if (taskmgrWindow == NULL) {
                taskmgrWindow = FindWindow(NULL, "Windows Task Manager");
            }
        }
    }
    
    // 如果找到窗口就置顶
    if (taskmgrWindow != NULL && IsWindowVisible(taskmgrWindow)) {
        SetWindowPos(taskmgrWindow, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    }
}

// 持续置顶控制台窗口
DWORD WINAPI zd(LPVOID lpParam) {
    for (;;) {
        HWND hWnd = GetConsoleWindow();
        SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        if (GetAsyncKeyState(VK_ESCAPE) & 0x8000) {
        	if (GetAsyncKeyState(VK_CONTROL) & 0x11) {
					cout << "用户按ESC+Ctrl退出程序" << endl;
					exit(0);
				}
		}
		if (GetAsyncKeyState('C') & 0x8000) {
			setColor(RED);
		    cout << "检测到C键被按下," <<"杀死域电子教室." <<endl;
		    kill();
		    setColor(WHITE);
		}
		        
		// 检测B键
		if (GetAsyncKeyState('B') & 0x8000) {
			setColor(RED);
			cout << "检测到B键被按下," <<"杀死域控制软件."<< endl;
			for(int i=0;i<10;i++){
				BrutalProcessKiller::KillProcessByNameBrutally("jfglzsp.exe");
				BrutalProcessKiller::KillProcessByNameBrutally("mpkpr.exe");
			}
			setColor(WHITE);
		}
    }
    return 0;
}

void zdd() {
    HWND hWnd = GetConsoleWindow();
    SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
}

// 循环启动任务管理器并置顶
/*void task() {
    setColor(GRAY);
    for (int i = 0; i > -1; i++) {
        zdd();
        setColor(RED);
        cout << "我的代码在极域之上！";
        setColor(GRAY);
        cout << "start taskmgr.exe" << ">>" << i << endl;
        system("taskmgr.exe");
        // 启动后立即开始循环置顶任务管理器
            SetTaskManagerTopMost();
    }
}
*/


// 全局变量用于控制线程
bool g_bRunning = true;
HANDLE g_hTaskManagerThreads[2] = {NULL, NULL}; // 存储两个监控线程的句柄

// 强制显示并置顶任务管理器窗口
void ForceShowTaskManager() {
    HWND taskmgrWindow = FindWindow("TaskManagerWindow", NULL);
    if (taskmgrWindow == NULL) {
        taskmgrWindow = FindWindow("#32770", "Windows 任务管理器");
        if (taskmgrWindow == NULL) {
            taskmgrWindow = FindWindow(NULL, "任务管理器");
            if (taskmgrWindow == NULL) {
                taskmgrWindow = FindWindow(NULL, "Windows Task Manager");
            }
        }
    }
    
    if (taskmgrWindow != NULL) {
        // 强制显示窗口（如果最小化则恢复）
        if (IsIconic(taskmgrWindow)) {
            ShowWindow(taskmgrWindow, SW_RESTORE);
        }
        
        // 确保窗口可见
        ShowWindow(taskmgrWindow, SW_SHOW);
        SetWindowPos(taskmgrWindow, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        
        // 强制窗口到前台
        SetForegroundWindow(taskmgrWindow);
    }
}

// 检查任务管理器是否在运行
bool IsTaskManagerRunning() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(hSnapshot, &pe)) {
        CloseHandle(hSnapshot);
        return false;
    }
    
    bool found = false;
    do {
        if (_stricmp(pe.szExeFile, "Taskmgr.exe") == 0) {
            found = true;
            break;
        }
    } while (Process32Next(hSnapshot, &pe));
    
    CloseHandle(hSnapshot);
    return found;
}

// 专门置顶任务管理器的线程 - 增强版
DWORD WINAPI TaskManagerTopMostThread(LPVOID lpParam) {
    while (g_bRunning) {
        SetTaskManagerTopMost();//ZDD
        ForceShowTaskManager();//MIN WINDOW
    }
    setColor(YELLOW);
    cout << "任务管理器置顶线程已结束" << endl;
    setColor(WHITE);
    return 0;
}

// 监控并重启任务管理器的线程
DWORD WINAPI TaskManagerMonitorThread(LPVOID lpParam) {
    while (g_bRunning) {
        if (!IsTaskManagerRunning()) {
            // 任务管理器被关闭，重新启动
            system("taskmgr.exe");
            Sleep(1000); // 等待任务管理器启动
        }
        Sleep(500); // 检查间隔
    }
    setColor(YELLOW);
    cout << endl;
    cout << "任务管理器监控线程已结束" << endl;
    setColor(WHITE);
    return 0;
}

// 等待所有任务管理器相关线程结束
void WaitForTaskManagerThreads() {
    setColor(YELLOW);
    cout << "正在结束任务管理器相关线程..." << endl;
    setColor(WHITE);
    
    // 设置运行标志为false，让线程自然退出
    g_bRunning = false;
    
    // 等待线程结束
    for (int i = 0; i < 2; i++) {
        if (g_hTaskManagerThreads[i] != NULL) {
            WaitForSingleObject(g_hTaskManagerThreads[i], 3000); // 等待3秒
            CloseHandle(g_hTaskManagerThreads[i]);
            g_hTaskManagerThreads[i] = NULL;
        }
    }
    
    setColor(GREEN);
    cout << "所有任务管理器线程已结束" << endl;
    setColor(WHITE);
}

// 杀死所有任务管理器进程
void KillAllTaskManager() {
    BrutalProcessKiller::KillProcessByNameBrutally("Taskmgr.exe");
    Sleep(500);
    BrutalProcessKiller::KillProcessByNameBrutally("Taskmgr.exe"); // 确保杀死
}

void task() {
    setColor(GRAY);
    
    // 重置运行标志
    g_bRunning = true;
    
    //启动！！！
    setColor(D_YELLOW);
	cout<<"循环任务管理器已启动，按下Alt关闭！"<<endl;
	setColor(GRAY);
    Sleep(1000); // 等待启动
    // 启动任务管理器监控线程
	g_hTaskManagerThreads[0] = CreateThread(NULL, 0, TaskManagerMonitorThread, NULL, 0, NULL);
	g_hTaskManagerThreads[1] = CreateThread(NULL, 0, TaskManagerTopMostThread, NULL, 0, NULL);
    
    int i = 0;
    while (true) {
        // 检测是否按下 ALT 键
        if (GetAsyncKeyState(VK_MENU) & 0x8000) {
            setColor(YELLOW);
            cout << "检测到 ALT 键，结束任务管理器循环" << endl;
            setColor(WHITE);
            
            // 结束所有相关线程
            WaitForTaskManagerThreads();
            
            // 杀死所有任务管理器进程
            KillAllTaskManager();
            
            return;
        }

        zdd();
        setColor(RED);
        cout << "我的代码在极域之上！";
        setColor(GRAY);
        cout << "监控任务管理器状态" << ">>" << i++ << endl;
        
        // 持续强制显示任务管理器
        ForceShowTaskManager();
        
        Sleep(100); // 减少CPU占用
    }
}

// 在mai函数中确保线程被正确清理
int mai() {
    int x;
    //CD
    setColor(D_BLUE);
	cout<<"------------------------帮助列表------------------------"<<endl;
	cout<<"        TaskMgr   循环启动任务管理器(输入0)"<<endl<<"        Kill      杀死极域电子教室(输入1)"<<endl<<"        TaskList  进程列表(输入2)"<<endl<<"        TaskKillX 杀死某进程(输入3)"<<endl<<"        Help      帮助列表(输入4)"<<endl<<endl<<"        按下C键结束极域电子教室"<<endl<<"        按下B建结束控制软件"<<endl<<"        任务管理器按ALT键退出"<<endl<<"        按下ESC+Ctrl关闭程序"<<endl;
	cout<<"--------------------------------------------------------"<<endl<<endl;
	//
    setColor(D_YELLOW);
    cout << "0=TaskMgr" << "   1=Kill" << "    2=TaskList" << "   3=TaskKillX" <<"   4=Help"<<endl;
    setColor(GREEN);
    cout<<endl;
    cout<<"(0-4)>>";cin >> x;
    
    switch (x) {
        case 0:
        	setColor(GRAY);
        	cout<<"0:启动任务管理器"<<endl<<endl;
            // 确保之前的线程已经结束
            if (!g_bRunning) {
                g_bRunning = true;
            }
            // 启动任务管理器功能
            task();
            break;
            
        case 1:
        	setColor(GRAY);
			cout<<"1:一键杀控"<<endl<<endl;
            kill();
            break;
            
        case 2:
        	setColor(GRAY);
			cout<<"2:进程列表"<<endl<<endl;
			setColor(D_RED);
            system("tasklist");
            break;
            
        case 3:
        	setColor(GRAY);
			cout<<"3:强制结束进程"<<endl<<endl;
			setColor(GREEN);
            cout<<"Task>>";
            cin>>processName;
            command = processName;
            BrutalProcessKiller::KillProcessByNameBrutally(command.c_str());
            break;
            
        case 4:
        	setColor(GRAY);
			cout<<"4:查看帮助"<<endl<<endl;
            mai();
            return 0;
            break;
            
        default:
            cout<<"无效指令，输入4查看指令帮助！"<<endl<<endl;
            mai();
            return 0;
            break;
    }
    return 0;
}

int main() {
	system("title Wddmzjyzs  -By G255  Web:https://g255x.github.io");
	//提权
	if (!EnsureAdminPrivileges()) {
		setColor(RED);
		cout<<"请以管理员启动！"<<endl;
	    system("pause");
	    return 1;
	}
	//居中窗口
	CenterConsoleWindow();
    // 使用Windows API创建线程
    CreateThread(NULL, 0, zd, NULL, 0, NULL);
    for (;;) {
    	cout<<endl;
    	setColor(WHITE);
    	cout<<"ヾ(≧▽≦*)oφ(*￣0￣)q(≧▽≦q)ψ(｀?′)ψ（￣︶￣）↗"<<endl<<endl;
    	setColor(YELLOW);
    	cout<<"              Wddmzjyzs   -By G255  "<<endl;
    	setColor(Q_GREEN);
    	cout<<"          Web:https://g255x.github.io";
    	setColor(WHITE);
    	cout<<endl<<"--------------------------------------------------------"<<endl<<endl;
        mai();
        setColor(GREEN);
		cout<<endl<<endl<<"操作成功完成！"<<"  ";
		setColor(WHITE);
        system("pause");
        system("cls");
    }
} 
