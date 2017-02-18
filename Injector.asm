; Windows DLL Injector v1.2
; Copyright Amezoure, 2017. All rights reserved.

format PE GUI 4.0
entry FindProcess

include 'WIN32A.INC'

; +---------------------------------------------+
; | MACROS SECTION                              |
; +---------------------------------------------+

macro pushd value {
    match pushd, pushd \{
        local ..continue

        if value eqtype ''
            call ..continue
            db value, 0

            ..continue:
        else
            push value
        end if

        pushd equ
    \}

    restore pushd
}

; +---------------------------------------------+
; | CODE SECTION                                |
; +---------------------------------------------+

proc FindProcess uses ebx
    invoke  CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, 0
    inc     eax
    jz      @f
    dec     eax
    mov     ebx, eax

    mov     [lppe.dwSize], sizeof.PROCESSENTRY32
    invoke  Process32First, ebx, lppe
    test    eax, eax
    jz      @f

.search:
    invoke  lstrcmpi, lppe.szExeFile, 'SomeProcess.exe'
    test    eax, eax
    jnz     .next
    jmp     .find

.next:
    invoke  Process32Next, ebx, lppe
    test    eax, eax
    jnz     .search
    jmp     @f

.find:
    invoke  OpenProcess, PROCESS_ALL_ACCESS, 0, [lppe.th32ProcessID]
    test    eax, eax
    jz      @f
    stdcall InjectLibrary, eax

@@:
    invoke  CloseHandle, ebx
    ret
endp

proc InjectLibrary uses ebx esi edi, hProcess:DWORD
    invoke  GetFullPathName, 'SomeLibrary.dll', MAX_PATH, szLibraryPath, 0
    test    eax, eax
    jz      @f
    mov     ebx, eax

    invoke  GetModuleHandle, 'KERNEL32.DLL'
    test    eax, eax
    jz      @f

    invoke  GetProcAddress, eax, 'LoadLibraryA'
    test    eax, eax
    jz      @f
    mov     esi, eax

    invoke  VirtualAllocEx, [hProcess], 0, ebx, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE
    test    eax, eax
    jz      @f
    mov     edi, eax

    invoke  WriteProcessMemory, [hProcess], eax, szLibraryPath, ebx, 0
    test    eax, eax
    jz      @f

    invoke  CreateRemoteThread, [hProcess], 0, 0, esi, edi, 0, 0
    test    eax, eax
    jz      @f

    invoke  WaitForSingleObject, eax, INFINITE
    test    eax, eax
    jnz     @f
    invoke  Beep, 2EEh, 12Ch

@@:
    invoke  CloseHandle, [hProcess]
    ret
endp

; +---------------------------------------------+
; | OPTIONS AND EQUATIONS                       |
; +---------------------------------------------+

TH32CS_SNAPPROCESS = 2h
INFINITE = 0FFFFFFFFh

struct PROCESSENTRY32
    dwSize dd ?
    cntUsage dd ?
    th32ProcessID dd ?
    th32DefaultHeapID dd ?
    th32ModuleID dd ?
    cntThreads dd ?
    th32ParentProcessID dd ?
    pcPriClassBase dd ?
    dwFlags dd ?
    szExeFile rb MAX_PATH
ends

lppe PROCESSENTRY32
szLibraryPath rb MAX_PATH

; +---------------------------------------------+
; | DATA SECTION                                |
; +---------------------------------------------+

data import
    dd 0, 0, 0, RVA kernel_name, RVA kernel_table
    dd 0, 0, 0, 0, 0

    kernel_name db 'KERNEL32.DLL', 0

    kernel_table:
        Beep dd RVA _Beep
        CloseHandle dd RVA _CloseHandle
        CreateRemoteThread dd RVA _CreateRemoteThread
        CreateToolhelp32Snapshot dd RVA _CreateToolhelp32Snapshot
        GetFullPathName dd RVA _GetFullPathName
        GetModuleHandle dd RVA _GetModuleHandle
        GetProcAddress dd RVA _GetProcAddress
        OpenProcess dd RVA _OpenProcess
        Process32First dd RVA _Process32First
        Process32Next dd RVA _Process32Next
        VirtualAllocEx dd RVA _VirtualAllocEx
        WaitForSingleObject dd RVA _WaitForSingleObject
        WriteProcessMemory dd RVA _WriteProcessMemory
        lstrcmpi dd RVA _lstrcmpi
        dd 0

    _Beep dw 0
        db 'Beep', 0
    _CloseHandle dw 0
        db 'CloseHandle', 0
    _CreateRemoteThread dw 0
        db 'CreateRemoteThread', 0
    _CreateToolhelp32Snapshot dw 0
        db 'CreateToolhelp32Snapshot', 0
    _GetFullPathName dw 0
        db 'GetFullPathNameA', 0
    _GetModuleHandle dw 0
        db 'GetModuleHandleA', 0
    _GetProcAddress dw 0
        db 'GetProcAddress', 0
    _OpenProcess dw 0
        db 'OpenProcess', 0
    _Process32First dw 0
        db 'Process32First', 0
    _Process32Next dw 0
        db 'Process32Next', 0
    _VirtualAllocEx dw 0
        db 'VirtualAllocEx', 0
    _WaitForSingleObject dw 0
        db 'WaitForSingleObject', 0
    _WriteProcessMemory dw 0
        db 'WriteProcessMemory', 0
    _lstrcmpi dw 0
        db 'lstrcmpiA', 0
end data
