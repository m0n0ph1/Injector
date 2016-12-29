; Windows DLL Injector v1.1
; Copyright Amezoure, 2016. All rights reserved.
;
; This program is free software: you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public License
; along with this program. If not, see <http://www.gnu.org/licenses/>.

format PE GUI 4.0

include 'WIN32A.INC'

; +---------------------------------------------+
; | CODE SECTION				|
; +---------------------------------------------+

invoke	InitCommonControls
invoke	GetModuleHandle, 0
invoke	DialogBoxParam, eax, ID_MAIN, HWND_DESKTOP, DialogProc, 0
invoke	ExitProcess, 0

proc DialogProc uses ebx esi edi, hwndDlg, uMsg, wParam, lParam
	cmp	[uMsg], WM_INITDIALOG
	je	.initdialog
	cmp	[uMsg], WM_COMMAND
	je	.command
	cmp	[uMsg], WM_CLOSE
	je	.close
	xor	eax, eax
	jmp	.finish

.initdialog:
	stdcall FindProcess
	jmp	.processed

.command:
	mov	eax, [wParam]
	and	eax, 0FFFFh
	cmp	eax, ID_INJECT
	je	.inject
	jmp	.processed

.inject:
	stdcall InjectDLL

.close:
	invoke	EndDialog, [hwndDlg], 0

.processed:
	mov	eax, TRUE

.finish:
	ret
endp

proc FindProcess
	invoke	CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, 0
	inc	eax
	jz	.quit
	dec	eax
	mov	[hSnapshot], eax

	mov	[lppe.dwSize], sizeof.PROCESSENTRY32
	invoke	Process32First, [hSnapshot], lppe
	test	eax, eax
	jz	.quit

.search:
	invoke	lstrcmpi, lppe.szExeFile, szProcess
	test	eax, eax
	jnz	.next
	jmp	.find

.next:
	invoke	Process32Next, [hSnapshot], lppe
	test	eax, eax
	jnz	.search
	jmp	.quit

.find:
	invoke	OpenProcess, PROCESS_ALL_ACCESS, 0, [lppe.th32ProcessID]
	test	eax, eax
	jz	.quit
	mov	[hProcess], eax

.quit:
	invoke	CloseHandle, [hSnapshot]
	ret
endp

proc InjectDLL
local dwPathLength:DWORD, lpLoadLibAddress:DWORD, lpSpace:DWORD
	invoke	GetFullPathName, szLibrary, MAX_PATH, szLibPath, 0
	test	eax, eax
	jz	.quit
	mov	[dwPathLength], eax

	invoke	GetModuleHandle, szKernel32
	test	eax, eax
	jz	.quit

	invoke	GetProcAddress, eax, szLoadLibFunc
	test	eax, eax
	jz	.quit
	mov	[lpLoadLibAddress], eax

	invoke	VirtualAllocEx, [hProcess], 0, [dwPathLength], MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE
	test	eax, eax
	jz	.quit
	mov	[lpSpace], eax

	invoke	WriteProcessMemory, [hProcess], eax, szLibPath, [dwPathLength], 0
	test	eax, eax
	jz	.quit

	invoke	CreateRemoteThread, [hProcess], 0, 0, [lpLoadLibAddress], [lpSpace], 0, 0
	test	eax, eax
	jz	.quit

	invoke	WaitForSingleObject, eax, INFINITE
	test	eax, eax
	jnz	.quit
	invoke	Beep, 2EEh, 12Ch

.quit:
	invoke	CloseHandle, [hProcess]
	ret
endp

; +---------------------------------------------+
; | OPTIONS AND EQUATIONS			|
; +---------------------------------------------+

ID_MAIN = 29Ah
ID_INJECT = 3E7h

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

dwProcessID dd ?
hProcess dd ?
hSnapshot dd ?
lppe PROCESSENTRY32
szKernel32 db 'KERNEL32.DLL', 0
szLibPath rb MAX_PATH
szLibrary db 'SomeLibrary.dll', 0
szLoadLibFunc db 'LoadLibraryA', 0
szProcess db 'SomeProcess.exe', 0

; +---------------------------------------------+
; | DATA SECTION				|
; +---------------------------------------------+

data import
	library kernel32, 'KERNEL32.DLL',\
		user32, 'USER32.DLL',\
		comctl32, 'COMCTL32.DLL'

	import	kernel32, Beep, 'Beep',\
		CloseHandle, 'CloseHandle',\
		CreateRemoteThread, 'CreateRemoteThread',\
		CreateToolhelp32Snapshot, 'CreateToolhelp32Snapshot',\
		ExitProcess, 'ExitProcess',\
		GetFullPathName, 'GetFullPathNameA',\
		GetModuleHandle, 'GetModuleHandleA',\
		GetProcAddress, 'GetProcAddress',\
		OpenProcess, 'OpenProcess',\
		Process32First, 'Process32First',\
		Process32Next, 'Process32Next',\
		VirtualAllocEx, 'VirtualAllocEx',\
		WaitForSingleObject, 'WaitForSingleObject',\
		WriteProcessMemory, 'WriteProcessMemory',\
		lstrcmpi, 'lstrcmpiA'

	import	user32, DialogBoxParam, 'DialogBoxParamA',\
		EndDialog, 'EndDialog'

	import	comctl32, InitCommonControls, 'InitCommonControls'
end data

data resource
	directory RT_DIALOG, dialogs, RT_MANIFEST, manifests

	resource dialogs, ID_MAIN, LANG_ENGLISH or SUBLANG_DEFAULT, main_dialog
	resource manifests, 1, LANG_ENGLISH or SUBLANG_DEFAULT, manifest

	dialog main_dialog, 'DLL Injector', 0, 0, 150, 50, WS_CAPTION or WS_VISIBLE or WS_SYSMENU or DS_CENTER
		dialogitem 'BUTTON', 'Inject', ID_INJECT, 30, 15, 90, 20, WS_VISIBLE
	enddialog

	resdata manifest
		db '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>', 13, 10
		db '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">', 13, 10
		db '<assemblyIdentity version="1.0.0.0" processorArchitecture="x86" name="Injector.exe" type="win32"/>', 13, 10
		db '<description>DLL Injector</description>', 13, 10
		db '<dependency>', 13, 10
		db '<dependentAssembly>', 13, 10
		db '<assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="x86" publicKeyToken="6595b64144ccf1df" language="*"/>', 13, 10
		db '</dependentAssembly>', 13, 10
		db '</dependency>', 13, 10
		db '</assembly>', 13, 10
	endres
end data
