; Windows DLL Injector v1.0
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

format PE GUI

include 'WIN32A.INC'

; +---------------------------------------------+
; | CODE SECTION				|
; +---------------------------------------------+

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
jmp	.inject

.next:
invoke	Process32Next, [hSnapshot], lppe
test	eax, eax
jnz	.search
jmp	.quit

.inject:
invoke	OpenProcess, PROCESS_ALL_ACCESS, 0, [lppe.th32ProcessID]
test	eax, eax
jz	.quit
mov	[hProcess], eax

invoke	GetFullPathName, szLibrary, MAX_PATH, szLibPath, 0
test	eax, eax
jz	.quit
mov	[dwPathLength], eax

invoke	GetModuleHandle, szKernel32
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
invoke	Beep, 2EEh, 12Ch

.quit:
invoke	ExitProcess, 0

; +---------------------------------------------+
; | OPTIONS AND EQUATIONS			|
; +---------------------------------------------+

TH32CS_SNAPPROCESS = 2h

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

dwPathLength dd ?
hProcess dd ?
hSnapshot dd ?
lpLoadLibAddress dd ?
lpSpace dd ?
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
	library kernel32, 'KERNEL32.DLL'

	import	kernel32, Beep, 'Beep',\
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
		WriteProcessMemory, 'WriteProcessMemory',\
		lstrcmpi, 'lstrcmpiA'
end data