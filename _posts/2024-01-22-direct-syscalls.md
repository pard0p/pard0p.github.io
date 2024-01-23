---
title: Mi implementación de Hell's Gate
date: 2024-01-22 20:18:00 +0800
categories: [Malware, Evasion]
tags: [POC]
---

<style>
    h1 {
        font-size: 50px;
    }

    h2 {
        font-weight:700;
        font-size: 35px;
        color: #DDA0DD;
    }

    h3 {
        font-weight:700;
        font-size: 25px;
        color: #DDA0DD;
    }

    h4 {
        font-weight:400;
        font-size: 25px;
        color: #DDA0DD;
    }

    .content {
        font-size: 22px;
        text-align: justify;
    }
</style>

## Syscalls Directas

Uno de los métodos principales para evitar los hooks en la ntdll.dll es el uso de instrucciones Syscall directamente en el código de nuestros programas.

Si conocemos el número de la Syscall y la forma de realizar la llamada, es posible generar una rutina en ensamblador similar a la existente en la ntdll.dll que ejecute la llamada al sistema que nosotros queramos.

Por ejemplo, la función NtAllocateVirtualMemoryEx de la ntdll.dll ejecuta la Syscall con el número **0x76**.

![img-description](/assets/img/direct-syscalls/img1.png)

Por lo tanto, en nuestro código deberíamos de ser capaces de ejecutar esta función sin pasar por la ntdll.dll si seguimos la misma estructura y creamos y compilamos un ejecutable con la siguiente rutina en asm:

```c++
global My_NtAllocateVirtualMemoryEx

My_NtAllocateVirtualMemoryEx:
	mov r10, rcx
	mov eax, 0x76
	syscall
	ret
```

### <u>Problemas</u>

El problema principal es que resulta **sencillo detectar** las instrucciones Syscall mediante técnicas de análisis de código, ya que bajo ningún concepto una instrucción de este tipo debe encontrarse fuera del espacio de código comprendido entre las librerías del sistema.

De esta manera, siempre y cuando un proceso en el que sus Syscalls provengan de modulos sin verificar o regiones de memoria en las que no debería existir este tipo instrucción haría saltar las alarmas.

Si a pesar de esto queremos implementar este método, nos encontraríamos frente a otra problematica. El **número de la Syscall varía** dependiendo de la versión de Windows. No obstante, esto puede solventarse mediante Hell's Gate o técnicas similares.

## Hell's Gate

![img-description](/assets/img/direct-syscalls/img2.gif)

Tal y como puede apreciarse en el paper de Hell's Gate, se trata de una técnica diseñada específicamente para ejecutar **Syscalls de forma directa obteniendo el SSN de forma dinámica** y sin llamar excesivamente la atención.

Su funcionamiento podría resumirse en los siguientes pasos:
1. Sacar la **dirección base de la NTDLL** en memoria.
2. Encontrar la **tabla de export de la NTDLL** en memoria.
3. Encontrar la **dirección de la función** correspondiente.
4. Extraer el **SSN**.
5. Ejecución de la **Syscall**.

### <u>Mi implementación</u>

Quizás no se trata de una implementación extremadamente óptima, sin embargo considero que he captado el concepto y lo he simplificado en la medida de lo posible.

#### 1. Sacar la dirección base de la NTDLL en memoria

Para comprender esta parte es necesario entender en una cierta profundidad qué es el PBE.

El PBE o Process Enviroment Block es el una estructura de datos que aporta información sobre el proceso en ejecución. Cada proceso cuenta con su propio PEB y su finalidad es la de poder acceder a ciertos datos sobre él, como por ejemplo:
- El contexto del proceso.
- La dirección base de la imagen.
- LDR.
- Parámetros del proceso.
- Si el proceso está protegico con el PPL.
- etc.

La obtencion del PBE se puede realizar mediante la función **__readgsqword** en 64 bits y **__readfsdword** en 32 bits.

```c++
#include "peb.h"

int main() {
	#if defined(_WIN64)
		PPEB Peb = (PPEB)__readgsqword(0x60);
		return ERROR_SUCCESS;
	#else
		PPEB Peb = (PPEB)__readfsdword(0x30);
		return ERROR_SUCCESS;
	#endif
}
```

Uno de los parámetros que componen el PBE, el cual tiene una gran importancia en este punto, es el **LDR**. El LDR es una estructura la cual contiene **información sobre los módulos cargados en el proceso**. Gracias a esto, es posible listar las DLLs cargadas en la memoria de un proceso y obtener la dirección base de la NTDLL.

```c++
#include "peb.h"
#include <Windows.h>
#include <cstdio>

HMODULE GetNtdllHandle() {
    #if defined(_WIN64)
        PPEB Peb = (PPEB)__readgsqword(0x60);
    #else
        PPEB Peb = (PPEB)__readfsdword(0x30);
    #endif

    PLDR_MODULE pLoadModule;
    pLoadModule = (PLDR_MODULE)((PBYTE)Peb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 16);

    return (HMODULE)pLoadModule->BaseAddress;
}
```

> El primer Flink apunta al propio exe y el segundo a la ntdll.dll. Añadir un flin mas (Flink->Flink->Flink) mostraría kernel32.dll.

#### 2. Encontrar la tabla de export de la NTDLL en memoria

Ahora que sabemos la dirección base de la NTDLL dentro del proceso, podemos **aprovechar la estructura típica de un PE para encontrar la tabla de exports**.

```c++
#include "peb.h"
#include <Windows.h>
#include <cstdio>

PIMAGE_EXPORT_DIRECTORY GetExportTableAddress(HMODULE ImageBase) {
    uintptr_t baseAddress = reinterpret_cast<uintptr_t>(ImageBase);

    uintptr_t dosHeaderAddr = baseAddress;
    IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(dosHeaderAddr);

    uintptr_t peHeaderAddr = baseAddress + dosHeader->e_lfanew;
    IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(peHeaderAddr);

    IMAGE_EXPORT_DIRECTORY* exportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
        baseAddress + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    return (PIMAGE_EXPORT_DIRECTORY)exportDir;
}
```

#### 3. Encontrar la dirección de la función correspondiente

Con la dirección de la tabla de exports de la NTDLL ya podemos acceder a ella y **buscar mediante el propio nombre de la función** la dirección en la que se encuentra.

```c++
#include "peb.h"
#include <Windows.h>
#include <cstdio>

HANDLE GetExportFunctionAddress(HMODULE moduleHandle, PIMAGE_EXPORT_DIRECTORY exportDir, const char* functionName) {
    uintptr_t baseAddress = reinterpret_cast<uintptr_t>(moduleHandle);
    DWORD* addressOfFunctions = reinterpret_cast<DWORD*>(baseAddress + exportDir->AddressOfFunctions);
    DWORD numberOfFunctions = exportDir->NumberOfFunctions;

    DWORD* addressOfNameOrdinals = reinterpret_cast<DWORD*>(baseAddress + exportDir->AddressOfNameOrdinals);
    DWORD* addressOfNames = reinterpret_cast<DWORD*>(baseAddress + exportDir->AddressOfNames);

    uintptr_t functionAddress = 0;

    for (DWORD i = 0; i < numberOfFunctions; ++i) {
        const char* currentFunctionName = nullptr;

        if (i < exportDir->NumberOfNames) {
            currentFunctionName = reinterpret_cast<const char*>(baseAddress + addressOfNames[i]);
        }

        functionAddress = baseAddress + addressOfFunctions[i+1];

        if (currentFunctionName && strcmp(currentFunctionName, functionName) == 0) {
            functionAddress = functionAddress;
            return (HANDLE)functionAddress;
        }
    }

    return (HANDLE)-1;
}
```

#### 4. Extraer el SSN

Este paso lo he realizado mediante una rutina de ensamblador, ya que creo que es más sencillo.

```c++
#include "peb.h"
#include <Windows.h>
#include <cstdio>

extern "C" DWORD GetSSNByFuncAddress(HANDLE functionAddress);
```

```c++
section .text

global GetSSNByFuncAddress

GetSSNByFuncAddress:
    mov ebx, 0xB8D18B4C
    mov rdx, 0x0
    mov rax, [rcx]
    cmp eax, ebx
    je GetSSN + 0x1B
    add rcx, 0x20
    add rdx, 0x1
    jmp GetSSN + 0xA
    mov rax, [rcx + 0x4]
    sub rax, rdx
    ret
```

> El código completo puedes encontrarlo en [mi GitHub](https://github.com/pard0p/SSN_Finder)
{: .prompt-info }