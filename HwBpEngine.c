//#include "HwBpEngine.h"
//#include "HwBpExceptions.c"
//#include "badger_exports.h"
//#include "utils.h"
//#include "common.h"
//
//PHWBP_ENGINE gEngine = NULL;
//\
//LONG ExceptionHandler(
//        IN OUT PEXCEPTION_POINTERS Exception
//);
//
///*!
// * Init Hardware breakpoint engine by
// * registering a Vectored exception handler
// * @param Engine   if emtpy global handler gonna be used
// * @param Handler
// * @return
// */
//NTSTATUS HwBpEngineInit(
//        OUT PHWBP_ENGINE Engine,
//        IN  PVOID        Handler
//) {
//    PHWBP_ENGINE HwBpEngine  = Engine;
//    PVOID        HwBpHandler = Handler;
//
//    /* check if an engine object has been specified in the function param.
//     * if not then check if teh callee want's to init the global engine.
//     * tho if the global engine has been already init then abort  */
////    if ( ( ! HwBpEngine && ! HwBpHandler ) ) {
////        return STATUS_INVALID_PARAMETER;
////    }
//
//    /* since we did not specify an engine let's use the global one */
//    if ( ! HwBpEngine ) {
//        HwBpEngine  = BadgerAlloc( sizeof( HWBP_ENGINE ) );
//        HwBpHandler = &ExceptionHandler;
//    }
//
//    /* register Vectored exception handler */
//    if ( ! ( HwBpEngine->Veh = KERNEL32$AddVectoredExceptionHandler( TRUE, HwBpHandler ) ) ) {
//        return STATUS_UNSUCCESSFUL;
//    }
//
//    /* tell the engine that it has not added anything atm */
//    HwBpEngine->First = TRUE;
//
//    gEngine = HwBpEngine;
//    return STATUS_SUCCESS;
//}
//
///*!
// * Set hardware breakpoint on specified address
// * @param Tib
// * @param Address
// * @param Position
// * @param Add
// * @return
// */
//NTSTATUS HwBpEngineSetBp(
//        IN DWORD Tid,
//        IN PVOID Address,
//        IN BYTE  Position,
//        IN BYTE  Add
//) {
//    //CLIENT_ID         Client  = { 0 };
//    CONTEXT           Context = { 0 };
//    HANDLE            Thread  = NULL;
//    NTSTATUS          Status  = STATUS_SUCCESS;
//    //OBJECT_ATTRIBUTES ObjAttr = { 0 };
//
//    /* Initialize Object Attributes */
//    //InitializeObjectAttributes( &ObjAttr, NULL, 0, NULL, NULL );
//
////    Client.UniqueProcess = C_PTR( Pid );
////    Client.UniqueThread  = C_PTR( Tid );
//
//    /* try to get open thread handle */
//    if(!OpenThread(THREAD_ALL_ACCESS,FALSE,Tid)){
//        BadgerDispatch(gdispatch,"OpenThread failed with error: %d",GetLastError());
//        goto FAILED;
//    }
//
//    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
//
//    /* try to get context of thread */
//    if(!GetThreadContext(Thread,&Context)){
//        BadgerDispatch(gdispatch,"OpenThread failed with error: %d",GetLastError());
//        goto FAILED;
//    }
//
//    /* add hardware breakpoint */
//    if ( Add )
//    {
//        /* set address */
//        ( &Context.Dr0 )[ Position ] = U_PTR( Address );
//
//        /* setup registers */
//        Context.Dr7 &= ~( 3ull << ( 16 + 4 * Position ) );
//        Context.Dr7 &= ~( 3ull << ( 18 + 4 * Position ) );
//        Context.Dr7 |= 1ull << ( 2 * Position );
//    }
//    else /* remove hardware breakpoint */
//    {
//        if ( ( &Context.Dr0 )[ Position ] == Address ) {
//            BadgerDispatch(gdispatch,
//                    "Dr Registers:  \n"
//                    "- Dr0[%d]: %p  \n"
//                    "- Dr7   : %p  \n",
//                    Position, ( &Context.Dr0 )[ Position ],
//                    Context.Dr7
//            );
//
//                    ( &Context.Dr0 )[ Position ] = U_PTR( NULL );
//            Context.Dr7 &= ~( 1ull << ( 2 * Position ) );
//
//            BadgerDispatch(gdispatch,
//                    "Dr Registers:  \n"
//                    "- Dr0[%d]: %p  \n"
//                    "- Dr7   : %p  \n",
//                    Position, ( &Context.Dr0 )[ Position ],
//                    Context.Dr7
//            );
//        }
//    }
//
//    if(!GetThreadContext(Thread,&Context)){
//        BadgerDispatch(gdispatch,"failed second getThreadContext. Error = %d\n",GetLastError());
//        goto FAILED;
//    }
//
//    return Status;
//
//    FAILED:
//    if ( Thread ) {
//        KERNEL32$CloseHandle( Thread );
//        Thread = NULL;
//    }
//
//    return Status;
//}
//
///*!
// * Set an hardware breakpoint to an address
// * and adds it to the engine breakpoints list linked
// * @param Engine
// * @param Thread
// * @param Address
// * @param Function
// * @param Position
// * @return
// */
//NTSTATUS HwBpEngineAdd(
//        IN PHWBP_ENGINE Engine,
//        IN DWORD        Tid,
//        IN PVOID        Address,
//        IN PVOID        Function,
//        IN BYTE         Position
//) {
//    PHWBP_ENGINE HwBpEngine = gEngine;
//    PBP_LIST     BpEntry    = NULL;
//
//    BadgerDispatch(gdispatch, "Engine:[%p] Tid:[%d] Address:[%p] Function:[%p] Position:[%d]\n", Engine, Tid, Address, Function, Position );
//
////    /* check if engine has been specified */
////    if ( ! HwBpEngine ) {
////        return STATUS_INVALID_PARAMETER;
////    }
//
//    /* check if the right params has been specified */
//    if ( ! Address || ! Function ) {
//        return STATUS_INVALID_PARAMETER;
//    }
//
//    /* if no engine specified use the global one */
////    if ( ! HwBpEngine ) {
////        HwBpEngine = Instance.HwBpEngine;
////    }
//
//    /* create bp entry */
//    BpEntry = BadgerAlloc( sizeof( BP_LIST ) );
//    BpEntry->Tid      = Tid;
//    BpEntry->Address  = Address;
//    BpEntry->Function = Function;
//    BpEntry->Position = Position;
//    BpEntry->Next     = gEngine->Breakpoints;
//
//    /* set breakpoint */
//    if ( ! NT_SUCCESS( HwBpEngineSetBp( Tid, Address, Position, TRUE ) ) ) {
//        BadgerDispatch(gdispatch, "[HWBP] Failed to set hardware breakpoint" );
//        goto FAILED;
//    } else {
//        BadgerDispatch(gdispatch, "[HWBP] Added hardware breakpoint: Tid:[%d] Addr:[%p] Pos:[%d]\n", Tid, Address, Position );
//    }
//
//    /* append breakpoint */
//    gEngine->Breakpoints = BpEntry;
//
//    return STATUS_SUCCESS;
//
//    FAILED:
//    if ( BpEntry ) {
//        BadgerFree( BpEntry );
//        BpEntry = NULL;
//    }
//
//    return STATUS_UNSUCCESSFUL;
//}
//
//NTSTATUS HwBpEngineRemove(
//        IN PHWBP_ENGINE Engine,
//        IN DWORD        Tid,
//        IN PVOID        Address
//) {
//    PHWBP_ENGINE HwBpEngine = NULL;
//    PBP_LIST     BpEntry    = NULL;
//    PBP_LIST     BpLast     = NULL;
//
////    if ( ! Engine  ) {
////        return STATUS_INVALID_PARAMETER;
////    }
////
////    if ( ! HwBpEngine ) {
////        HwBpEngine = Instance.HwBpEngine;
////    }
//
//
//    /* set linked list */
//    BpEntry = BpLast = gEngine->Breakpoints;
//
//    for ( ;; )
//    {
//        /* check if BpEntry is NULL */
//        if ( ! BpEntry ) {
//            break;
//        }
//
//        /* is it the breakpoint we want to remove ? */
//        if ( BpEntry->Tid == Tid && BpEntry->Address == Address )
//        {
//            /* unlink from linked list */
//            BpLast->Next = BpEntry->Next;
//
//            /* disable hardware breakpoint */
//            HwBpEngineSetBp( BpEntry->Tid, BpEntry->Address, BpEntry->Position, FALSE );
//
//            /* zero out struct */
//            BadgerMemset( BpEntry, 0,sizeof( BP_LIST ) );
//
//            /* free memory struct */
//            BadgerFree( BpEntry );
//
//            break;
//        }
//
//        BpLast  = BpEntry;
//        BpEntry = BpEntry->Next;
//    }
//
//    return STATUS_SUCCESS;
//}
//
//NTSTATUS HwBpEngineDestroy(
//        IN PHWBP_ENGINE Engine
//) {
//    PHWBP_ENGINE HwBpEngine = Engine;
//    PBP_LIST     BpEntry    = NULL;
//    PBP_LIST     BpNext     = NULL;
//
////    if ( ! Engine &&  ) {
////        return STATUS_INVALID_PARAMETER;
////    }
//
////    if ( ! HwBpEngine ) {
////        HwBpEngine = Instance.HwBpEngine;
////    }
//
//    /* remove Vector exception handler */
//
//    KERNEL32$RemoveVectoredExceptionHandler( gEngine->Veh );
//
//    BpEntry = gEngine->Breakpoints;
//
//    /* remove all breakpoints and free memory */
//    do {
//        /* check if BpEntry is NULL */
//        if ( ! BpEntry ) {
//            break;
//        }
//
//        /* get next element from linked list */
//        BpNext = BpEntry->Next;
//
//        /* disable hardware breakpoinnt */
//        HwBpEngineSetBp( BpEntry->Tid, BpEntry->Address, BpEntry->Position, TRUE );
//
//        /* zero out struct */
//        BadgerMemset( BpEntry,0, sizeof( BP_LIST ) );
//
//        /* free memory struct */
//        BadgerFree( BpEntry );
//
//        BpEntry = BpNext;
//    } while ( TRUE );
//
//    /* free global state */
////    if ( HwBpEngine == Instance.HwBpEngine ) {
////        NtHeapFree( HwBpEngine );
////
////        Instance.HwBpEngine = NULL;
////    }
//
//    BadgerFree(gEngine);
//
//    gEngine = NULL;
//
//    return STATUS_SUCCESS;
//}
//
///*!
// * Global exception handler
// * @param Exception
// * @return
// */
//LONG ExceptionHandler(
//        IN OUT PEXCEPTION_POINTERS Exception
//) {
//    PBP_LIST BpEntry = NULL;
//    BOOL     Found   = FALSE;
//
//    BadgerDispatch(gdispatch, "Exception Address: %p\n", Exception->ExceptionRecord->ExceptionAddress );
//    BadgerDispatch(gdispatch, "Exception Code   : %p\n", Exception->ExceptionRecord->ExceptionCode );
//
//    BpEntry = gEngine->Breakpoints;
//
//    if ( Exception->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP )
//    {
//        /* search in linked list for bp entry */
//        do {
//            /* stop search */
//            if ( ! BpEntry ) {
//                break;
//            }
//
//            /* check if it's the address we want */
//            if ( BpEntry->Address == Exception->ExceptionRecord->ExceptionAddress ) {
//                Found = TRUE;
//
//                /* remove breakpoint */
//                HwBpEngineSetBp( BpEntry->Tid, BpEntry->Address, BpEntry->Position, FALSE );
//
//                /* execute registered exception */
//                ( ( VOID (*)( PEXCEPTION_POINTERS ) ) BpEntry->Function ) ( Exception );
//
//                break;
//            }
//
//            /* Next entry */
//            BpEntry = BpEntry->Next;
//        } while ( TRUE );
//
//        BadgerDispatch(gdispatch, "Found exception handler: %s\n", Found ? "TRUE" : "FALSE" );
//        if ( Found ) {
//            return EXCEPTION_CONTINUE_EXECUTION;
//        }
//    }
//
//    return EXCEPTION_CONTINUE_SEARCH;
//}