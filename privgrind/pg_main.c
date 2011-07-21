
/*--------------------------------------------------------------------*/
/*--- Privgrind: The Priv-seperation Valgrind tool.      pg_main.c ---*/
/*--------------------------------------------------------------------*/

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_options.h"
#include "pub_tool_machine.h"
#include "pub_tool_mallocfree.h"
#include <string.h>

#include "pg_include.h"

#define FN_LENGTH 100
#define UNKNOWN_FUNC_ID 0

static Bool clo_trace_mem       = True;
static Bool clo_trace_calls     = True;

static VgHashTable func_ht;
static VgHashTable addr_ht;

static int curr_func_id = UNKNOWN_FUNC_ID;

static Bool pg_process_cmd_line_option(Char* arg)
{
   if VG_BOOL_CLO(arg, "--trace-mem", clo_trace_mem) {}
   else if VG_BOOL_CLO(arg, "--trace-calls", clo_trace_calls) {}
   else
      return False;
   
   tl_assert(clo_trace_mem || clo_trace_calls);
   return True;
}

static void pg_print_usage(void)
{  
   VG_(printf)(
"    --trace-mem=no|yes    trace all memory accesses by function [yes]\n"
"    --trace-calls=no|yes  trace all calls made by the calling function [yes]\n"
   );
}

static void pg_print_debug_usage(void)
{  
   VG_(printf)(
"  (none) "
   );
}

static void pg_post_clo_init(void)
{
   func_ht = VG_(HT_construct) ( "func_hash" );
   addr_ht = VG_(HT_construct) ( "data_addr_hash" );

   /* Add a node for unknown functions */
   PG_Func *func = VG_(malloc) ("func_ht.node", sizeof (PG_Func));
   func->fnname = "<Unknown>";
   func->key = hash_sdbm(func->fnname);
   func->id = curr_func_id++;
   tl_assert(func->id == UNKNOWN_FUNC_ID);
   VG_(HT_add_node) ( func_ht, func );
}


/*------------------------------------------------------------*/
/*--- Stuff for --trace-mem                                ---*/
/*------------------------------------------------------------*/

#define MAX_DSIZE    512

typedef
   IRExpr 
   IRAtom;

typedef 
   enum { Event_Ir, Event_Dr, Event_Dw, Event_Dm }
   EventKind;

typedef
   struct {
      EventKind  ekind;
      IRAtom*    addr;
      Int        size;
      UWord      func_id;
   }
   Event;

/* Up to this many unnotified events are allowed.  Must be at least two,
   so that reads and writes to the same address can be merged into a modify.
   Beyond that, larger numbers just potentially induce more spilling due to
   extending live ranges of address temporaries. */
#define N_EVENTS 4

/* Maintain an ordered list of memory events which are outstanding, in
   the sense that no IR has yet been generated to do the relevant
   helper calls.  The SB is scanned top to bottom and memory events
   are added to the end of the list, merging with the most recent
   notified event where possible (Dw immediately following Dr and
   having the same size and EA can be merged).

   This merging is done so that for architectures which have
   load-op-store instructions (x86, amd64), the instr is treated as if
   it makes just one memory reference (a modify), rather than two (a
   read followed by a write at the same address).

   At various points the list will need to be flushed, that is, IR
   generated from it.  That must happen before any possible exit from
   the block (the end, or an IRStmt_Exit).  Flushing also takes place
   when there is no space to add a new event.

   If we require the simulation statistics to be up to date with
   respect to possible memory exceptions, then the list would have to
   be flushed before each memory reference.  That's a pain so we don't
   bother.

   Flushing the list consists of walking it start to end and emitting
   instrumentation IR for each event, in the order in which they
   appear. */

static Event events[N_EVENTS];
static Int events_used = 0;

static void update_access(Addr addr, UWord func_id,  SizeT bytes_read, 
			  SizeT bytes_written)
{
  PG_Addr* addr_node = VG_(HT_lookup) ( addr_ht, addr );
  if (addr_node == NULL) {
    addr_node = VG_(malloc) ("trace_load.addr_node", sizeof(PG_Addr) );
    addr_node->addr = addr;
    addr_node->access_ht = VG_(HT_construct) ( "access_hash" );
    VG_(HT_add_node) (addr_ht, addr_node);
  }
  PG_Access* access_node = VG_(HT_lookup) ( addr_node->access_ht, func_id );
  if (access_node == NULL) {
    access_node = VG_(malloc) ("trace_load.access_node", sizeof(PG_Access) );
    access_node->func_id = func_id;
    access_node->bytes_read = 0;
    access_node->bytes_written = 0;
    VG_(HT_add_node) (addr_node->access_ht, access_node);
  }
  access_node->bytes_read += bytes_read;
  access_node->bytes_written += bytes_written;
}

static VG_REGPARM(3) void trace_load(Addr addr, SizeT size, UWord func_id)
{
  if (size > 0) {
    update_access(addr, func_id, size, 0);
  }
}

static VG_REGPARM(3) void trace_store(Addr addr, SizeT size, UWord func_id)
{
  if (size > 0) {
    update_access(addr, func_id, 0, size);
  }
}

static VG_REGPARM(3) void trace_modify(Addr addr, SizeT size, UWord func_id)
{
  if (size > 0) {
    update_access(addr, func_id, size, size);
  }
}

static void flushEvents(IRSB* sb)
{
   Int        i;
   Char*      helperName;
   void*      helperAddr;
   IRExpr**   argv;
   IRDirty*   di;
   Event*     ev;

   for (i = 0; i < events_used; i++) {

      ev = &events[i];
      
      // Decide on helper fn to call and args to pass it.
      switch (ev->ekind) {
         case Event_Ir: continue;
         case Event_Dr: helperName = "trace_load";
                        helperAddr =  trace_load;   break;

         case Event_Dw: helperName = "trace_store";
                        helperAddr =  trace_store;  break;

         case Event_Dm: helperName = "trace_modify";
                        helperAddr =  trace_modify; break;
         default:
            tl_assert(0);
      }

      // Add the helper.
      argv = mkIRExprVec_3( ev->addr, mkIRExpr_HWord( ev->size ), 
			    mkIRExpr_HWord( ev->func_id ) );
      di   = unsafeIRDirty_0_N( /*regparms*/3, 
                                helperName, VG_(fnptr_to_fnentry)( helperAddr ),
                                argv );
      addStmtToIRSB( sb, IRStmt_Dirty(di) );
   }

   events_used = 0;
}

// WARNING:  If you aren't interested in instruction reads, you can omit the
// code that adds calls to trace_instr() in flushEvents().  However, you
// must still call this function, addEvent_Ir() -- it is necessary to add
// the Ir events to the events list so that merging of paired load/store
// events into modify events works correctly.
static void addEvent_Ir ( IRSB* sb, IRAtom* iaddr, UInt isize, UWord func_id )
{
   Event* evt;
   tl_assert(clo_trace_mem);
   if (events_used == N_EVENTS)
      flushEvents(sb);
   tl_assert(events_used >= 0 && events_used < N_EVENTS);
   evt = &events[events_used];
   evt->ekind   = Event_Ir;
   evt->addr    = iaddr;
   evt->size    = isize;
   evt->func_id = func_id;
   events_used++;
}

static
void addEvent_Dr ( IRSB* sb, IRAtom* daddr, Int dsize, UWord func_id )
{
   Event* evt;
   tl_assert(clo_trace_mem);
   tl_assert(isIRAtom(daddr));
   tl_assert(dsize >= 1 && dsize <= MAX_DSIZE);
   if (events_used == N_EVENTS)
      flushEvents(sb);
   tl_assert(events_used >= 0 && events_used < N_EVENTS);
   evt = &events[events_used];
   evt->ekind = Event_Dr;
   evt->addr  = daddr;
   evt->size  = dsize;
   evt->func_id = func_id;
   events_used++;
}

static
void addEvent_Dw ( IRSB* sb, IRAtom* daddr, Int dsize, UWord func_id )
{
   Event* lastEvt;
   Event* evt;
   tl_assert(clo_trace_mem);
   tl_assert(isIRAtom(daddr));
   tl_assert(dsize >= 1 && dsize <= MAX_DSIZE);

   // Is it possible to merge this write with the preceding read?
   lastEvt = &events[events_used-1];
   if (events_used > 0
    && lastEvt->ekind == Event_Dr
    && lastEvt->size  == dsize
    && eqIRAtom(lastEvt->addr, daddr))
   {
      lastEvt->ekind = Event_Dm;
      return;
   }

   // No.  Add as normal.
   if (events_used == N_EVENTS)
      flushEvents(sb);
   tl_assert(events_used >= 0 && events_used < N_EVENTS);
   evt = &events[events_used];
   evt->ekind = Event_Dw;
   evt->size  = dsize;
   evt->addr  = daddr;
   evt->func_id = func_id;
   events_used++;
}

static
IRSB* pg_instrument ( VgCallbackClosure* closure,
                      IRSB* sbIn, 
                      VexGuestLayout* layout, 
                      VexGuestExtents* vge,
                      IRType gWordTy, IRType hWordTy )
{
   Int        i;
   IRSB*      sbOut;
   Char       fnname[FN_LENGTH];
   IRTypeEnv* tyenv = sbIn->tyenv;
   UWord      func_id = -1;       

   if (gWordTy != hWordTy) {
      /* We don't currently support this case. */
      VG_(tool_panic)("host/guest word size mismatch");
   }

   /* Set up SB */
   sbOut = deepCopyIRSBExceptStmts(sbIn);
  
   // Copy verbatim any IR preamble preceding the first IMark
   i = 0;
   while (i < sbIn->stmts_used && sbIn->stmts[i]->tag != Ist_IMark) {
      addStmtToIRSB( sbOut, sbIn->stmts[i] );
      i++;
   }

   if (clo_trace_mem) {
      events_used = 0;
   }
   
   if (i < sbIn->stmts_used) {
     tl_assert(sbIn->stmts[i]->tag == Ist_IMark);
     Bool found_fn = VG_(get_fnname)(sbIn->stmts[i]->Ist.IMark.addr,
				     fnname, FN_LENGTH);
     if (!found_fn) {
       func_id = UNKNOWN_FUNC_ID;
     } else {
       UWord key = hash_sdbm(fnname);
       PG_Func * func = VG_(HT_lookup) ( func_ht, key );
       if (func == NULL) {
	 func = VG_(malloc) ("func_ht.node", sizeof (PG_Func));
	 func->key = key;
	 func->fnname = VG_(malloc) ("func_ht.node.fnname", strlen(fnname));
	 memcpy(func->fnname, fnname, strlen(fnname));
	 func->id = curr_func_id++;
	 VG_(HT_add_node) ( func_ht, func );
       }
       func_id = func->id;
     }
   }     

   for (/*use current i*/; i < sbIn->stmts_used; i++) {
      IRStmt* st = sbIn->stmts[i];
      if (!st || st->tag == Ist_NoOp) continue;
      
      switch (st->tag) {
         case Ist_NoOp:
         case Ist_AbiHint:
         case Ist_Put:
         case Ist_PutI:
         case Ist_MBE:
            addStmtToIRSB( sbOut, st );
            break;

         case Ist_IMark:
            if (clo_trace_mem) {
               // WARNING: do not remove this function call, even if you
               // aren't interested in instruction reads.  See the comment
               // above the function itself for more detail.
               addEvent_Ir( sbOut, mkIRExpr_HWord( (HWord)st->Ist.IMark.addr ),
                            st->Ist.IMark.len, func_id );
            }
            addStmtToIRSB( sbOut, st );
            break;

         case Ist_WrTmp:
            if (clo_trace_mem) {
               IRExpr* data = st->Ist.WrTmp.data;
               if (data->tag == Iex_Load) {
                  addEvent_Dr( sbOut, data->Iex.Load.addr,
                               sizeofIRType(data->Iex.Load.ty), func_id );
               }
            }
            addStmtToIRSB( sbOut, st );
            break;

         case Ist_Store:
            if (clo_trace_mem) {
               IRExpr* data  = st->Ist.Store.data;
               addEvent_Dw( sbOut, st->Ist.Store.addr,
                            sizeofIRType(typeOfIRExpr(tyenv, data)), func_id );
            }
            addStmtToIRSB( sbOut, st );
            break;

         case Ist_Dirty: {
            if (clo_trace_mem) {
               Int      dsize;
               IRDirty* d = st->Ist.Dirty.details;
               if (d->mFx != Ifx_None) {
                  // This dirty helper accesses memory.  Collect the details.
                  tl_assert(d->mAddr != NULL);
                  tl_assert(d->mSize != 0);
                  dsize = d->mSize;
                  if (d->mFx == Ifx_Read || d->mFx == Ifx_Modify)
                     addEvent_Dr( sbOut, d->mAddr, dsize, func_id );
                  if (d->mFx == Ifx_Write || d->mFx == Ifx_Modify)
                     addEvent_Dw( sbOut, d->mAddr, dsize, func_id );
               } else {
                  tl_assert(d->mAddr == NULL);
                  tl_assert(d->mSize == 0);
               }
            }
            addStmtToIRSB( sbOut, st );
            break;
         }

         case Ist_CAS: {
            /* We treat it as a read and a write of the location.  I
               think that is the same behaviour as it was before IRCAS
               was introduced, since prior to that point, the Vex
               front ends would translate a lock-prefixed instruction
               into a (normal) read followed by a (normal) write. */
            Int    dataSize;
            IRType dataTy;
            IRCAS* cas = st->Ist.CAS.details;
            tl_assert(cas->addr != NULL);
            tl_assert(cas->dataLo != NULL);
            dataTy   = typeOfIRExpr(tyenv, cas->dataLo);
            dataSize = sizeofIRType(dataTy);
            if (cas->dataHi != NULL)
               dataSize *= 2; /* since it's a doubleword-CAS */
            if (clo_trace_mem) {
               addEvent_Dr( sbOut, cas->addr, dataSize, func_id );
               addEvent_Dw( sbOut, cas->addr, dataSize, func_id );
            }
            addStmtToIRSB( sbOut, st );
            break;
         }

         case Ist_LLSC: {
            IRType dataTy;
            if (st->Ist.LLSC.storedata == NULL) {
               /* LL */
               dataTy = typeOfIRTemp(tyenv, st->Ist.LLSC.result);
               if (clo_trace_mem)
                  addEvent_Dr( sbOut, st->Ist.LLSC.addr,
                                      sizeofIRType(dataTy), func_id );
            } else {
               /* SC */
               dataTy = typeOfIRExpr(tyenv, st->Ist.LLSC.storedata);
               if (clo_trace_mem)
                  addEvent_Dw( sbOut, st->Ist.LLSC.addr,
                                      sizeofIRType(dataTy), func_id );
            }
            addStmtToIRSB( sbOut, st );
            break;
         }

         case Ist_Exit:
            if (clo_trace_mem) {
               flushEvents(sbOut);
            }

            addStmtToIRSB( sbOut, st );

            break;

         default:
            tl_assert(0);
      }
   }

   if (clo_trace_mem) {
      /* At the end of the sbIn.  Flush outstandings. */
      flushEvents(sbOut);
   }

   return sbOut;
}

static void pg_fini(Int exitcode)
{
  PG_Func * func;
  PG_Addr * addr;
  PG_Access * access;

  VG_(HT_ResetIter)(func_ht);
  while ( (func = VG_(HT_Next)(func_ht)) ) {
    VG_(printf) ("FUNC: %s : %lu\n", func->fnname, func->id);
    if (func->id != UNKNOWN_FUNC_ID) 
      VG_(free) (func->fnname);
  }

  VG_(HT_ResetIter)(addr_ht);
  while ( (addr = VG_(HT_Next)(addr_ht)) ) {
    if (VG_(HT_count_nodes) (addr->access_ht) > 1) {
      VG_(printf) ("ADDR: 0x%lx\n", addr->addr);
      VG_(HT_ResetIter)(addr->access_ht);
      while ( (access = VG_(HT_Next)(addr->access_ht)) ) {
	VG_(printf) ("  ACCESS: %lu, %lu, %lu\n", access->func_id, 
		     access->bytes_read, access->bytes_written);
      }
    }
    VG_(HT_destruct) (addr->access_ht);
  }

  VG_(HT_destruct) (func_ht);
  VG_(HT_destruct) (addr_ht);
  
}

static void pg_pre_clo_init(void)
{
   VG_(details_name)            ("Privgrind");
   VG_(details_version)         (NULL);
   VG_(details_description)     ("the Priv-Seperation Valgrind tool");
   VG_(details_copyright_author)(
      "Copyright (C) 2011, Ross McIlroy.");
   VG_(details_bug_reports_to)  (VG_BUGS_TO);

   VG_(basic_tool_funcs)        (pg_post_clo_init,
                                 pg_instrument,
                                 pg_fini);
   VG_(needs_command_line_options)(pg_process_cmd_line_option,
                                   pg_print_usage,
                                   pg_print_debug_usage);
}

VG_DETERMINE_INTERFACE_VERSION(pg_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
