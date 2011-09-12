
/*--------------------------------------------------------------------*/
/*--- Privgrind: The Priv-seperation Valgrind tool.      pg_main.c ---*/
/*--------------------------------------------------------------------*/


#include "pub_tool_basics.h"
#include "pub_tool_vki.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_libcprint.h"

#include <string.h>
#include "pg_include.h"
#include "pub_tool_xarray.h"    
#include "pub_tool_debuginfo.h"    

static Char* clo_privgrind_out_file = "privgrind.out.%p";
static Char* clo_boundary_fun = 0;
static Bool clo_trace_mem       = True;
static Bool clo_trace_calls     = True;


static VgHashTable func_ht;
static VgHashTable live_ht;
static PG_PageRange   freed_objs;

/* Assume 4 KB pages */
#define PAGE_SIZE 4096
#define PAGE_MASK (~0xFFF)

static Bool pg_process_cmd_line_option(Char* arg)
{
   if 	   VG_BOOL_CLO(arg, "--trace-mem", clo_trace_mem) {}
   else if VG_BOOL_CLO(arg, "--trace-calls", clo_trace_calls) {}
   else if VG_STR_CLO( arg, "--boundary-function", clo_boundary_fun) {}
   else if VG_STR_CLO( arg, "--privgrind-out-file", clo_privgrind_out_file) {}
   else return False;
   
   tl_assert(clo_trace_mem || clo_trace_calls);
   return True;
}

static void pg_print_usage(void)
{  
   VG_(printf)(
"    --privgrind-out-file=<f>  Output file name [privgrind.out.%%p]\n"
"    --boundary-function=<f>   Dump information when entering boundary function\n"
"    --trace-mem=no|yes        Trace all memory accesses by function [yes]\n"
"    --trace-calls=no|yes      Trace all calls made by the calling function [yes]\n"
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
   live_ht = VG_(HT_construct) ( "data_addr_hash" );

   /* Add a node for unknown functions */
   initUnknownFunc(func_ht);
}


/*------------------------------------------------------------*/
/*--- Stuff for --trace-mem                                ---*/
/*------------------------------------------------------------*/

static void insertNode( PG_PageRange* page_node, PG_DataObj * insert_node ) 
{
  PG_DataObj *curr, *prev;
  insert_node->prev = NULL;
  insert_node->next = NULL;
  /* TODO: replace this with a binary search */
  curr = page_node->first;
  prev = NULL;
  for (;;) {
    if (curr == NULL || curr->addr >= insert_node->addr) {
      if (curr == page_node->first) {
	/* insert at front */
	insert_node->next = page_node->first;
	page_node->first = insert_node;
	break;
      } else if (curr == NULL) {
	/* insert at the end */
	tl_assert(prev != NULL); // should have been inserted at the front
	prev->next = insert_node;
	insert_node->prev = prev;
	break;
      } else {
	/* insert inbetween prev and curr */
	insert_node->prev = prev;
	insert_node->next = curr;
	curr->prev = insert_node;
	prev->next = insert_node;
	break;
      }
    }
    prev = curr;
    curr = curr->next;
  }
}

static void removeNode ( PG_PageRange* page_node, PG_DataObj * addr_node ) 
{
  if (addr_node == page_node->first) {
    page_node->first = addr_node->next;
  } else if (addr_node->prev != NULL) {
    addr_node->prev->next = addr_node->next;
  }
  if (addr_node->next != NULL) {
    addr_node->next->prev = addr_node->prev;
  }
  addr_node->next = NULL;
  addr_node->prev = NULL;
}

static PG_DataObj * getNode ( PG_PageRange* page_node, Addr addr ) 
{
  PG_DataObj * ret = NULL;
  /* TODO: replace this with a binary search */
  ret = page_node->first;
  while(ret != NULL) {
    if (addr >= ret->addr && addr < (ret->addr + ret->size)) {
      return ret;
    }
    ret = ret->next;
  }
  return ret;
}

PG_DataObj * PG_(dataobj_node_malloced)( Addr addr, SizeT size )
{
  PG_PageRange* page_node = NULL;
  PG_DataObj *  addr_node = NULL;
  /* Lookup page list */
  Addr page_addr = addr & PAGE_MASK;
  do {
    /* create address node */
    addr_node = VG_(malloc) ("trace_load.addr_node", sizeof(PG_DataObj) );
    memset(addr_node, 0, sizeof(PG_DataObj));
    addr_node->addr = addr;
    addr_node->size = size;
    addr_node->access_ht = VG_(HT_construct) ( "access_hash" );
    
    page_node = VG_(HT_lookup) ( live_ht, page_addr );
    if (!page_node) {
      page_node = VG_(malloc) ("trace_load.page_node", sizeof(PG_PageRange) );
      memset(page_node, 0, sizeof(PG_PageRange));
      page_node->page_addr = page_addr;
      VG_(HT_add_node) (live_ht, page_node);
    }
    /* Insert node into list */
    insertNode( page_node, addr_node );
    
    page_addr += PAGE_SIZE;
  } while (page_addr < addr + size);
  return addr_node;
}

void PG_(dataobj_node_freed)( Addr addr )
{
  PG_PageRange* page_node = NULL;
  PG_DataObj *  addr_node = NULL;
  /* Lookup page list */
  Addr page_addr = addr & PAGE_MASK;

  do {
    page_node = VG_(HT_lookup) ( live_ht, page_addr );
    if (page_node == NULL) return;
    addr_node = getNode(page_node, addr);
    if (addr_node == NULL) return;
    /* Remove node from list */
    removeNode( page_node, addr_node );
    /* Save in freed_objs for later output */
    insertNode( &freed_objs, addr_node);

    page_addr += PAGE_SIZE;
  } while (page_addr < addr + addr_node->size);
}

PG_DataObj * PG_(dataobj_get_node)( Addr addr )
{
  /* Lookup page list */
  Addr page_addr = addr & PAGE_MASK;

  PG_PageRange* page_node = VG_(HT_lookup) ( live_ht, page_addr );
  if (page_node) {
    return (getNode(page_node, addr));
  } else {
    return NULL;
  }
}

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
  /* look up address in malloced list */
  PG_DataObj * addr_node = PG_(dataobj_get_node)( addr );
  if (addr_node == NULL) {
    /* Check if it is a global that we have not yet added to our list */
    Addr glob_start;
    Word glob_size;
    if (VG_(get_global_obj) ( addr, &glob_start, &glob_size )) {
      /* Treat this global as having been malloced to add it to the list
	 of addresses traced */
      addr_node = PG_(dataobj_node_malloced)( glob_start, glob_size );
    } else if (VG_(DebugInfo_sect_kind)( NULL, 0, addr) == Vg_SectData) {
      /* If it is in the data section, just add an object based on access */
      addr_node = PG_(dataobj_node_malloced)( addr, 
			bytes_read == 0 ? bytes_read : bytes_written);
    }
  }
  if (addr_node != NULL) {
    PG_Access* access_node = VG_(HT_lookup) ( addr_node->access_ht, func_id );
    if (access_node == NULL) {
		access_node = VG_(malloc) ("trace_load.access_node", sizeof(PG_Access) );
		access_node->func_id = func_id;
		/* Lookup iteration */
		access_node->iteration = getFunc(func_id)->iteration;
		access_node->bytes_read = 0;
		access_node->bytes_written = 0;
		VG_(HT_add_node) (addr_node->access_ht, access_node);
    } else if (access_node->iteration < getFunc(func_id)->iteration) {
		/* If more recent function iteration, create new node */
		PG_Access* new_access_node = VG_(malloc) ("trace_load.access_node", sizeof(PG_Access) );
		new_access_node->func_id = func_id;
		/* Lookup iteration */
		new_access_node->iteration = getFunc(func_id)->iteration;
		new_access_node->bytes_read = 0;
		new_access_node->bytes_written = 0;
		/* Insert into node list */
		new_access_node->ll_next = access_node;
		VG_(HT_remove) ( addr_node->access_ht, func_id );
		VG_(HT_add_node) (addr_node->access_ht, new_access_node);
	}
    access_node->bytes_read += bytes_read;
    access_node->bytes_written += bytes_written;
  }

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


static void dump_info()
{
	
	Int     fd;
	SysRes  sres;
	Char    buf[512];
   
	PG_PageRange * page;
	PG_DataObj * addr;
	PG_Access  * access;

   // Setup output filename.  Nb: it's important to do this now, ie. as late
   // as possible.  If we do it at start-up and the program forks and the
   // output file format string contains a %p (pid) specifier, both the
   // parent and child will incorrectly write to the same file;  this
   // happened in 3.3.0.
   Char* privgrind_out_file =
      VG_(expand_file_name)("--privgrind-out-file", clo_privgrind_out_file);

   sres = VG_(open)(privgrind_out_file, VKI_O_CREAT|VKI_O_TRUNC|VKI_O_WRONLY,
                                         VKI_S_IRUSR|VKI_S_IWUSR);
   if (sr_isError(sres)) {
      // If the file can't be opened for whatever reason (conflict
      // between multiple privgrinded processes?), give up now.
      VG_(umsg)("error: can't open Privgrind output file '%s'\n",
                privgrind_out_file );
      VG_(umsg)("       ... so output will be missing.\n");
      VG_(free)(privgrind_out_file);
      return;
   } else {
      fd = sr_Res(sres);
      VG_(free)(privgrind_out_file);
   }
   
	/* Scan through pages from live_ht */
	VG_(HT_ResetIter)(live_ht);
	while ( (page = VG_(HT_Next)(live_ht)) ) {
	  
		/* Scan through addresses */
		addr = page->first;
		while ( addr != NULL ) {
		
			if (VG_(HT_count_nodes) (addr->access_ht) > 1) {

				VG_(sprintf) (buf, "ADDR: 0x%lx\n", addr->addr);
				VG_(write)(fd, (void*)buf, VG_(strlen)(buf));
				
				VG_(HT_ResetIter)(addr->access_ht);

				/* Scan through accesses */
				while ( (access = VG_(HT_Next)(addr->access_ht)) ) {
					VG_(sprintf) (buf, "  ACCESS: %lu, %lu, %lu\n", access->func_id,
						   access->bytes_read, access->bytes_written);
					VG_(write)(fd, (void*)buf, VG_(strlen)(buf));
				}
			
			}
		
			addr = addr->next;
		}
	}

   // Close file
   VG_(close) (fd);
   	
}

static VG_REGPARM(2) void trace_call(UWord caller_func_id, UWord target_func_id)
{
  PG_Func *caller_func;
  PG_Func *target_func;
  PG_CallHistory *call_history;  
  PG_Calls *target;
  
  /* Extend call history list */
  target_func = getFunc(target_func_id);
  tl_assert(target_func != NULL);
  call_history = VG_(malloc) ("func_ht.node.call_history", sizeof (PG_CallHistory));
  call_history->calls_ht = VG_(HT_construct) ( "calls_hash" );
  call_history->next = target_func->call_history;
  target_func->call_history = call_history;    
  target_func->iteration++;
  
  caller_func = getFunc(caller_func_id);
  tl_assert(caller_func != NULL);
  target = VG_(HT_lookup) ( caller_func->call_history->calls_ht, target_func_id );
  if (target == NULL) {
    target = VG_(malloc) ("trace_calls.calls", sizeof(PG_Calls));
    target->target_id = target_func_id;
    target->count = 0;
    VG_(HT_add_node) ( caller_func->call_history->calls_ht, target );
  }
  target->count++;
  
   // Check for a marker function call
  if (target_func_id == 27) {
	  if (clo_trace_mem) {
		  // Dump info to file
		  dump_info();
	  }
  }
  
}

static VG_REGPARM(2) void trace_call_indirect(UWord caller_func_id, 
					      Addr target_addr)
{
  PG_Func *caller_func;
  PG_Func *target_func;
  PG_CallHistory *call_history;  
  PG_Calls *target;
  UWord target_func_id;
  
  caller_func = getFunc(caller_func_id);
  tl_assert(caller_func != NULL);
  target_func_id = getFuncId(target_addr, func_ht);
  
  /* Extend call history list */
  target_func = getFunc(target_func_id);
  tl_assert(target_func != NULL);
  call_history = VG_(malloc) ("func_ht.node.call_history", sizeof (PG_CallHistory));
  call_history->calls_ht = VG_(HT_construct) ( "calls_hash" );
  call_history->next = target_func->call_history;
  target_func->call_history = call_history;    
  target_func->iteration++;

  target = VG_(HT_lookup) ( caller_func->call_history->calls_ht, target_func_id );
  if (target == NULL) {
    target = VG_(malloc) ("trace_calls.calls", sizeof(PG_Calls));
    target->target_id = target_func_id;
    target->count = 0;
    VG_(HT_add_node) ( caller_func->call_history->calls_ht, target );
  }
  target->count++;
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
void addEvent_Call ( IRSB* sb, UWord func_id, UWord target_func_id )
{
  Char*      helperName;
  void*      helperAddr;
  IRExpr**   argv;
  IRDirty*   di;

  helperName = "trace_call";
  helperAddr =  trace_call;

  // Add the helper.
  argv = mkIRExprVec_2( mkIRExpr_HWord( func_id ), 
			mkIRExpr_HWord( target_func_id ) );
  di   = unsafeIRDirty_0_N( /*regparms*/2, 
			    helperName, VG_(fnptr_to_fnentry)( helperAddr ),
			    argv );
  addStmtToIRSB( sb, IRStmt_Dirty(di) );
  
}

static
void addEvent_Call_Indirect ( IRSB *sb, UWord func_id, IRExpr *target_addr )
{
  Char*      helperName;
  void*      helperAddr;
  IRExpr**   argv;
  IRDirty*   di;

  helperName = "trace_call_indirect";
  helperAddr =  trace_call_indirect;

  // Add the helper.
  argv = mkIRExprVec_2( mkIRExpr_HWord( func_id ), 
			target_addr );
  di   = unsafeIRDirty_0_N( /*regparms*/2, 
			    helperName, VG_(fnptr_to_fnentry)( helperAddr ),
			    argv );
  addStmtToIRSB( sb, IRStmt_Dirty(di) );
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
     func_id = getFuncId(sbIn->stmts[i]->Ist.IMark.addr, func_ht);
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
	   {
	     /* reset function id if it has changed */
	     Int new_func_id = getFuncId(sbIn->stmts[i]->Ist.IMark.addr, func_ht);
	     if (new_func_id != func_id) {
	       /* changed functions midway through a block */
	       if (clo_trace_calls) {
		 addEvent_Call( sbOut, func_id, new_func_id);
	       }
	       if (clo_trace_mem) {
		 flushEvents(sbOut);
	       }
	       func_id = new_func_id;
	     }
	     if (clo_trace_mem) {
               // WARNING: do not remove this function call, even if you
               // aren't interested in instruction reads.  See the comment
               // above the function itself for more detail.
               addEvent_Ir( sbOut, mkIRExpr_HWord( (HWord)st->Ist.IMark.addr ),
                            st->Ist.IMark.len, func_id );
	     }
	     addStmtToIRSB( sbOut, st );
	     break;
	   }
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

	   if (clo_trace_calls) {
	     if (st->Ist.Exit.jk == Ijk_Call || st->Ist.Exit.jk ==  Ijk_Boring) {
	       Addr target = irConstToAddr(st->Ist.Exit.dst);
	       UWord target_fid = getFuncId(target, func_ht);
	       if (target_fid != func_id) {
		 addEvent_Call( sbOut, func_id, target_fid);
	       }
	     }
	   }
	   if (clo_trace_mem) {
	     flushEvents(sbOut);
	   }
	   
	   addStmtToIRSB( sbOut, st );
	   
	   break;

         default:
            tl_assert(0);
      }
   }

   if (clo_trace_calls) {
     if (sbIn->jumpkind == Ijk_Call || sbIn->jumpkind == Ijk_Boring) {
       switch (sbIn->next->tag) {
       case Iex_Const:
	 {
	   Addr target = irConstToAddr(sbIn->next->Iex.Const.con);
	   UWord target_fid = getFuncId(target, func_ht);
	   if (target_fid != func_id) {
	     addEvent_Call( sbOut, func_id, target_fid);
	   }
	   break;
	 }
       case Iex_RdTmp:
	 /* looks like an indirect branch (branch to unknown) */
	 addEvent_Call_Indirect( sbOut, func_id, sbIn->next );
	 break;
       default:
	 /* shouldn't happen - if the incoming IR is properly
	    flattened, should only have tmp and const cases to
	    consider. */
	 tl_assert(0);
       }
     }
   }
   if (clo_trace_mem) {
      /* At the end of the sbIn.  Flush outstandings. */
      flushEvents(sbOut);
   }


   return sbOut;
}

/* Output function  details */
static void pg_out_fun (void)
{

	PG_Func * func;
	PG_Calls * call;
	PG_CallHistory * call_history;
	unsigned int i;
	
  VG_(HT_ResetIter)(func_ht);
  while ( (func = VG_(HT_Next)(func_ht)) ) {
    VG_(printf) ("FUNC: %lu %s (%s%s)\n", func->id, func->fnname,
		 func->dirname, func->filename);
    if (clo_trace_calls) {
	  
      i=0;
      call_history = func->call_history;
      while (call_history != NULL) {
		  VG_(printf) ("  ITERATION: %lu \n", i );
		  VG_(HT_ResetIter)(call_history->calls_ht);
		  while ( (call = VG_(HT_Next)(call_history->calls_ht)) ) {
			VG_(printf) ("  	CALL: %lu, %lu \n", call->target_id, call->count);
		  }
		  call_history = call_history->next;
		  i++;
      }
      
    }
    if (func->id != UNKNOWN_FUNC_ID) { 
      VG_(free) (func->fnname);
      VG_(free) (func->filename);
      VG_(free) (func->dirname);
    }
  }
}

/* Output data object details */
static void pg_out_obj (PG_PageRange * page, PG_DataObj * addr)
{
  PG_Access  * access;
  
	addr = freed_objs.first;
	while (addr != NULL) {
		if (VG_(HT_count_nodes) (addr->access_ht) > 1) {
			VG_(printf) ("ADDR: 0x%lx\n", addr->addr);
			VG_(HT_ResetIter)(addr->access_ht);
			while ( (access = VG_(HT_Next)(addr->access_ht)) ) {
				
				while (access != NULL) { 
					VG_(printf) ("  ACCESS: %lu, iter:%u, %lu, %lu\n",
						access->func_id, access->iteration,
						access->bytes_read, access->bytes_written);
					access = access->ll_next;
				}
						
			}
		
		VG_(HT_destruct) (addr->access_ht);
		
		}
	  addr = addr->next;
	}
}

static void pg_fini(Int exitcode)
{
  PG_PageRange * page;
  PG_DataObj * addr;

  /* Output function details */
	pg_out_fun();


  if (clo_trace_mem) {
	  
/*
    // Scan through live list, adding to freed list
    VG_(HT_ResetIter)(live_ht);
    while ( (page = VG_(HT_Next)(live_ht)) ) {
      addr = page->first;
      while ( addr != NULL ) {
				PG_DataObj * next = addr->next;
				PG_(dataobj_node_freed)(addr->addr);
				addr = next;
      }
    }
*/

	// Output data object details
	pg_out_obj(page, addr);
	
  }

  VG_(HT_destruct) (func_ht);
  VG_(HT_destruct) (live_ht);
  
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

   VG_(needs_malloc_replacement)  (PG_(malloc),
                                   PG_(__builtin_new),
                                   PG_(__builtin_vec_new),
                                   PG_(memalign),
                                   PG_(calloc),
                                   PG_(free),
                                   PG_(__builtin_delete),
                                   PG_(__builtin_vec_delete),
                                   PG_(realloc),
                                   PG_(malloc_usable_size), 
                                   PG_MALLOC_REDZONE_SZB );
}

VG_DETERMINE_INTERFACE_VERSION(pg_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
