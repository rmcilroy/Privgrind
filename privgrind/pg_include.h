/*--------------------------------------------------------------------*/
/*--- Privgrind: The Priv-seperation Valgrind tool.   pg_include.h ---*/
/*--------------------------------------------------------------------*/

#ifndef __PG_INCLUDE__
#define __PG_INCLUDE__

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_options.h"
#include "pub_tool_machine.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_hashtable.h"
#include "valgrind.h"

#define FN_LENGTH   100
#define FILENAME_LENGTH 100
#define DIRNAME_LENGTH  512
#define UNKNOWN_FUNC_ID 0

#define PG_(str)    VGAPPEND(vgPrivGrind_,str)

/* This is set the same as memcheck, but might not need be as large */
#define PG_MALLOC_REDZONE_SZB    16

/* This describes a function. Nb: first two fields must match core's
 * VgHashNode. */
typedef 
    struct _PG_Calls {
       struct _PG_Calls * next;
       UWord              target_id;
       UWord              count;
    }
    PG_Calls;

/* This describes a function. Nb: first two fields must match core's
 * VgHashNode. */
typedef
   struct _PG_Func {
      struct _PG_Func*  next;
      UWord             key;            
      Char *            fnname;     
      Char *            filename;
      Char *            dirname;
      UWord             id;
      VgHashTable       calls_ht;
   }
   PG_Func;

/* This describes access to a data object. Nb: first two fields must match 
 * core's VgHashNode. */
typedef
   struct _PG_PageRange {
      struct _PG_PageRecord*  next;
      Addr page_addr;
      struct _PG_DataObj*  first;
   }
   PG_PageRange;

/* This describes access to a data object */
typedef
   struct _PG_DataObj {
      struct _PG_DataObj*  next;
      struct _PG_DataObj*  prev;
      Addr              addr;  
      SizeT             size;  
      VgHashTable       access_ht;
   }
   PG_DataObj;

typedef
   struct _PG_Access {
      struct _PG_Access*  next;
      UWord               func_id;
      UWord               bytes_read;
      UWord               bytes_written;
   }
   PG_Access;

static inline UWord hash_sdbm(Char *str)
{
  HWord hash = 0;
  int c;

  while ((c = *str++) != 0)
    hash = c + (hash << 6) + (hash << 16) - hash;
  
  return hash;
}

/* pg_main.c */
void PG_(dataobj_node_malloced)( Addr addr, SizeT size );
void PG_(dataobj_node_freed)( Addr addr );
PG_DataObj * PG_(dataobj_get_node)( Addr addr );

/* pg_malloc_wrappers.c */
void* PG_(malloc) (ThreadId tid, SizeT size);
void* PG_(__builtin_new)(ThreadId tid, SizeT size);
void* PG_(__builtin_vec_new) (ThreadId tid, SizeT size);
void* PG_(memalign) (ThreadId tid, SizeT alignB, SizeT size);
void* PG_(calloc) (ThreadId tid, SizeT nmemb, SizeT size1);
void PG_(free) (ThreadId tid, void* addr);
void PG_(__builtin_delete) (ThreadId tid, void* addr);
void PG_(__builtin_vec_delete) (ThreadId tid, void* addr);
void* PG_(realloc) (ThreadId tid, void* addr, SizeT new_size);
SizeT PG_(malloc_usable_size) (ThreadId tid, void* addr);

/* pg_util.c */
void initUnknownFunc(VgHashTable func_ht);
UWord getFuncId( Addr addr, VgHashTable func_ht);
Addr irConstToAddr(IRConst * con);
PG_Func * getFunc(UWord func_id);

#endif
