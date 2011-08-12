/*--------------------------------------------------------------------*/
/*--- Privgrind: The Priv-seperation Valgrind tool.  pg_malloc_wrappers.c ---*/
/*--------------------------------------------------------------------*/

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_stacktrace.h"
#include "pub_tool_replacemalloc.h"  

#include "pg_include.h"

static void dataobj_node_freed( Addr addr ) {}
static void dataobj_node_malloced( Addr addr, SizeT size ) {}
static PG_DataObj * dataobj_get_node( Addr addr ) { return NULL; }

/* Allocate memory and note memory allocated */
static void* PG_(new_obj)  ( ThreadId tid, SizeT szB, SizeT alignB, 
			     Bool is_zeroed)
{
  ExeContext* ec;
  
  // Allocate and zero if necessary
  void *p = VG_(cli_malloc)( alignB, szB );
  if (!p) {
    return NULL;
  }
  if (is_zeroed) {
    VG_(memset)((void*)p, 0, szB);
  } 
  ec = VG_(record_ExeContext)(tid, 0/*first_ip_delta*/);
  tl_assert(ec);

  VG_(printf)("alloc %p size %d\n", p, (int)szB);
  dataobj_node_malloced((Addr)p, szB);
  
  return p;
}


static void PG_(handle_free) ( ThreadId tid, void *p )
{

  VG_(printf)("free %p\n", p);
  dataobj_node_freed( (Addr)p );

  VG_(cli_free) ( p );
}

void* PG_(malloc) (ThreadId tid, SizeT size) 
{
  return PG_(new_obj) ( tid, size, VG_(clo_alignment), False);
}

void* PG_(__builtin_new)(ThreadId tid, SizeT size)
{
  return PG_(new_obj) ( tid, size, VG_(clo_alignment), False);
}

void* PG_(__builtin_vec_new) (ThreadId tid, SizeT size)
{
  return PG_(new_obj) ( tid, size, VG_(clo_alignment), False);
}

void* PG_(memalign) (ThreadId tid, SizeT alignB, SizeT size)
{
  return PG_(new_obj) ( tid, size, alignB, False);
}

void* PG_(calloc) (ThreadId tid, SizeT nmemb, SizeT size1)
{
  return PG_(new_obj) ( tid, nmemb*size1, VG_(clo_alignment), True );
}

void PG_(free) (ThreadId tid, void* addr)
{
  PG_(handle_free) ( tid, addr );
}

void PG_(__builtin_delete) (ThreadId tid, void* addr)
{
  PG_(handle_free) ( tid, addr );
}

void PG_(__builtin_vec_delete) (ThreadId tid, void* addr)
{
  PG_(handle_free) ( tid, addr );
}

void* PG_(realloc) (ThreadId tid, void* addr, SizeT new_szB)
{
   PG_DataObj *obj;
   void       *p_new, *p_old;
   SizeT      old_szB;

   /* Get the old block info */
   obj = dataobj_get_node((Addr)addr);
   if (obj == NULL) {
      return NULL;
   }

   old_szB = obj->size;
   p_old   = (void*) obj->addr; 

   /* Get new memory */
   p_new = VG_(cli_malloc)(VG_(clo_alignment), new_szB);

   if (p_new) {
     /* Copy from old to new */
     VG_(memcpy)(p_new, p_old, new_szB <= old_szB ? new_szB : old_szB);
     
     /* free old address */
     VG_(cli_free) ( p_old );

     /* update data access node */
     obj->size = new_szB;
     obj->addr = (Addr)p_new;

   } else {
     /* free address and remove from database, we will be returning null */
     VG_(cli_free) ( p_old );
     dataobj_node_freed( (Addr) p_old );
   }

   return p_new;
}

SizeT PG_(malloc_usable_size) (ThreadId tid, void* addr)
{
  PG_DataObj *obj = dataobj_get_node((Addr)addr);
  return (obj->size);
}
                                   
