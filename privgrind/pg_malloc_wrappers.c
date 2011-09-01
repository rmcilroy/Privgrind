/*--------------------------------------------------------------------*/
/*--- Privgrind: The Priv-seperation Valgrind tool.  pg_malloc_wrappers.c ---*/
/*--------------------------------------------------------------------*/

#include "pg_include.h"
#include "pub_tool_replacemalloc.h"
#include "assert.h"

#define DEFAULT_ALIGN 16

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
  PG_(dataobj_node_malloced)( (Addr) p, szB );

  return p;
}


static void PG_(handle_free) ( ThreadId tid, void *p )
{
  PG_(dataobj_node_freed)( (Addr) p );
  VG_(cli_free) ( p );
}

void* PG_(malloc) (ThreadId tid, SizeT size) 
{
  return PG_(new_obj) ( tid, size, DEFAULT_ALIGN, False);
}

void* PG_(__builtin_new)(ThreadId tid, SizeT size)
{
  return PG_(new_obj) ( tid, size, DEFAULT_ALIGN, False);
}

void* PG_(__builtin_vec_new) (ThreadId tid, SizeT size)
{
  return PG_(new_obj) ( tid, size, DEFAULT_ALIGN, False);
}

void* PG_(memalign) (ThreadId tid, SizeT alignB, SizeT size)
{
  return PG_(new_obj) ( tid, size, alignB, False);
}

void* PG_(calloc) (ThreadId tid, SizeT nmemb, SizeT size1)
{
  return PG_(new_obj) ( tid, nmemb*size1, DEFAULT_ALIGN, True );
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
   obj = PG_(dataobj_get_node)((Addr)addr);
   if (obj == NULL) {
      return NULL;
   }

   obj = PG_(dataobj_get_node)( (Addr) addr );
   p_old   = addr; 
   old_szB = obj->size;

   /* Get new memory */
   p_new = VG_(cli_malloc)(DEFAULT_ALIGN, new_szB);

   if (p_new) {
     /* Copy from old to new */
     VG_(memcpy)(p_new, p_old, new_szB <= old_szB ? new_szB : old_szB);
     
     /* free old address */
     VG_(cli_free) ( p_old );

     /* update data access node */
     obj->addr = (Addr)p_new;
     obj->size = new_szB;
   } else {
     /* remove old address from live database */
     PG_(dataobj_node_freed)( (Addr) addr );
   }
   
   /* free old address */
   VG_(cli_free) ( p_old );

   return p_new;
}

SizeT PG_(malloc_usable_size) (ThreadId tid, void* addr)
{
  PG_DataObj * addr_node = PG_(dataobj_get_node)( (Addr) addr );
  return (addr_node->size);
}
                                   
