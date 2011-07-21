/*--------------------------------------------------------------------*/
/*--- Privgrind: The Priv-seperation Valgrind tool.   pg_include.h ---*/
/*--------------------------------------------------------------------*/

#ifndef __PG_INCLUDE__
#define __PG_INCLUDE__

#include "pub_tool_hashtable.h"

/* This describes a function. Nb: first two fields must match core's
 * VgHashNode. */
typedef
   struct _PG_Func {
      struct _PG_Func*  next;
      UWord             key;            
      Char *            fnname;
      UWord             id;
   }
   PG_Func;

/* This describes access to a data object. Nb: first two fields must match 
 * core's VgHashNode. */
typedef
   struct _PG_Addr {
      struct _PG_Addr*  next;
      UWord             addr;  
      VgHashTable       access_ht;
   }
   PG_Addr;

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

#endif
