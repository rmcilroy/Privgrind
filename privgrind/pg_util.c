/* Utility functions for PrivGrind */

#include <string.h>
#include "pg_include.h"

static int curr_func_id = UNKNOWN_FUNC_ID;
static PG_Func ** func_array = NULL;
static Int func_array_len = 0;

static void addFunc(PG_Func * func) {
  if (func_array == NULL || func->id >= func_array_len) {
    // resize array
    if (func_array == NULL) {
      func_array_len = 128;
    } else {
      func_array_len <<= 1;
    }
    func_array = VG_(realloc)("func_array", func_array, 
			      func_array_len * sizeof(PG_Func *));
  }
  func_array[func->id] = func;
}

PG_Func * getFunc(UWord func_id) {
  tl_assert(func_id < func_array_len);
  return func_array[func_id];
}

void initUnknownFunc(VgHashTable func_ht) 
{
   PG_Func *func = VG_(malloc) ("func_ht.node", sizeof (PG_Func));
   func->fnname = "<Unknown>";
   func->filename = "";
   func->dirname = "";
   func->key = hash_sdbm(func->fnname);
   func->id = curr_func_id++;
   tl_assert(func->id == UNKNOWN_FUNC_ID);
   func->calls_ht = VG_(HT_construct) ( "calls_hash" );
   VG_(HT_add_node) ( func_ht, func );
   addFunc(func);
}

UWord getFuncId( Addr addr, VgHashTable func_ht)
{
  UWord func_id;
  Char fnname[FN_LENGTH];
  Bool found_fn = VG_(get_fnname)(addr, fnname, FN_LENGTH);
  if (!found_fn) {
    func_id = UNKNOWN_FUNC_ID;
  } else {
    UWord key = hash_sdbm(fnname);
    PG_Func * func = VG_(HT_lookup) ( func_ht, key );
    if (func == NULL) {
      UInt linenum;
      Bool dirname_available;
      func = VG_(malloc) ("func_ht.node", sizeof (PG_Func));
      func->key = key;
      func->id = curr_func_id++;
      func->fnname = VG_(malloc) ("func_ht.node.fnname", strlen(fnname));
      func->filename = VG_(malloc)("func_ht.node.filename", FILENAME_LENGTH);
      func->dirname  = VG_(malloc)("func_ht.node.dirname", DIRNAME_LENGTH);
      memcpy(func->fnname, fnname, strlen(fnname));
      VG_(get_filename_linenum) ( addr, func->filename, FILENAME_LENGTH,
				  func->dirname,  DIRNAME_LENGTH,
				  &dirname_available, &linenum );
      func->calls_ht = VG_(HT_construct) ( "calls_hash" );
      VG_(HT_add_node) ( func_ht, func );
      addFunc(func);
    }
    func_id = func->id;
  }
  return func_id;
}

Addr irConstToAddr(IRConst * con) {
  switch (con->tag) {
  case Ico_U8:
    return (Addr) con->Ico.U8;
  case Ico_U16:
    return (Addr) con->Ico.U16;
  case Ico_U32:
    return (Addr) con->Ico.U32;
  case Ico_U64:
    tl_assert (sizeof(Addr) >= sizeof(ULong));
    return (Addr) con->Ico.U64;
  default:
    VG_(printf)("Constant with type %d not compatible with Addr\n", con->tag);
    tl_assert(0);
  }
  return 0;
}
