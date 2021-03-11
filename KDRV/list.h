#ifndef _LIST_H
#define _LIST_H

#include "global.h"

typedef struct _LIST_ENTRY
{
  PLIST_ENTRY Next;
  PVOID Data;
} LIST_ENTRY, * PLIST_ENTRY;

PLIST_ENTRY AllocateList();
VOID InsertEntry(PLIST_ENTRY list, PVOID data);
VOID FreeList(PLIST_ENTRY list);

#endif