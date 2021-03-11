#include "list.h"

PLIST_ENTRY AllocateList()
{
  PLIST_ENTRY list = (PLIST_ENTRY)RtlAllocateMemory(TRUE, sizeof(LIST_ENTRY));
  return list;
}

VOID InsertEntry(PLIST_ENTRY list, PVOID data)
{
  while (list->Next)
  {
    list = list->Next;
  }
}

VOID FreeList(PLIST_ENTRY list)
{
  while (list->Next)
  {
    RtlFreeMemory(list->Data);
  }
}