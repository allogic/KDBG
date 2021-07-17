#ifndef _LIST_H
#define _LIST_H

#include "global.h"

typedef struct _LIST_NODE
{
  PLIST_NODE Next;
  PVOID Data;
} LIST_NODE, * PLIST_NODE;

template<typename TYPE>
static void Insert(PLIST_NODE tail, TYPE& data)
{
  if (list)
  {
    list = (TYPE*)malloc(sizeof())
  }
  else
  {

  }
}
static void Delete(PLIST_NODE head)
{
  
  while (head->Next)
  {

  }
}

#endif