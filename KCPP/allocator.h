#ifndef _ALLOCATOR_H
#define _ALLOCATOR_H

#include "global.h"
#include "random.h"

void* operator new (size_t size);

void operator delete (void* ptr);
void operator delete[] (void* ptr);

#endif