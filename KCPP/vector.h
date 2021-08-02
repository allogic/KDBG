#ifndef _VECTOR_H
#define _VECTOR_H

#include "global.h"
#include "allocator.h"

template<typename T>
struct Vector
{
  T* Buffer = nullptr;
  size_t Size = 0;

  Vector()
  {

  }
  Vector(size_t size)
    : Buffer{ new T[size] }
    , Size{ size }
  {

  }

  T& operator [] (size_t index)
  {
    return Buffer[index];
  }

  void Clear()
  {
    memset(Buffer, 0, Size);
    Size = 0;
  }
  void Resize(SIZE_T size)
  {
    T* tmp = new T[size];
    memcpy(tmp, Buffer, Size);
    delete[] Buffer;
    Buffer = new T[size];
    Size = size;
    memcpy(Buffer, tmp, Size);
    delete[] tmp;
  }
  void Push(T const& value)
  {
    Resize(Size + 1);
    memcpy(Buffer[Size], &value, sizeof(T));
    Size++;
  }
  void Pop()
  {
    Resize(Size - 1);
    Size--;
  }
  size_t Length()
  {
    return Size;
  }
};

#endif