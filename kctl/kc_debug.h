#ifndef KC_DEBUG_H
#define KC_DEBUG_H

#include <kc_core.h>

///////////////////////////////////////////////////////////
// Debug utilities
///////////////////////////////////////////////////////////

#ifdef NDEBUG
#define KD_LOG(FMT, ...)
#else
#define KD_LOG(FMT, ...) printf(FMT, __VA_ARGS__)
#endif

#endif