#ifndef KM_DEBUG_H
#define KM_DEBUG_H

#include <km_core.h>

///////////////////////////////////////////////////////////
// Debug utilities
///////////////////////////////////////////////////////////

#ifndef DBG
#define KD_LOG(FMT, ...)
#else
#define KD_LOG(FMT, ...) DbgPrintEx(0, 0, FMT, __VA_ARGS__)
#endif

#endif
