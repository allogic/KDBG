#ifndef _DEVICE_H
#define _DEVICE_H

#include "global.h"

/*
* Communication device.
*/

VOID CreateDevice(PDRIVER_OBJECT driver, PDEVICE_OBJECT& device, PCWCHAR deviceName, PCWCHAR symbolicName);
VOID DeleteDevice(PDEVICE_OBJECT device, PCWCHAR symbolicName);

#endif