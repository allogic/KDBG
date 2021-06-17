#ifndef _DEVICE_H
#define _DEVICE_H

#include "global.h"

NTSTATUS CreateDevice(PDRIVER_OBJECT driver, PDEVICE_OBJECT& device, PUNICODE_STRING deviceName, PUNICODE_STRING symbolicName);
NTSTATUS DeleteDevice(PDEVICE_OBJECT device, PUNICODE_STRING symbolicName);

#endif