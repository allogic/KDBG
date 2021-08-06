/*
* @author allogic
* @file device.h
* @brief Communication device.
* @copyright allogic 2021. All Rights Reserved.
*/

#ifndef _DEVICE_H
#define _DEVICE_H

#include "global.h"

/*
* Communication device.
*/

NTSTATUS
CreateDevice(
  PDRIVER_OBJECT driver,
  PDEVICE_OBJECT* device,
  PCWCHAR deviceName,
  PCWCHAR symbolicName);

NTSTATUS
DeleteDevice(
  PDEVICE_OBJECT device,
  PCWCHAR symbolicName);

#endif