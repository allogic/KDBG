/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_Test,
    0x21e61ff6,0x2a91,0x49f2,0x8f,0x10,0xa6,0x03,0x27,0x5f,0x87,0x0f);
// {21e61ff6-2a91-49f2-8f10-a603275f870f}
