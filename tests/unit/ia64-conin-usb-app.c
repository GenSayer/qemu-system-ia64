/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Minimal IA-64 EFI application used by the firmware USB keyboard test. */

typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned int UINT32;
typedef unsigned long UINT64;
typedef unsigned long UINTN;
typedef unsigned short CHAR16;
typedef UINT64 EFI_STATUS;
typedef void VOID;
typedef VOID *EFI_HANDLE;
typedef VOID *EFI_EVENT;

#define EFI_SUCCESS 0
#define EFI_NOT_READY (0x8000000000000000ULL | 6U)
#define EFI_DEVICE_ERROR (0x8000000000000000ULL | 7U)

typedef struct {
    UINT64 Signature;
    UINT32 Revision;
    UINT32 HeaderSize;
    UINT32 Crc32;
    UINT32 Reserved;
} EFI_TABLE_HEADER;

typedef struct {
    UINT16 ScanCode;
    CHAR16 UnicodeChar;
} EFI_INPUT_KEY;

typedef struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL EFI_SIMPLE_TEXT_INPUT_PROTOCOL;
struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL {
    EFI_STATUS (*Reset)(EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,
                        UINT8 ExtendedVerification);
    EFI_STATUS (*ReadKeyStroke)(EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,
                                EFI_INPUT_KEY *Key);
    EFI_EVENT WaitForKey;
};

typedef struct _EFI_SIMPLE_TEXT_OUT_PROTOCOL EFI_SIMPLE_TEXT_OUT_PROTOCOL;
struct _EFI_SIMPLE_TEXT_OUT_PROTOCOL {
    EFI_STATUS (*Reset)(EFI_SIMPLE_TEXT_OUT_PROTOCOL *This,
                        UINT8 ExtendedVerification);
    EFI_STATUS (*OutputString)(EFI_SIMPLE_TEXT_OUT_PROTOCOL *This,
                               CHAR16 *String);
    VOID *TestString;
    VOID *QueryMode;
    VOID *SetMode;
    VOID *SetAttribute;
    VOID *ClearScreen;
    VOID *SetCursorPosition;
    VOID *EnableCursor;
    VOID *Mode;
};

typedef struct _EFI_BOOT_SERVICES EFI_BOOT_SERVICES;
typedef EFI_STATUS EFI_EXIT(EFI_HANDLE ImageHandle,
                            EFI_STATUS ExitStatus,
                            UINTN ExitDataSize,
                            CHAR16 *ExitData);
struct _EFI_BOOT_SERVICES {
    EFI_TABLE_HEADER Hdr;
    VOID *RaiseTpl;
    VOID *RestoreTpl;
    VOID *AllocatePages;
    VOID *FreePages;
    VOID *GetMemoryMap;
    VOID *AllocatePool;
    VOID *FreePool;
    VOID *CreateEvent;
    VOID *SetTimer;
    VOID *WaitForEvent;
    VOID *SignalEvent;
    VOID *CloseEvent;
    VOID *CheckEvent;
    VOID *InstallProtocolInterface;
    VOID *ReinstallProtocolInterface;
    VOID *UninstallProtocolInterface;
    VOID *HandleProtocol;
    VOID *Reserved;
    VOID *RegisterProtocolNotify;
    VOID *LocateHandle;
    VOID *LocateDevicePath;
    VOID *InstallConfigurationTable;
    VOID *LoadImage;
    VOID *StartImage;
    EFI_EXIT *Exit;
    VOID *UnloadImage;
    VOID *ExitBootServices;
    VOID *GetNextMonotonicCount;
    EFI_STATUS (*Stall)(UINTN Microseconds);
};

typedef struct {
    EFI_TABLE_HEADER Hdr;
    CHAR16 *FirmwareVendor;
    UINT32 FirmwareRevision;
    EFI_HANDLE ConsoleInHandle;
    EFI_SIMPLE_TEXT_INPUT_PROTOCOL *ConIn;
    EFI_HANDLE ConsoleOutHandle;
    EFI_SIMPLE_TEXT_OUT_PROTOCOL *ConOut;
    EFI_HANDLE StandardErrorHandle;
    VOID *StdErr;
    VOID *RuntimeServices;
    EFI_BOOT_SERVICES *BootServices;
    UINTN NumberOfTableEntries;
    VOID *ConfigurationTable;
} EFI_SYSTEM_TABLE;

static CHAR16 waiting_message[] = {
    'I', 'A', '6', '4', ' ', 'U', 'S', 'B', ' ', 'K', 'B', 'D', ':', ' ',
    'w', 'a', 'i', 't', 'i', 'n', 'g', '\r', '\n', 0,
};

static CHAR16 success_message[] = {
    'I', 'A', '6', '4', ' ', 'U', 'S', 'B', ' ', 'K', 'B', 'D', ':', ' ',
    'r', 'e', 'a', 'd', ' ', 'x', '\r', '\n', 0,
};

static CHAR16 unexpected_message[] = {
    'I', 'A', '6', '4', ' ', 'U', 'S', 'B', ' ', 'K', 'B', 'D', ':', ' ',
    'u', 'n', 'e', 'x', 'p', 'e', 'c', 't', 'e', 'd', ' ', 'k', 'e', 'y',
    '\r', '\n', 0,
};

static CHAR16 failure_message[] = {
    'I', 'A', '6', '4', ' ', 'U', 'S', 'B', ' ', 'K', 'B', 'D', ':', ' ',
    'f', 'a', 'i', 'l', 'e', 'd', '\r', '\n', 0,
};

static void output(EFI_SYSTEM_TABLE *system_table, CHAR16 *message)
{
    if (system_table != (VOID *)0 && system_table->ConOut != (VOID *)0) {
        system_table->ConOut->OutputString(system_table->ConOut, message);
    }
}

EFI_STATUS efi_main(EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *system_table)
{
    UINTN attempt;

    if (system_table == (VOID *)0 || system_table->ConIn == (VOID *)0 ||
        system_table->BootServices == (VOID *)0 ||
        system_table->BootServices->Exit == (VOID *)0) {
        return EFI_DEVICE_ERROR;
    }

    output(system_table, waiting_message);

    for (attempt = 0; attempt < 10000U; attempt++) {
        EFI_INPUT_KEY key;
        EFI_STATUS status;

        key.ScanCode = 0;
        key.UnicodeChar = 0;
        status = system_table->ConIn->ReadKeyStroke(system_table->ConIn, &key);
        if (status == EFI_SUCCESS) {
            if (key.ScanCode == 0 &&
                (key.UnicodeChar == 'x' || key.UnicodeChar == 'X')) {
                output(system_table, success_message);
                status = system_table->BootServices->Exit(
                    image_handle, EFI_SUCCESS, 0, (VOID *)0);
                output(system_table, failure_message);
                return status;
            }
            output(system_table, unexpected_message);
            return EFI_DEVICE_ERROR;
        }
        if (status != EFI_NOT_READY) {
            output(system_table, failure_message);
            return status;
        }
        if (system_table->BootServices->Stall != 0) {
            system_table->BootServices->Stall(1000U);
        }
    }

    output(system_table, failure_message);
    return EFI_DEVICE_ERROR;
}

/* Force emission of the IA-64 function descriptor required by PE/COFF. */
EFI_STATUS (*efi_entry_descriptor_reference)(EFI_HANDLE, EFI_SYSTEM_TABLE *)
    __attribute__((used)) = efi_main;
