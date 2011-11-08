/*
 * divert.c
 * (C) 2011, all rights reserved,
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <wdf.h>
#include <stdarg.h>
#include <ntstrsafe.h>

#include "divert_device.h"

/*
 * WDK function declaration cruft.
 */
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD divert_unload;
EVT_WDF_IO_IN_CALLER_CONTEXT divert_caller_context;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL divert_ioctl;
EVT_WDF_DEVICE_FILE_CREATE divert_create;
EVT_WDF_TIMER divert_timer;
EVT_WDF_FILE_CLEANUP divert_cleanup;
EVT_WDF_FILE_CLOSE divert_close;

/*
 * Debugging macros.
 */
// #define DEBUG_ON
#define DEBUG_BUFSIZE       512

#ifdef DEBUG_ON
static void DEBUG(PCCH format, ...)
{
    va_list args;
    char buf[DEBUG_BUFSIZE+1];
    va_start(args, format);
    RtlStringCbVPrintfA(buf, DEBUG_BUFSIZE, format, args);
    DbgPrint("DIVERT: %s", buf);
    va_end(args);
}
static void DEBUG_ERROR(PCCH format, NTSTATUS status, ...)
{
    va_list args;
    char buf[DEBUG_BUFSIZE+1];
    va_start(args, status);
    RtlStringCbVPrintfA(buf, DEBUG_BUFSIZE, format, args);
    DbgPrint("DIVERT: *** ERROR ***: (status = %x): %s", status, buf);
    va_end(args);
}
#else       // DEBUG_ON
#define DEBUG(format, ...)
#define DEBUG_ERROR(format, status, ...)
#endif      // DEBUG_ON

/*
 * Packet filter.
 */
struct filter_s
{
    UINT8  protocol:4;                      // field's protocol
    UINT8  test:4;                          // Filter test
    UINT8  field;                           // Field of interest
    UINT8  success;                         // Success continuation
    UINT8  failure;                         // Fail continuation
    UINT32 arg[4];                          // Comparison argument
};
typedef struct filter_s *filter_t;
#define DIVERT_FILTER_PROTOCOL_NONE         0
#define DIVERT_FILTER_PROTOCOL_IP           1
#define DIVERT_FILTER_PROTOCOL_IPV6         2
#define DIVERT_FILTER_PROTOCOL_ICMP         3
#define DIVERT_FILTER_PROTOCOL_ICMPV6       4
#define DIVERT_FILTER_PROTOCOL_TCP          5
#define DIVERT_FILTER_PROTOCOL_UDP          6

/*
 * Context information.
 */
#define DIVERT_CONTEXT_MAGIC                0xB75D18F185A65197ull
#define DIVERT_CONTEXT_SIZE                 (sizeof(struct context_s))
#define DIVERT_CONTEXT_QUEUE_MAXLENGTH      1024
#define DIVERT_CONTEXT_NUMLAYERS            4
#define DIVERT_CONTEXT_OUTBOUND_IPV4_LAYER  0
#define DIVERT_CONTEXT_INBOUND_IPV4_LAYER   1
#define DIVERT_CONTEXT_OUTBOUND_IPV6_LAYER  2
#define DIVERT_CONTEXT_INBOUND_IPV6_LAYER   3
typedef enum
{
    DIVERT_CONTEXT_STATE_OPENING = 0xA0,    // Context is opening.
    DIVERT_CONTEXT_STATE_OPEN    = 0xB1,    // Context is open.
    DIVERT_CONTEXT_STATE_CLOSING = 0xC2,    // Context is closing.
    DIVERT_CONTEXT_STATE_CLOSED  = 0xD3,    // Context is closed.
    DIVERT_CONTEXT_STATE_INVALID = 0xE4     // Context is invalid.
} context_state_t;
struct context_s
{
    UINT64 magic;                           // DIVERT_CONTEXT_MAGIC
    context_state_t state;                  // Context's state.
    KSPIN_LOCK lock;                        // Context-wide lock.
    WDFDEVICE device;                       // Context's device.
    LIST_ENTRY packet_queue;                // Packet queue.
    ULONG packet_queue_length;              // Packet queue length.
    ULONG packet_queue_maxlength;           // Packet queue max length.
    WDFTIMER timer;                         // Packet timer.
    BOOL timer_ticktock;                    // Packet timer ticktock.
    NDIS_HANDLE pool_handle;                // NET_BUFFER_LIST pool handle.
    WDFQUEUE read_queue;                    // Read queue.
    GUID sublayer_guid[DIVERT_CONTEXT_NUMLAYERS];
                                            // Sublayer GUIDs.
    GUID callout_guid[DIVERT_CONTEXT_NUMLAYERS];
                                            // Callout GUIDs.
    GUID filter_guid[DIVERT_CONTEXT_NUMLAYERS];
                                            // Filter GUIDs.
    BOOL registered[DIVERT_CONTEXT_NUMLAYERS];
                                            // What is registered?
    HANDLE engine_handle;                   // WFP engine handle.
    LONG filter_on;                         // Is filter on?
    struct filter_s filter[DIVERT_FILTER_MAXLEN];
                                            // Packet filter.
};
typedef struct context_s context_s;
typedef struct context_s *context_t;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(context_s, divert_context_get);

/*
 * Request context.
 */
struct req_context_s
{
    struct divert_addr_s *addr;             // Pointer to address structure.
};
typedef struct req_context_s req_context_s;
typedef struct req_context_s *req_context_t;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(req_context_s, divert_req_context_get);

/*
 * Packets
 */
#define DIVERT_PACKET_TAG               'Pvid'
#define DIVERT_PACKET_SIZE              (sizeof(struct packet_s))
#define DIVERT_PACKET_TIMEOUT           128
struct packet_s
{
    LIST_ENTRY entry;                       // Entry for queue
    PNET_BUFFER buffer;                     // The packet
    PNET_BUFFER_LIST buffers;               // The NBL contain the packet
    UINT8 direction;                        // Packet direction
    UINT32 if_idx;                          // Interface index
    UINT32 sub_if_idx;                      // Sub-interface index
    BOOL ip_checksum;                       // IP checksum is valid
    BOOL tcp_checksum;                      // TCP checksum is valid
    BOOL udp_checksum;                      // UDP checksum is valid
    BOOL timer_ticktock;                    // Time-out ticktock
};
typedef struct packet_s *packet_t;
#define DIVERT_NET_BUFFER_LIST_TAG      'Lvid'

/*
 * Address definition.
 */
struct divert_addr_s
{
    UINT32 IfIdx;
    UINT32 SubIfIdx;
    UINT8  Direction;
};
typedef struct divert_addr_s *divert_addr_t;

/*
 * Header definitions.
 */
struct iphdr
{
    UINT8  HdrLength:4;
    UINT8  Version:4;
    UINT8  TOS;
    UINT16 Length;
    UINT16 Id;
    UINT16 FragOff0;
    UINT8  TTL;
    UINT8  Protocol;
    UINT16 Checksum;
    UINT32 SrcAddr;
    UINT32 DstAddr;
};
struct ipv6hdr
{
    UINT8  TrafficClass0:4;
    UINT8  Version:4;
    UINT8  FlowLabel0:4;
    UINT8  TrafficClass1:4;
    UINT16 FlowLabel1;
    UINT16 Length;
    UINT8  NextHdr;
    UINT8  HopLimit;
    UINT32 SrcAddr[4];
    UINT32 DstAddr[4];
};
struct icmphdr
{
    UINT8  Type;
    UINT8  Code;
    UINT16 Checksum;
    UINT32 Body;
};
struct icmpv6hdr
{
    UINT8  Type;
    UINT8  Code;
    UINT16 Checksum;
    UINT32 Body;
};
struct tcphdr
{
    UINT16 SrcPort;
    UINT16 DstPort;
    UINT32 SeqNum;
    UINT32 AckNum;
    UINT16 Reserved1:4;
    UINT16 HdrLength:4;
    UINT16 Fin:1;
    UINT16 Syn:1;
    UINT16 Rst:1;
    UINT16 Psh:1;
    UINT16 Ack:1;
    UINT16 Urg:1;
    UINT16 Reserved2:2;
    UINT16 Window;
    UINT16 Checksum;
    UINT16 UrgPtr;
};
struct udphdr
{
    UINT16 SrcPort;
    UINT16 DstPort;
    UINT16 Length;
    UINT16 Checksum;
};

#define IPHDR_GET_FRAGOFF(hdr)          (((hdr)->FragOff0) & 0xFF1F)
#define IPHDR_GET_MF(hdr)               (((hdr)->FragOff0) & 0x0020)
#define IPHDR_GET_DF(hdr)               (((hdr)->FragOff0) & 0x0040)
#define IPV6HDR_GET_TRAFFICCLASS(hdr)   \
    ((((hdr)->TrafficClass0) << 4) | ((hdr)->TrafficClass1))
#define IPV6HDR_GET_FLOWLABEL(hdr)      \
    ((((UINT32)(hdr)->FlowLabel0) << 16) | ((UINT32)(hdr)->FlowLabel1))

/*
 * Misc.
 */
#define UINT8_MAX       0xFF
#define UINT16_MAX      0xFFFF

typedef void (*divert_callout_t)(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);

/*
 * Global packet injection handles.
 */
HANDLE inject_handle;
HANDLE injectv6_handle;

#define DIVERT_PACKET_ALLOW         ((HANDLE)0)
#define DIVERT_PACKET_INJECTED      ((HANDLE)1)

/*
 * Prototypes.
 */
extern VOID divert_ioctl(IN WDFQUEUE queue, IN WDFREQUEST request,
    IN size_t in_length, IN size_t out_len, IN ULONG code);
extern NTSTATUS divert_read(context_t context, WDFREQUEST request);
static void divert_read_service(context_t context);
static BOOLEAN divert_context_verify(context_t context, context_state_t state);
extern VOID divert_create(IN WDFDEVICE device, IN WDFREQUEST request,
    IN WDFFILEOBJECT object);
static NTSTATUS divert_register_callouts(context_t context, BOOL is_inbound,
    BOOL is_outbound, BOOL is_ipv4, BOOL is_ipv6);
static NTSTATUS divert_register_callout(context_t context, UINT idx,
    BOOL is_inbound, BOOL is_outbound, BOOL is_ipv4, BOOL is_ipv6);
extern VOID divert_timer(IN WDFTIMER timer);
extern VOID divert_cleanup(IN WDFFILEOBJECT object);
extern VOID divert_close(IN WDFFILEOBJECT object);
extern NTSTATUS divert_write(context_t context, WDFREQUEST request,
    divert_addr_t addr);
extern void NTAPI divert_inject_complete(VOID *context,
    NET_BUFFER_LIST *packets, BOOLEAN dispatch_level);
static NTSTATUS divert_notify_callout(IN FWPS_CALLOUT_NOTIFY_TYPE type,
    IN const GUID *filter_key, IN const FWPS_FILTER0 *filter);
static void divert_classify_outbound_v4_callout(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void divert_classify_inbound_v4_callout(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void divert_classify_outbound_v6_callout(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void divert_classify_inbound_v6_callout(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void divert_classify_callout(IN UINT8 direction, IN UINT32 if_idx,
    IN UINT32 sub_if_idx, IN BOOL isipv4,
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static BOOL divert_reinject_packet(context_t context, UINT8 direction,
    BOOL isipv4, UINT32 if_idx, UINT32 sub_if_idx, PNET_BUFFER_LIST buffers,
    PNET_BUFFER buffer);
static void NTAPI divert_reinject_complete(VOID *context,
    NET_BUFFER_LIST *buffers_cpy, BOOLEAN dispatch_level);
static BOOL divert_queue_packet(context_t context, PNET_BUFFER_LIST buffers,
    PNET_BUFFER buffer, UINT8 direction, UINT32 if_idx, UINT32 sub_if_idx);
static UINT16 divert_checksum(const void *pseudo_header,
    size_t pseudo_header_len, const void *data, size_t size);
static void divert_update_checksums(void *header, size_t len,
    BOOL update_ip, BOOL update_tcp, BOOL update_udp);
static BOOL divert_filter(PNET_BUFFER buffer, UINT32 if_idx, UINT32 sub_if_idx,
    BOOL outbound, filter_t filter);
static BOOL divert_filter_compile(divert_ioctl_filter_t ioctl_filter,
    size_t ioctl_filter_len, filter_t filter);
static void divert_filter_analyze(filter_t filter, BOOL *is_inbound,
    BOOL *is_outbound, BOOL *ip_ipv4, BOOL *is_ipv6);
static BOOL divert_filter_test(filter_t filter, UINT8 ip, UINT8 protocol,
    UINT8 field, UINT32 arg);

/*
 * Driver entry routine.
 */
extern NTSTATUS DriverEntry(IN PDRIVER_OBJECT driver_obj,
    IN PUNICODE_STRING reg_path)
{
    WDF_DRIVER_CONFIG config;
    WDFDRIVER driver;
    PWDFDEVICE_INIT device_init;
    WDFDEVICE device;
    WDF_FILEOBJECT_CONFIG file_config;
    WDF_IO_QUEUE_CONFIG queue_config;
    WDFQUEUE queue;
    WDF_OBJECT_ATTRIBUTES obj_attrs;
    NTSTATUS status;
    DECLARE_CONST_UNICODE_STRING(device_name, DIVERT_DEVICE_NAME);
    DECLARE_CONST_UNICODE_STRING(dos_device_name, DIVERT_DOS_DEVICE_NAME);

    DEBUG("LOAD: loading divert driver");

    // Configure ourself as a non-PnP driver:
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = divert_unload;
    status = WdfDriverCreate(driver_obj, reg_path, WDF_NO_OBJECT_ATTRIBUTES,
        &config, &driver);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WDF driver", status);
        return status;
    }
    device_init = WdfControlDeviceInitAllocate(driver,
        &SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RW_RES_R);
    if (device_init == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DEBUG_ERROR("failed to allocate WDF control device init structure",
            status);
        return status;
    }
    WdfDeviceInitSetDeviceType(device_init, FILE_DEVICE_NETWORK);
    WdfDeviceInitSetIoType(device_init, WdfDeviceIoDirect);
    status = WdfDeviceInitAssignName(device_init, &device_name);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WDF device name", status);
        WdfDeviceInitFree(device_init);
        return status;
    }
    WDF_FILEOBJECT_CONFIG_INIT(&file_config, divert_create, divert_close,
        divert_cleanup);
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&obj_attrs, context_s);
    WdfDeviceInitSetFileObjectConfig(device_init, &file_config, &obj_attrs);
    WdfDeviceInitSetIoInCallerContextCallback(device_init,
        divert_caller_context);
    WDF_OBJECT_ATTRIBUTES_INIT(&obj_attrs);
    status = WdfDeviceCreate(&device_init, &obj_attrs, &device);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WDF control device", status);
        WdfDeviceInitFree(device_init);
        return status;
    }
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue_config,
        WdfIoQueueDispatchParallel);
    queue_config.EvtIoRead          = NULL;
    queue_config.EvtIoWrite         = NULL;
    queue_config.EvtIoDeviceControl = divert_ioctl;
    WDF_OBJECT_ATTRIBUTES_INIT(&obj_attrs);
    status = WdfIoQueueCreate(device, &queue_config, &obj_attrs, &queue);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create default WDF queue", status);
        return status;
    }
    status = WdfDeviceCreateSymbolicLink(device, &dos_device_name);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create device symbolic link", status);
        return status;
    }
    WdfControlFinishInitializing(device);

    // Create the packet injection handles.
    status = FwpsInjectionHandleCreate0(AF_INET,
        FWPS_INJECTION_TYPE_NETWORK, &inject_handle);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WFP packet injection handle", status);
        return status;
    }
    status = FwpsInjectionHandleCreate0(AF_INET6,
        FWPS_INJECTION_TYPE_NETWORK, &injectv6_handle);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WFP ipv6 packet injection handle",
            status);
        return status;
    }

    return STATUS_SUCCESS;
}

/*
 * Driver unload routine.
 */
extern VOID divert_unload(IN WDFDRIVER Driver)
{
    DEBUG("UNLOAD: unloading the divert driver");
    FwpsInjectionHandleDestroy0(inject_handle);
    FwpsInjectionHandleDestroy0(injectv6_handle);
}

/*
 * Divert context verify.
 */
static BOOLEAN divert_context_verify(context_t context, context_state_t state)
{
    if (context == NULL)
    {
        DEBUG_ERROR("failed to verify context; context is NULL",
            STATUS_INVALID_HANDLE);
        return FALSE;
    }
    if (context->magic != DIVERT_CONTEXT_MAGIC)
    {
        DEBUG_ERROR("failed to verify context; invalid magic number",
            STATUS_INVALID_HANDLE);
        return FALSE;
    }
    if (context->state != state)
    {
        DEBUG_ERROR("failed to verify context; expected context state %x, "
            "found context state %x", STATUS_INVALID_HANDLE, state,
            context->state);
        return FALSE;
    }
    return TRUE;
}

/*
 * Divert create routine.
 */
extern VOID divert_create(IN WDFDEVICE device, IN WDFREQUEST request,
    IN WDFFILEOBJECT object)
{
    NET_BUFFER_LIST_POOL_PARAMETERS pool_params;
    WDF_IO_QUEUE_CONFIG queue_config;
    WDF_TIMER_CONFIG timer_config;
    WDF_OBJECT_ATTRIBUTES timer_attributes;
    FWPM_SESSION0 session;
    NTSTATUS status = STATUS_SUCCESS;
    UINT8 i;
    context_t context = divert_context_get(object);

    DEBUG("CREATE: creating a new divert context (context=%p)", context);

    // Initialise the new context:
    context->magic  = DIVERT_CONTEXT_MAGIC;
    context->state  = DIVERT_CONTEXT_STATE_OPENING;
    context->device = device;
    context->packet_queue_length = 0;
    context->packet_queue_maxlength = DIVERT_CONTEXT_QUEUE_MAXLENGTH;
    for (i = 0; i < DIVERT_FILTER_MAXLEN; i++)
    {
        context->filter[i].protocol = DIVERT_FILTER_PROTOCOL_NONE;
        context->filter[i].field    = DIVERT_FILTER_FIELD_ZERO;
        context->filter[i].test     = DIVERT_FILTER_TEST_EQ;
        context->filter[i].arg[0]   = 0;
        context->filter[i].arg[1]   = 0;
        context->filter[i].arg[2]   = 0;
        context->filter[i].arg[3]   = 0;
        context->filter[i].success  = DIVERT_FILTER_RESULT_REJECT;
        context->filter[i].failure  = DIVERT_FILTER_RESULT_REJECT;
    }
    for (i = 0; i < DIVERT_CONTEXT_NUMLAYERS; i++)
    {
        context->registered[i] = FALSE;
    }
    context->filter_on = FALSE;
    KeInitializeSpinLock(&context->lock);
    InitializeListHead(&context->packet_queue);
    for (i = 0; i < DIVERT_CONTEXT_NUMLAYERS; i++)
    {
        status = ExUuidCreate(&context->sublayer_guid[i]);
        if (!NT_SUCCESS(status))
        {
            DEBUG_ERROR("failed to create sub-layer GUID", status);
            goto divert_create_exit;
        }
        status = ExUuidCreate(&context->callout_guid[i]);
        if (!NT_SUCCESS(status))
        {
            DEBUG_ERROR("failed to create callout GUID", status);
            goto divert_create_exit;
        }
        status = ExUuidCreate(&context->filter_guid[i]);
        if (!NT_SUCCESS(status))
        {
            DEBUG_ERROR("failed to create filter GUID", status);
            goto divert_create_exit;
        }
    }
    RtlZeroMemory(&pool_params, sizeof(pool_params));
    pool_params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    pool_params.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    pool_params.Header.Size = sizeof(pool_params);
    pool_params.fAllocateNetBuffer = TRUE;
    pool_params.PoolTag = DIVERT_NET_BUFFER_LIST_TAG;
    pool_params.DataSize = 0;
    context->pool_handle = NdisAllocateNetBufferListPool(NULL, &pool_params);
    if (context->pool_handle == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DEBUG_ERROR("failed to allocate net buffer list pool", status);
        goto divert_create_exit;
    }  
    WDF_IO_QUEUE_CONFIG_INIT(&queue_config, WdfIoQueueDispatchManual);
    status = WdfIoQueueCreate(device, &queue_config, WDF_NO_OBJECT_ATTRIBUTES,
        &context->read_queue);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create I/O read queue", status);
        goto divert_create_exit;
    }
    WDF_TIMER_CONFIG_INIT_PERIODIC(&timer_config, divert_timer,
        DIVERT_PACKET_TIMEOUT);
    timer_config.AutomaticSerialization = TRUE;
    WDF_OBJECT_ATTRIBUTES_INIT(&timer_attributes);
    timer_attributes.ParentObject = (WDFOBJECT)object;
    status = WdfTimerCreate(&timer_config, &timer_attributes, &context->timer);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create packet time-out timer", status);
        goto divert_create_exit;
    }
    RtlZeroMemory(&session, sizeof(session));
    session.flags |= FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session,
        &context->engine_handle);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WFP engine handle", status);
        goto divert_create_exit;
    }
    context->state = DIVERT_CONTEXT_STATE_OPEN;
    WdfTimerStart(context->timer,
        WDF_REL_TIMEOUT_IN_MS(DIVERT_PACKET_TIMEOUT));

divert_create_exit:

    // Clean-up on error:
    if (!NT_SUCCESS(status))
    {
        if (context->pool_handle != NULL)
        {
            NdisFreeNetBufferPool(context->pool_handle);
        }
        if (context->read_queue != NULL)
        {
            WdfObjectDelete(context->read_queue);
        }
        if (context->timer != NULL)
        {
            WdfObjectDelete(context->timer);
        }
        if (context->engine_handle != NULL)
        {
            FwpmEngineClose0(context->engine_handle);
        }
        context->state = DIVERT_CONTEXT_STATE_INVALID;
    }

    WdfRequestComplete(request, status);
}

/*
 * Register all WFP callouts.
 */
static NTSTATUS divert_register_callouts(context_t context, BOOL is_inbound,
    BOOL is_outbound, BOOL is_ipv4, BOOL is_ipv6)
{
    UINT8 i;
    NTSTATUS status;

    status = FwpmTransactionBegin0(context->engine_handle, 0);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to begin WFP transaction", status);
        goto divert_register_callouts_exit;
    }
    for (i = 0; i < DIVERT_CONTEXT_NUMLAYERS; i++)
    {
        status = divert_register_callout(context, i, is_inbound, is_outbound,
            is_ipv4, is_ipv6);
        if (!NT_SUCCESS(status))
        {
            FwpmTransactionAbort0(context->engine_handle);
            goto divert_register_callouts_exit;
        }
    }
    status = FwpmTransactionCommit0(context->engine_handle);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to commit WFP transaction", status);
        goto divert_register_callouts_exit;
    }

divert_register_callouts_exit:

    if (!NT_SUCCESS(status))
    {
        for (i = 0; i < DIVERT_CONTEXT_NUMLAYERS; i++)
        {
            if (context->registered[i])
            {
                FwpsCalloutUnregisterByKey0(&context->callout_guid[i]);
                context->registered[i] = FALSE;
            }
        }
    }

    return status;
}

/*
 * Register a WFP callout.
 */
static NTSTATUS divert_register_callout(context_t context, UINT idx,
    BOOL is_inbound, BOOL is_outbound, BOOL is_ipv4, BOOL is_ipv6)
{
    static wchar_t *sublayer_name[DIVERT_CONTEXT_NUMLAYERS] =
    {
        L"DivertSubLayerOutboundIPv4",
        L"DivertSubLayerInboundIPv4",
        L"DivertSubLayerOutboundIPv6",
        L"DivertSubLayerInboundIPv6"
    };
    static wchar_t *sublayer_desc[DIVERT_CONTEXT_NUMLAYERS] =
    {
        L"Divert sublayer (outbound IPv4)",
        L"Divert sublayer (inbound IPv4)",
        L"Divert sublayer (outbound IPv6)",
        L"Divert sublayer (inbound IPv6)"
    };
    static wchar_t *callout_name[DIVERT_CONTEXT_NUMLAYERS] =
    {
        L"DivertCalloutOutboundIPv4",
        L"DivertCalloutInboundIPv4",
        L"DivertCalloutOutboundIPv6",
        L"DivertCalloutInboundIPv6"
    };
    static wchar_t *callout_desc[DIVERT_CONTEXT_NUMLAYERS] =
    {
        L"Divert callout (outbound IPv4)",
        L"Divert callout (inbound IPv4)",
        L"Divert callout (outbound IPv6)",
        L"Divert callout (inbound IPv6)"
    };
    static wchar_t *filter_name[DIVERT_CONTEXT_NUMLAYERS] =
    {
        L"DivertFilterOutboundIPv4",
        L"DivertFilterInboundIPv4",
        L"DivertFilterOutboundIPv6",
        L"DivertFilterInboundIPv6"
    };
    static wchar_t *filter_desc[DIVERT_CONTEXT_NUMLAYERS] =
    {
        L"Divert filter (outbound IPv4)",
        L"Divert filter (inbound IPv4)",
        L"Divert filter (outbound IPv6)",
        L"Divert filter (inbound IPv6)"
    };
    GUID layer;
    FWPM_SUBLAYER0 sublayer;
    FWPS_CALLOUT0 scallout;
    FWPM_CALLOUT0 mcallout;
    FWPM_FILTER0 filter;
    BOOL required, registered = FALSE;
    divert_callout_t callout;
    NTSTATUS status;

    switch (idx)
    {
        case DIVERT_CONTEXT_OUTBOUND_IPV4_LAYER:
            required = (is_outbound && is_ipv4);
            layer = FWPM_LAYER_OUTBOUND_IPPACKET_V4;
            callout = divert_classify_outbound_v4_callout;
            break;
        case DIVERT_CONTEXT_INBOUND_IPV4_LAYER:
            required = (is_inbound && is_ipv4);
            layer = FWPM_LAYER_INBOUND_IPPACKET_V4;
            callout = divert_classify_inbound_v4_callout;
            break;
        case DIVERT_CONTEXT_OUTBOUND_IPV6_LAYER:
            required = (is_outbound && is_ipv6);
            layer = FWPM_LAYER_OUTBOUND_IPPACKET_V6;
            callout = divert_classify_outbound_v6_callout;
            break;
        case DIVERT_CONTEXT_INBOUND_IPV6_LAYER:
            required = (is_inbound && is_ipv6);
            layer = FWPM_LAYER_INBOUND_IPPACKET_V6;
            callout = divert_classify_inbound_v6_callout;
            break;
        default:
            return STATUS_INVALID_PARAMETER;
    }

    if (!required)
    {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&sublayer, sizeof(sublayer));
    sublayer.subLayerKey             = context->sublayer_guid[idx];
    sublayer.displayData.name        = sublayer_name[idx];
    sublayer.displayData.description = sublayer_desc[idx];
    sublayer.weight                  = FWP_EMPTY;
    RtlZeroMemory(&scallout, sizeof(scallout));
    scallout.calloutKey              = context->callout_guid[idx];
    scallout.classifyFn              = callout;
    scallout.notifyFn                = divert_notify_callout;
    scallout.flowDeleteFn            = NULL;
    RtlZeroMemory(&mcallout, sizeof(mcallout));
    mcallout.calloutKey              = context->callout_guid[idx];
    mcallout.displayData.name        = callout_name[idx];
    mcallout.displayData.description = callout_desc[idx];
    mcallout.applicableLayer         = layer;
    RtlZeroMemory(&filter, sizeof(filter));
    filter.filterKey                 = context->filter_guid[idx];
    filter.layerKey                  = layer;
    filter.displayData.name          = filter_name[idx];
    filter.displayData.description   = filter_desc[idx];
    filter.action.type               = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey         = context->callout_guid[idx];
    filter.subLayerKey               = context->sublayer_guid[idx];
    filter.weight.type               = FWP_EMPTY;
    filter.rawContext                = (UINT64)context;
    status = FwpmSubLayerAdd0(context->engine_handle, &sublayer, NULL);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to add WFP sub-layer", status);
        goto divert_register_callout_error;
    }
    status = FwpsCalloutRegister0(WdfDeviceWdmGetDeviceObject(context->device),
        &scallout, NULL);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to register WFP callout", status);
        goto divert_register_callout_error;
    }
    registered = TRUE;
    status = FwpmCalloutAdd0(context->engine_handle, &mcallout, NULL, NULL);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to add WFP callout", status);
        goto divert_register_callout_error;
    }
    status = FwpmFilterAdd0(context->engine_handle, &filter, NULL, NULL);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to add WFP filter", status);
        goto divert_register_callout_error;
    }
    context->registered[idx] = TRUE;

    return STATUS_SUCCESS;

divert_register_callout_error:
    if (registered)
    {
        FwpsCalloutUnregisterByKey0(&context->callout_guid[idx]);
    }
    return status;
}

/*
 * Divert old-packet cleanup routine.
 */
extern VOID divert_timer(IN WDFTIMER timer)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    PLIST_ENTRY entry;
    PNET_BUFFER_LIST packets;
    WDFFILEOBJECT object = (WDFFILEOBJECT)WdfTimerGetParentObject(timer);
    context_t context = divert_context_get(object);
    packet_t packet;

    if (!divert_context_verify(context, DIVERT_CONTEXT_STATE_OPEN))
    {
        return;
    }

    // DEBUG("TIMER (context=%p, ticktock=%u)", context,
    //     context->timer_ticktock);

    // Sweep away old packets.
    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    while (!IsListEmpty(&context->packet_queue))
    {
        entry = RemoveHeadList(&context->packet_queue);
        packet = CONTAINING_RECORD(entry, struct packet_s, entry);
        if (packet->timer_ticktock == context->timer_ticktock)
        {
            InsertHeadList(&context->packet_queue, entry);
            break;
        }
        context->packet_queue_length--;
        KeReleaseInStackQueuedSpinLock(&lock_handle);

        // Packet is old, dispose of it.
        DEBUG("TIMEOUT (context=%p, packet=%p)", context, packet);
        FwpsDereferenceNetBufferList0(packet->buffers, FALSE);
        ExFreePoolWithTag(packet, DIVERT_PACKET_TAG);
        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    }

    KeReleaseInStackQueuedSpinLock(&lock_handle);
    context->timer_ticktock = !context->timer_ticktock;
}

/*
 * Divert cleanup routine.
 */
extern VOID divert_cleanup(IN WDFFILEOBJECT object)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    PLIST_ENTRY entry;
    PNET_BUFFER_LIST packets;
    UINT i;
    context_t context = divert_context_get(object);
    packet_t packet;
    NTSTATUS status;
    
    DEBUG("CLEANUP: cleaning up divert context (context=%p)", context);
    
    if (!divert_context_verify(context, DIVERT_CONTEXT_STATE_OPEN))
    {
        return;
    }
    WdfTimerStop(context->timer, FALSE);
    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    context->state = DIVERT_CONTEXT_STATE_CLOSING;
    while (!IsListEmpty(&context->packet_queue))
    {
        entry = RemoveHeadList(&context->packet_queue);
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        packet = CONTAINING_RECORD(entry, struct packet_s, entry);
        FwpsDereferenceNetBufferList0(packet->buffers, FALSE);
        ExFreePoolWithTag(packet, DIVERT_PACKET_TAG);
        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    }
    KeReleaseInStackQueuedSpinLock(&lock_handle);
    WdfIoQueuePurge(context->read_queue, NULL, NULL);
    WdfObjectDelete(context->read_queue);
    WdfObjectDelete(context->timer);

    status = FwpmTransactionBegin0(context->engine_handle, 0);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to begin WFP transaction", status);
        goto divert_cleanup_exit;
    }
    for (i = 0; i < DIVERT_CONTEXT_NUMLAYERS; i++)
    {
	if (!context->registered[i])
	{
	    continue;
	}
        status = FwpmFilterDeleteByKey0(context->engine_handle,
            context->filter_guid+i);
        if (!NT_SUCCESS(status))
        {
            DEBUG_ERROR("failed delete WFP filter", status);
            FwpmTransactionAbort0(context->engine_handle);
            goto divert_cleanup_exit;
        }
        status = FwpmSubLayerDeleteByKey0(context->engine_handle,
            context->sublayer_guid+i);
        if (!NT_SUCCESS(status))
        {
            DEBUG_ERROR("failed delete WFP sub-layer", status);
            FwpmTransactionAbort0(context->engine_handle);
            goto divert_cleanup_exit;
        }
    }
    status = FwpmTransactionCommit0(context->engine_handle);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to commit WFP transaction", status);
        goto divert_cleanup_exit;
    }

divert_cleanup_exit:
    FwpmEngineClose0(context->engine_handle);
    for (i = 0; i < DIVERT_CONTEXT_NUMLAYERS; i++)
    {
        if (context->registered[i])
        {
            FwpsCalloutUnregisterByKey0(&context->callout_guid[i]);
        }
    }
    NdisFreeNetBufferPool(context->pool_handle);
}

/*
 * Divert close routine.
 */
extern VOID divert_close(IN WDFFILEOBJECT object)
{
    context_t context = divert_context_get(object);
    
    DEBUG("CLOSE: closing divert context (context=%p)", context);
    
    if (!divert_context_verify(context, DIVERT_CONTEXT_STATE_CLOSING))
    {
        return;
    }
    context->state = DIVERT_CONTEXT_STATE_CLOSED;
}

/*
 * Divert read routine.
 */
static NTSTATUS divert_read(context_t context, WDFREQUEST request)
{
    NTSTATUS status = STATUS_SUCCESS;

    DEBUG("READ: reading diverted packet (context=%p, request=%p)", context,
        request);

    // Forward the request to the pending read queue:
    status = WdfRequestForwardToIoQueue(request, context->read_queue);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to forward I/O request to read queue", status);
        return status;
    }

    // Service the read request:
    divert_read_service(context);

    return STATUS_SUCCESS;
}

/*
 * Divert read request service.
 */
static void divert_read_service(context_t context)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    WDFREQUEST request;
    PLIST_ENTRY entry;
    PMDL dst_mdl;
    PVOID dst, src;
    ULONG dst_len, src_len;
    NTSTATUS status;
    packet_t packet;
    req_context_t req_context;
    divert_addr_t addr;

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    while (context->state == DIVERT_CONTEXT_STATE_OPEN &&
           !IsListEmpty(&context->packet_queue))
    {
        status = WdfIoQueueRetrieveNextRequest(context->read_queue, &request);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        entry = RemoveHeadList(&context->packet_queue);
        context->packet_queue_length--;
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        packet = CONTAINING_RECORD(entry, struct packet_s, entry);
        
        DEBUG("SERVICE: servicing read request (context=%p, request=%p, "
            "packet=%p)", context, request, packet);
        
        // We have now have a read request and a packet; service the read.
        status = WdfRequestRetrieveOutputWdmMdl(request, &dst_mdl);
        dst_len = 0;
        if (!NT_SUCCESS(status))
        {
            DEBUG_ERROR("failed to retrieve output MDL", status);
            goto divert_read_service_complete;
        }
        dst = MmGetSystemAddressForMdlSafe(dst_mdl, NormalPagePriority);
        if (dst == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            DEBUG_ERROR("failed to get address of output MDL", status);
            goto divert_read_service_complete;
        }
        dst_len = MmGetMdlByteCount(dst_mdl);
        src_len = NET_BUFFER_DATA_LENGTH(packet->buffer);
        dst_len = (src_len < dst_len? src_len: dst_len);
        src = NdisGetDataBuffer(packet->buffer, dst_len, NULL, 1, 0);
        if (src == NULL)
        {
            NdisGetDataBuffer(packet->buffer, dst_len, dst, 1, 0);
        }
        else
        {
            RtlCopyMemory(dst, src, dst_len);
        }
        
        // Write the address information.
        req_context = divert_req_context_get(request);
        addr = req_context->addr;
        if (addr != NULL)
        {
            addr->IfIdx = packet->if_idx;
            addr->SubIfIdx = packet->sub_if_idx;
            addr->Direction = packet->direction;
        }

        // Compute the IP/TCP/UDP checksums here if required.
        divert_update_checksums(dst, dst_len, packet->ip_checksum,
            packet->tcp_checksum, packet->udp_checksum);
        
        status = STATUS_SUCCESS;

divert_read_service_complete:
        FwpsDereferenceNetBufferList0(packet->buffers, FALSE);
        ExFreePoolWithTag(packet, DIVERT_PACKET_TAG);
        if (NT_SUCCESS(status))
        {
            WdfRequestCompleteWithInformation(request, status, dst_len);
        }
        else
        {
            WdfRequestComplete(request, status);
        }
        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    }
    KeReleaseInStackQueuedSpinLock(&lock_handle);
}

/*
 * Divert write routine.
 */
static NTSTATUS divert_write(context_t context, WDFREQUEST request,
    divert_addr_t addr)
{
    PMDL mdl = NULL;
    PVOID data;
    UINT data_len;
    struct iphdr *ip_header;
    BOOL isipv4;
    PNET_BUFFER_LIST buffers = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    DEBUG("WRITE: writing/injecting a packet (context=%p, request=%p)",
        context, request);

    if (!divert_context_verify(context, DIVERT_CONTEXT_STATE_OPEN))
    {
        status = STATUS_INVALID_DEVICE_STATE;
        goto divert_write_exit;
    }

    status = WdfRequestRetrieveOutputWdmMdl(request, &mdl);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to retrieve input MDL", status);
        goto divert_write_exit;
    }

    data = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    if (data == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DEBUG_ERROR("failed to get MDL address", status);
        goto divert_write_exit;
    }
    
    data_len = MmGetMdlByteCount(mdl);
    if (data_len < sizeof(struct iphdr))
    {
        status = STATUS_BUFFER_TOO_SMALL;
        DEBUG_ERROR("write buffer too small, cannot read ip header", status);
        goto divert_write_exit;
    }

    ip_header = (struct iphdr *)data;
    switch (ip_header->Version)
    {
        case 4:
            isipv4 = TRUE;
            break;
        case 6:
            isipv4 = FALSE;
            break;
        default:
            status = STATUS_INVALID_PARAMETER;
            DEBUG_ERROR("failed to inject packet; not IPv4 nor IPv6", status);
            goto divert_write_exit;
    }

    status = FwpsAllocateNetBufferAndNetBufferList0(context->pool_handle,
        0, 0, mdl, 0, data_len, &buffers);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create NET_BUFFER_LIST for injected packet",
            status);
        goto divert_write_exit;
    }

    switch (addr->Direction)
    {
        case DIVERT_PACKET_DIRECTION_OUTBOUND:
            if (isipv4)
            {
                status = FwpsInjectNetworkSendAsync0(inject_handle, 
                    DIVERT_PACKET_INJECTED, 0, UNSPECIFIED_COMPARTMENT_ID,
                    buffers, divert_inject_complete, (HANDLE)request);
            }
            else
            {
                status = FwpsInjectNetworkSendAsync0(injectv6_handle, 
                    DIVERT_PACKET_INJECTED, 0, UNSPECIFIED_COMPARTMENT_ID,
                    buffers, divert_inject_complete, (HANDLE)request);
            }
            break;
        case DIVERT_PACKET_DIRECTION_INBOUND:
            if (isipv4)
            {
                status = FwpsInjectNetworkReceiveAsync0(inject_handle, 
                    DIVERT_PACKET_INJECTED, 0, UNSPECIFIED_COMPARTMENT_ID,
                    addr->IfIdx, addr->SubIfIdx, buffers,
                    divert_inject_complete, (HANDLE)request);
            }
            else
            {
                status = FwpsInjectNetworkReceiveAsync0(injectv6_handle, 
                    DIVERT_PACKET_INJECTED, 0, UNSPECIFIED_COMPARTMENT_ID,
                    addr->IfIdx, addr->SubIfIdx, buffers,
                    divert_inject_complete, (HANDLE)request);
            }
            break;
        default:
            status = STATUS_INVALID_PARAMETER;
            DEBUG_ERROR("failed to inject packet; invalid direction", status);
            goto divert_write_exit;
    }

divert_write_exit:

    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to (re)inject packet", status);
        if (buffers != NULL)
        {
            FwpsFreeNetBufferList0(buffers);
        }
    }

    return status;
}

/*
 * Divert inject complete routine.
 */
static void NTAPI divert_inject_complete(VOID *context,
    NET_BUFFER_LIST *buffers, BOOLEAN dispatch_level)
{
    WDFREQUEST request = (WDFREQUEST)context;
    PNET_BUFFER buffer;
    size_t length = 0;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(dispatch_level);

    DEBUG("COMPLETE: write/inject packet complete (request=%p)", request);

    buffer = NET_BUFFER_LIST_FIRST_NB(buffers);
    status = NET_BUFFER_LIST_STATUS(buffers);
    if (NT_SUCCESS(status))
    {
        length = NET_BUFFER_DATA_LENGTH(buffer);
    }
    else
    {
        DEBUG_ERROR("failed to inject packet", status);
    }
    FwpsFreeNetBufferList0(buffers);
    WdfRequestCompleteWithInformation(request, status, length);
}

/*
 * Divert caller context preprocessing.
 */
VOID divert_caller_context(IN WDFDEVICE device, IN WDFREQUEST request)
{
    PCHAR inbuf;
    size_t inbuflen;
    WDF_REQUEST_PARAMETERS params;
    WDFMEMORY memobj;
    divert_addr_t addr;
    divert_ioctl_t ioctl;
    WDF_OBJECT_ATTRIBUTES attributes;
    req_context_t req_context = NULL;
    NTSTATUS status;

    WDF_REQUEST_PARAMETERS_INIT(&params);
    WdfRequestGetParameters(request, &params);

    if (params.Type != WdfRequestTypeDeviceControl)
    {
        goto divert_caller_context_exit;
    }

    // Get and verify the input buffer.
    status = WdfRequestRetrieveInputBuffer(request, 0, &inbuf, &inbuflen);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to retrieve input buffer", status);
        goto divert_caller_context_error;
    }

    if (inbuflen != sizeof(struct divert_ioctl_s))
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
        DEBUG_ERROR("input buffer not an ioctl message header", status);
        goto divert_caller_context_error;
    }

    ioctl = (divert_ioctl_t)inbuf;
    if (ioctl->version != DIVERT_VERSION || ioctl->magic != DIVERT_MAGIC ||
        ioctl->reserved != 0x0)
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
        DEBUG_ERROR("input buffer contained a bad ioctl message header",
            status);
        goto divert_caller_context_error;
    }

    // Probe and lock user buffers here (if required).
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, req_context_s);
    status = WdfObjectAllocateContext(request, &attributes, &req_context);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to allocate request context for ioctl", status);
        goto divert_caller_context_error;
    }
    req_context->addr = NULL;
    if (ioctl->arg == (UINT64)NULL)
    {
        goto divert_caller_context_exit;
    }
    switch (params.Parameters.DeviceIoControl.IoControlCode)
    {
        case IOCTL_DIVERT_RECV:
            status = WdfRequestProbeAndLockUserBufferForWrite(request,
                (PVOID)ioctl->arg, sizeof(struct divert_addr_s), &memobj);
            if (!NT_SUCCESS(status))
            {
                DEBUG_ERROR("invalid arg pointer for RECV ioctl", status);
                goto divert_caller_context_error;
            }
            addr = (divert_addr_t)WdfMemoryGetBuffer(memobj, NULL);
            break;

        case IOCTL_DIVERT_SEND:
            status = WdfRequestProbeAndLockUserBufferForRead(request,
                (PVOID)ioctl->arg, sizeof(struct divert_addr_s), &memobj);
            if (!NT_SUCCESS(status))
            {
                DEBUG_ERROR("invalid arg pointer for SEND ioctl", status);
                goto divert_caller_context_error;
            }
            addr = (divert_addr_t)WdfMemoryGetBuffer(memobj, NULL);
            break;

        case IOCTL_DIVERT_SET_FILTER:
            status = STATUS_INVALID_DEVICE_REQUEST;
            DEBUG_ERROR("arg pointer is non-NULL for SET_FILTER ioctl",
                status);
            goto divert_caller_context_error;
        
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            DEBUG_ERROR("failed to complete I/O control; invalid request",
                status);
            goto divert_caller_context_error;
    }
    
    req_context->addr = addr;

divert_caller_context_exit:

    status = WdfDeviceEnqueueRequest(device, request);
    
divert_caller_context_error:    
    
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to enqueue request", status);
        WdfRequestComplete(request, status);
    }
}

/*
 * Divert I/O control.
 */
extern VOID divert_ioctl(IN WDFQUEUE queue, IN WDFREQUEST request,
    IN size_t out_length, IN size_t in_length, IN ULONG code)
{
    PCHAR inbuf, outbuf;
    size_t inbuflen, outbuflen, filter_len;
    divert_ioctl_t ioctl;
    divert_ioctl_filter_t filter;
    divert_addr_t addr;
    req_context_t req_context;
    NTSTATUS status = STATUS_SUCCESS;
    context_t context = divert_context_get(WdfRequestGetFileObject(request));
    UNREFERENCED_PARAMETER(queue);

    DEBUG("IOCTL: I/O control request (context=%p)", context);

    if (!divert_context_verify(context, DIVERT_CONTEXT_STATE_OPEN))
    {
        status = STATUS_INVALID_DEVICE_STATE;
        goto divert_ioctl_exit;
    }

    // Get the buffers and do sanity checks.
    status = WdfRequestRetrieveInputBuffer(request, 0, &inbuf, &inbuflen);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to retrieve input buffer", status);
        goto divert_ioctl_exit;
    }
    status = WdfRequestRetrieveOutputBuffer(request, 0, &outbuf, &outbuflen);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to retrieve output buffer", status);
        goto divert_ioctl_exit;
    }
    if (inbuflen != in_length || outbuflen != out_length)
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
        DEBUG_ERROR("buffer length mismatch", status);
        goto divert_ioctl_exit;
    }

    // Handle the ioctl:
    switch (code)
    {
        case IOCTL_DIVERT_RECV:
            status = divert_read(context, request);
            if (NT_SUCCESS(status))
            {
                return;
            }
            break;
        
        case IOCTL_DIVERT_SEND:
            
            req_context = divert_req_context_get(request);
            addr = req_context->addr;
            status = divert_write(context, request, addr);
            if (NT_SUCCESS(status))
            {
                return;
            }
            break;
        
        case IOCTL_DIVERT_SET_FILTER:
        {
            BOOL is_inbound, is_outbound, is_ipv4, is_ipv6;

            if (InterlockedExchange(&context->filter_on, TRUE) == TRUE)
            {
                status = STATUS_INVALID_DEVICE_REQUEST;
                DEBUG_ERROR("duplicate SET_FILTER ioctl", status);
                goto divert_ioctl_exit;
            }

            filter = (divert_ioctl_filter_t)outbuf;
            filter_len = outbuflen;
            if (!divert_filter_compile(filter, filter_len, context->filter))
            {
                status = STATUS_INVALID_DEVICE_REQUEST;
                DEBUG_ERROR("failed to compile filter", status);
                goto divert_ioctl_exit;
            }

            divert_filter_analyze(context->filter, &is_inbound, &is_outbound,
                &is_ipv4, &is_ipv6);
            status = divert_register_callouts(context, is_inbound,
                is_outbound, is_ipv4, is_ipv6);

            break;
        }
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            DEBUG_ERROR("failed to complete I/O control; invalid request",
                status);
            break;
    }

divert_ioctl_exit:
    WdfRequestComplete(request, status);
}

/*
 * Divert notify callout.
 */
static NTSTATUS divert_notify_callout(IN FWPS_CALLOUT_NOTIFY_TYPE type,
    IN const GUID *filter_key, IN const FWPS_FILTER0 *filter)
{
    UNREFERENCED_PARAMETER(type);
    UNREFERENCED_PARAMETER(filter_key);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

/*
 * Divert classify outbound IPv4 callout.
 */
static void divert_classify_outbound_v4_callout(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    divert_classify_callout(DIVERT_PACKET_DIRECTION_OUTBOUND,
        fixed_vals->incomingValue[
            FWPS_FIELD_OUTBOUND_IPPACKET_V4_INTERFACE_INDEX].value.uint32,
        fixed_vals->incomingValue[
            FWPS_FIELD_OUTBOUND_IPPACKET_V4_SUB_INTERFACE_INDEX].value.uint32,
        TRUE, fixed_vals, meta_vals, data, filter, flow_context, result);
}

/*
 * Divert classify outbound IPv6 callout.
 */
static void divert_classify_outbound_v6_callout(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    divert_classify_callout(DIVERT_PACKET_DIRECTION_OUTBOUND,
        fixed_vals->incomingValue[
            FWPS_FIELD_OUTBOUND_IPPACKET_V6_INTERFACE_INDEX].value.uint32,
        fixed_vals->incomingValue[
            FWPS_FIELD_OUTBOUND_IPPACKET_V6_SUB_INTERFACE_INDEX].value.uint32,
        FALSE, fixed_vals, meta_vals, data, filter, flow_context, result);
}

/*
 * Divert classify inbound IPv4 callout.
 */
static void divert_classify_inbound_v4_callout(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    PNET_BUFFER_LIST buffers = (PNET_BUFFER_LIST)data;
    PNET_BUFFER buffer;
    NTSTATUS status;

    if (!(result->rights & FWPS_RIGHT_ACTION_WRITE) || data == NULL)
    {
        return;
    }

    buffer = NET_BUFFER_LIST_FIRST_NB(buffers);
    status = NdisRetreatNetBufferDataStart(buffer, meta_vals->ipHeaderSize,
        0, NULL);
    if (!NT_SUCCESS(status))
    {
        result->actionType = FWP_ACTION_PERMIT;
        return;
    }
    divert_classify_callout(DIVERT_PACKET_DIRECTION_INBOUND,
        fixed_vals->incomingValue[
            FWPS_FIELD_INBOUND_IPPACKET_V4_INTERFACE_INDEX].value.uint32,
        fixed_vals->incomingValue[
            FWPS_FIELD_INBOUND_IPPACKET_V4_SUB_INTERFACE_INDEX].value.uint32,
        TRUE, fixed_vals, meta_vals, data, filter, flow_context, result);
    if (result->actionType != FWP_ACTION_BLOCK)
    {
        NdisAdvanceNetBufferDataStart(buffer, meta_vals->ipHeaderSize,
            FALSE, NULL);
    }
}

/*
 * Divert classify inbound IPv6 callout.
 */
static void divert_classify_inbound_v6_callout(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    PNET_BUFFER_LIST buffers = (PNET_BUFFER_LIST)data;
    PNET_BUFFER buffer;
    NTSTATUS status;
   
    if (!(result->rights & FWPS_RIGHT_ACTION_WRITE) || data == NULL)
    {
        return;
    }

    buffer = NET_BUFFER_LIST_FIRST_NB(buffers);
    status = NdisRetreatNetBufferDataStart(buffer, sizeof(struct ipv6hdr),
        0, NULL);
    if (!NT_SUCCESS(status))
    {
        result->actionType = FWP_ACTION_PERMIT;
        return;
    }
    divert_classify_callout(DIVERT_PACKET_DIRECTION_INBOUND,
        fixed_vals->incomingValue[
            FWPS_FIELD_INBOUND_IPPACKET_V6_INTERFACE_INDEX].value.uint32,
        fixed_vals->incomingValue[
            FWPS_FIELD_INBOUND_IPPACKET_V6_SUB_INTERFACE_INDEX].value.uint32,
        FALSE, fixed_vals, meta_vals, data, filter, flow_context, result);
    if (result->actionType != FWP_ACTION_BLOCK)
    {
        NdisAdvanceNetBufferDataStart(buffer, sizeof(struct ipv6hdr), FALSE,
            NULL);
    }
}
/*
 * Divert classify callout.
 */
static void divert_classify_callout(IN UINT8 direction, IN UINT32 if_idx,
    IN UINT32 sub_if_idx, IN BOOL isipv4,
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    FWPS_PACKET_INJECTION_STATE packet_state;
    HANDLE packet_context;
    PNET_BUFFER_LIST buffers, buffers_fst, buffers_cpy, buffers_itr;
    PNET_BUFFER buffer, buffer0;
    PLIST_ENTRY entry;
    BOOL outbound;
    context_t context;
    packet_t packet;

    // Basic checks:
    if (!(result->rights & FWPS_RIGHT_ACTION_WRITE) || data == NULL)
    {
        return;
    }

    context = (context_t)filter->context;
    buffers = (PNET_BUFFER_LIST)data;
    if (isipv4)
    {
        packet_state = FwpsQueryPacketInjectionState0(inject_handle, buffers,
            &packet_context);
    }
    else
    {
        packet_state = FwpsQueryPacketInjectionState0(injectv6_handle,
            buffers, &packet_context);
    }
    if ((packet_state == FWPS_PACKET_INJECTED_BY_SELF ||
         packet_state == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) &&
         packet_context == DIVERT_PACKET_INJECTED)
    {
        result->actionType = FWP_ACTION_PERMIT;
        return;
    }
    if (!divert_context_verify(context, DIVERT_CONTEXT_STATE_OPEN))
    {
        result->actionType = FWP_ACTION_PERMIT;
        return;
    }

    /*
     * This code is complicated by the fact the a single NET_BUFFER_LIST
     * may contain several NET_BUFFER structures.  Each NET_BUFFER needs to
     * be filtered independently.  To achieve this we do the following:
     * 1) First check if any NET_BUFFER passes the filter.
     * 2) If no, then PERMIT the entire NET_BUFFER_LIST.
     * 3) Else, split the NET_BUFFER_LIST into individual NET_BUFFERs; and
     *    either queue or re-inject based on the filter.
     */

    // Find the first NET_BUFFER we need to queue:
    buffers_fst = buffers;
    outbound = (direction == DIVERT_PACKET_DIRECTION_OUTBOUND);
    do
    {
        buffer = NET_BUFFER_LIST_FIRST_NB(buffers_fst);
        if (divert_filter(buffer, if_idx, sub_if_idx, outbound,
            context->filter))
        {
            break;
        }
        buffers_fst= NET_BUFFER_LIST_NEXT_NBL(buffers_fst);
    }
    while (buffers_fst != NULL);

    // No NET_BUFFER needs to be queued, permit the entire NET_BUFFER_LIST:
    if (buffers_fst == NULL)
    {
        result->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // Re-inject all packets up to 'buffers_fst'
    buffers_itr = buffers;
    while (buffers_itr != buffers_fst)
    {
        buffer = NET_BUFFER_LIST_FIRST_NB(buffers_itr);
        if (!divert_reinject_packet(context, direction, isipv4, if_idx,
                sub_if_idx, buffers, buffer))
        {
            goto divert_classify_callout_exit;
        }
        buffers_itr = NET_BUFFER_LIST_NEXT_NBL(buffers_itr);
    }

    // Queue buffers_itr = buffers_fst, which matched our filter.
    buffer = NET_BUFFER_LIST_FIRST_NB(buffers_itr);
    if (!divert_queue_packet(context, buffers, buffer, direction, if_idx,
            sub_if_idx))
    {
        goto divert_classify_callout_exit;
    }
    buffers_itr = NET_BUFFER_LIST_NEXT_NBL(buffers_itr);

    // Queue or re-inject remaining packets.
    while (buffers_itr != NULL)
    {
        buffer = NET_BUFFER_LIST_FIRST_NB(buffers_itr);
        if (divert_filter(buffer, if_idx, sub_if_idx, outbound,
            context->filter))
        {
            if (!divert_queue_packet(context, buffers, buffer, direction,
                    if_idx, sub_if_idx))
            {
                goto divert_classify_callout_exit;
            }
        }
        else
        {
            if (!divert_reinject_packet(context, direction, isipv4, if_idx,
                    sub_if_idx, buffers, buffer))
            {
                goto divert_classify_callout_exit;
            }
        }
    }

    // Since new packets have been queued, service any read.
    divert_read_service(context);

divert_classify_callout_exit:
    result->actionType = FWP_ACTION_BLOCK;
    result->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
}

/*
 * Queue a NET_BUFFER.
 */
static BOOL divert_queue_packet(context_t context, PNET_BUFFER_LIST buffers,
    PNET_BUFFER buffer, UINT8 direction, UINT32 if_idx, UINT32 sub_if_idx)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO checksum_info;
    PLIST_ENTRY entry;
    packet_t packet;

    packet = (packet_t)ExAllocatePoolWithTag(NonPagedPool, DIVERT_PACKET_SIZE,
        DIVERT_PACKET_TAG);
    if (packet == NULL)
    {
        return FALSE;
    }
    checksum_info.Value = NET_BUFFER_LIST_INFO(buffers,
        TcpIpChecksumNetBufferListInfo);
    packet->buffer = buffer;
    packet->buffers = buffers;
    packet->direction = direction;
    packet->if_idx = if_idx;
    packet->sub_if_idx = sub_if_idx;
    if (direction == DIVERT_PACKET_DIRECTION_OUTBOUND)
    {
        // IPv4 Checksum is not calculated yet
        packet->ip_checksum = TRUE;
        packet->tcp_checksum = (BOOL)checksum_info.Transmit.TcpChecksum;
        packet->udp_checksum = (BOOL)checksum_info.Transmit.UdpChecksum;
    }
    else
    {
        packet->ip_checksum = FALSE;
        packet->tcp_checksum = FALSE;
        packet->udp_checksum = FALSE;
    }
    packet->timer_ticktock = context->timer_ticktock;
    entry = &packet->entry;
    FwpsReferenceNetBufferList0(buffers, FALSE);
    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != DIVERT_CONTEXT_STATE_OPEN)
    {
        // We are no longer open
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        FwpsDereferenceNetBufferList0(buffers, FALSE);
        ExFreePoolWithTag(packet, DIVERT_PACKET_TAG);
        return FALSE;
    }
    InsertTailList(&context->packet_queue, entry);
    entry = NULL;
    context->packet_queue_length++;
    if (context->packet_queue_length > context->packet_queue_maxlength)
    {
        entry = RemoveHeadList(&context->packet_queue);
        context->packet_queue_length--;
    }
    KeReleaseInStackQueuedSpinLock(&lock_handle);
    if (entry != NULL)
    {
        // Queue is full; 'entry' contains a dropped packet.
        DEBUG("DROP: packet queue is full, dropping packet");
        packet = CONTAINING_RECORD(entry, struct packet_s, entry);
        FwpsDereferenceNetBufferList0(packet->buffers, FALSE);
        ExFreePoolWithTag(packet, DIVERT_PACKET_TAG);
    }
    DEBUG("PACKET: diverting packet (packet=%p)", packet);

    return TRUE;
}

/*
 * Re-inject a NET_BUFFER.
 */
static BOOL divert_reinject_packet(context_t context, UINT8 direction,
    BOOL isipv4, UINT32 if_idx, UINT32 sub_if_idx, PNET_BUFFER_LIST buffers,
    PNET_BUFFER buffer)
{
    PNET_BUFFER_LIST buffers_cpy;
    NTSTATUS status;

    status = FwpsAllocateNetBufferAndNetBufferList0(
        context->pool_handle, 0, 0, NET_BUFFER_FIRST_MDL(buffer),
        NET_BUFFER_DATA_OFFSET(buffer), NET_BUFFER_DATA_LENGTH(buffer),
        &buffers_cpy);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }
    FwpsReferenceNetBufferList0(buffers, FALSE);
    if (direction == DIVERT_PACKET_DIRECTION_OUTBOUND)
    {
        if (isipv4)
        {
            status = FwpsInjectNetworkSendAsync0(inject_handle, 
                DIVERT_PACKET_ALLOW, 0, UNSPECIFIED_COMPARTMENT_ID,
                buffers_cpy, divert_reinject_complete, (HANDLE)buffers);
        }
        else
        {
            status = FwpsInjectNetworkSendAsync0(injectv6_handle, 
                DIVERT_PACKET_ALLOW, 0, UNSPECIFIED_COMPARTMENT_ID,
                buffers_cpy, divert_reinject_complete, (HANDLE)buffers);
        }
    }
    else
    {
        // NOTE: this case should never occur since inbound net buffers only
        //       ever contain one packet.  We keep for completeness.
        if (isipv4)
        {
            status = FwpsInjectNetworkReceiveAsync0(inject_handle, 
                DIVERT_PACKET_ALLOW, 0, UNSPECIFIED_COMPARTMENT_ID, if_idx,
                sub_if_idx, buffers_cpy, divert_reinject_complete,
                (HANDLE)buffers);
        }
        else
        {
            status = FwpsInjectNetworkReceiveAsync0(injectv6_handle, 
                DIVERT_PACKET_ALLOW, 0, UNSPECIFIED_COMPARTMENT_ID, if_idx,
                sub_if_idx, buffers_cpy, divert_reinject_complete,
                (HANDLE)buffers);
        }
    }
    if (!NT_SUCCESS(status))
    {
        FwpsDereferenceNetBufferList0(buffers, FALSE);
        FwpsFreeNetBufferList0(buffers_cpy);
        return FALSE;
    }
    return TRUE;
}

/*
 * Divert (re)inject complete.
 */
static void NTAPI divert_reinject_complete(VOID *context,
    NET_BUFFER_LIST *buffers_cpy, BOOLEAN dispatch_level)
{
    PNET_BUFFER_LIST buffers;
    UNREFERENCED_PARAMETER(dispatch_level);

    buffers = (PNET_BUFFER_LIST)context;
    FwpsDereferenceNetBufferList0(buffers, FALSE);
    FwpsFreeNetBufferList0(buffers_cpy);
}

/*
 * Generic checksum calculation.
 */
static UINT16 divert_checksum(const void *pseudo_header,
    size_t pseudo_header_len, const void *data, size_t len)
{
    register const UINT16 *data16 = (const UINT16 *)pseudo_header;
    register size_t len16 = pseudo_header_len >> 1;
    register UINT32 sum = 0;
    size_t i;

    for (i = 0; i < len16; i++)
    {
        sum += (UINT32)data16[i];
    }

    data16 = (const UINT16 *)data;
    len16 = len >> 1;
    for (i = 0; i < len16; i++)
    {
        sum += (UINT32)data16[i];
    }
    
    if (len & 0x1)
    {
        const UINT8 *data8 = (const UINT8 *)data;
        sum += (UINT32)data8[len-1];
    }

    sum = (sum & 0xFFFF) + (sum >> 16);
    sum += (sum >> 16);
    sum = ~sum;
    return (UINT16)sum;
}

/*
 * Given a well-formed packet, update the IP and/or TCP/UDP checksums if
 * required.
 */
static void divert_update_checksums(void *header, size_t len,
    BOOL update_ip, BOOL update_tcp, BOOL update_udp)
{
    struct
    {
        UINT32 SrcAddr;
        UINT32 DstAddr;
        UINT8  Zero;
        UINT8  Protocol;
        UINT16 TransLength;
    } pseudo_header;
    struct iphdr *ip_header = (struct iphdr *)header;
    size_t ip_header_len, trans_len;
    void *trans_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    UINT16 *trans_check_ptr;
    UINT sum;

    if (!update_ip && !update_tcp && !update_udp)
    {
        return;
    }

    if (len < sizeof(struct iphdr))
    {
        return;
    }

    if (ip_header->Version != 4)
    {
        return;
    }

    ip_header_len = ip_header->HdrLength*sizeof(UINT32);
    if (len < ip_header_len)
    {
        return;
    }

    if (update_ip)
    {
        ip_header->Checksum = 0;
        ip_header->Checksum = divert_checksum(NULL, 0, ip_header,
            ip_header_len);
    }

    trans_len = RtlUshortByteSwap(ip_header->Length) - ip_header_len;
    trans_header = (UINT8 *)ip_header + ip_header_len;
    switch (ip_header->Protocol)
    {
        case IPPROTO_TCP:
            if (!update_tcp)
            {
                return;
            }
            tcp_header = (struct tcphdr *)trans_header;
            if (trans_len < sizeof(struct tcphdr))
            {
                return;
            }
            trans_check_ptr = &tcp_header->Checksum;
            break;
        case IPPROTO_UDP:
            if (!update_udp)
            {
                return;
            }
            udp_header = (struct udphdr *)trans_header;
            if (trans_len < sizeof(struct udphdr))
            {
                return;
            }
            trans_check_ptr = &udp_header->Checksum;
            break;
        default:
            return;
    }

    pseudo_header.SrcAddr     = ip_header->SrcAddr;
    pseudo_header.DstAddr     = ip_header->DstAddr;
    pseudo_header.Zero        = 0x0;
    pseudo_header.Protocol    = ip_header->Protocol;
    pseudo_header.TransLength = RtlUshortByteSwap((UINT16)trans_len);
    *trans_check_ptr = 0x0;
    sum = divert_checksum(&pseudo_header, sizeof(pseudo_header),
        trans_header, trans_len);
    if (sum == 0 && ip_header->Protocol == IPPROTO_UDP)
    {
        *trans_check_ptr = 0xFFFF;
    }
    else
    {
        *trans_check_ptr = (UINT16)sum;
    }
}

/*
 * Checks if the given packet is of interest.
 */
static BOOL divert_filter(PNET_BUFFER buffer, UINT32 if_idx, UINT32 sub_if_idx,
    BOOL outbound, filter_t filter)
{
    // Buffer contains enough space for a full size iphdr and tcphdr/udphdr
    // (without options)
    UINT8 storage[0xF*sizeof(UINT32) + sizeof(struct tcphdr)];
    UINT8 *headers;
    size_t tot_len, cpy_len, ip_header_len;
    struct iphdr *ip_header = NULL;
    struct ipv6hdr *ipv6_header = NULL;
    struct icmphdr *icmp_header = NULL;
    struct icmpv6hdr *icmpv6_header = NULL;
    struct tcphdr *tcp_header = NULL;
    struct udphdr *udp_header = NULL;
    UINT8 ip, protocol, ttl;

    // Parse the headers: 
    tot_len = NET_BUFFER_DATA_LENGTH(buffer);
    if (tot_len < sizeof(struct iphdr))
    {
        DEBUG("FILTER: REJECT (packet length too small)");
        return FALSE;
    }
    cpy_len = (tot_len < sizeof(storage)? tot_len: sizeof(storage));
    headers = (UINT8 *)NdisGetDataBuffer(buffer, cpy_len, storage, 1, 0);
    if (headers == NULL)
    {
        headers = storage;
    }

    ip_header = (struct iphdr *)headers;
    switch (ip_header->Version)
    {
        case 4:
            ip_header_len = ip_header->HdrLength*sizeof(UINT32);
            if (RtlUshortByteSwap(ip_header->Length) != tot_len ||
                ip_header->HdrLength < 5 ||
                ip_header_len > tot_len)
            {
                DEBUG("FILTER: REJECT (bad IPv4 packet)");
                return FALSE;
            }
            protocol = ip_header->Protocol;
            break;
        case 6:
            ip_header = NULL;
            ipv6_header = (struct ipv6hdr *)headers;
            ip_header_len = sizeof(struct ipv6hdr);
            if (ip_header_len > tot_len ||
                RtlUshortByteSwap(ipv6_header->Length) +
                    sizeof(struct ipv6hdr) != tot_len)
            {
                DEBUG("FILTER: REJECT (bad IPv6 packet)");
                return FALSE;
            }
            protocol = ipv6_header->NextHdr;
            break;
        default:
            DEBUG("FILTER: REJECT (packet is neither IPv4 nor IPv6)");
            return FALSE;
    }

    switch (protocol)
    {
        case IPPROTO_ICMP:
            icmp_header = (struct icmphdr *)(headers + ip_header_len);
            if (ip_header == NULL ||
                sizeof(struct icmphdr) + ip_header_len > tot_len)
            {
                DEBUG("FILTER: REJECT (bad ICMP packet)");
                return FALSE;
            }
            break;
        case IPPROTO_ICMPV6:
            icmpv6_header = (struct icmpv6hdr *)(headers + ip_header_len);
            if (ipv6_header == NULL ||
                sizeof(struct icmpv6hdr) + ip_header_len > tot_len)
            {
                DEBUG("FILTER: REJECT (bad ICMPV6 packet)");
                return FALSE;
            }
            break;
        case IPPROTO_TCP:
            tcp_header = (struct tcphdr *)(headers + ip_header_len);
            if (tcp_header->HdrLength < 5 ||
                tcp_header->HdrLength*sizeof(UINT32) + ip_header_len > tot_len)
            {
                DEBUG("FILTER: REJECT (bad TCP packet)");
                return FALSE;
            }
            break;
        case IPPROTO_UDP:
            udp_header = (struct udphdr *)(headers + ip_header_len);
            if (sizeof(struct udphdr) + ip_header_len > tot_len)
            {
                DEBUG("FILTER: REJECT (bad UDP packet)");
                return FALSE;
            }
            break;
        default:
            break;
    }

    // Execute the filter:
    ip = 0;
    ttl = DIVERT_FILTER_MAXLEN+1;       // Additional safety
    while (ttl-- != 0)
    {
        BOOL result;
        UINT32 field[4];
        field[1] = 0;
        field[2] = 0;
        field[3] = 0;
        switch (filter[ip].protocol)
        {
            case DIVERT_FILTER_PROTOCOL_NONE:
                result = TRUE;
                break;
            case DIVERT_FILTER_PROTOCOL_IP:
                result = (ip_header != NULL);
                break;
            case DIVERT_FILTER_PROTOCOL_IPV6:
                result = (ipv6_header != NULL);
                break;
            case DIVERT_FILTER_PROTOCOL_ICMP:
                result = (icmp_header != NULL);
                break;
            case DIVERT_FILTER_PROTOCOL_ICMPV6:
                result = (icmpv6_header != NULL);
                break;
            case DIVERT_FILTER_PROTOCOL_TCP:
                result = (tcp_header != NULL);
                break;
            case DIVERT_FILTER_PROTOCOL_UDP:
                result = (udp_header != NULL);
                break;
            default:
                result = FALSE;
                break;
        }
        if (result)
        {
            switch (filter[ip].field)
            {
                case DIVERT_FILTER_FIELD_ZERO:
                    field[0] = 0;
                    break;
                case DIVERT_FILTER_FIELD_INBOUND:
                    field[0] = (UINT32)(!outbound);
                    break;
                case DIVERT_FILTER_FIELD_OUTBOUND:
                    field[0] = (UINT32)outbound;
                    break;
                case DIVERT_FILTER_FIELD_IFIDX:
                    field[0] = (UINT32)if_idx;
                    break;
                case DIVERT_FILTER_FIELD_SUBIFIDX:
                    field[0] = (UINT32)sub_if_idx;
                    break;
                case DIVERT_FILTER_FIELD_IP:
                    field[0] = (UINT32)(ip_header != NULL);
                    break;
                case DIVERT_FILTER_FIELD_IPV6:
                    field[0] = (UINT32)(ipv6_header != NULL);
                    break;
                case DIVERT_FILTER_FIELD_ICMP:
                    field[0] = (UINT32)(icmp_header != NULL);
                    break;
                case DIVERT_FILTER_FIELD_ICMPV6:
                    field[0] = (UINT32)(icmpv6_header != NULL);
                    break;
                case DIVERT_FILTER_FIELD_TCP:
                    field[0] = (UINT32)(tcp_header != NULL);
                    break;
                case DIVERT_FILTER_FIELD_UDP:
                    field[0] = (UINT32)(udp_header != NULL);
                    break;
                case DIVERT_FILTER_FIELD_IP_HDRLENGTH:
                    field[0] = (UINT32)ip_header->HdrLength;
                    break;
                case DIVERT_FILTER_FIELD_IP_TOS:
                    field[0] = (UINT32)RtlUshortByteSwap(ip_header->TOS);
                    break;
                case DIVERT_FILTER_FIELD_IP_LENGTH:
                    field[0] = (UINT32)RtlUshortByteSwap(ip_header->Length);
                    break;
                case DIVERT_FILTER_FIELD_IP_ID:
                    field[0] = (UINT32)RtlUshortByteSwap(ip_header->Id);
                    break;
                case DIVERT_FILTER_FIELD_IP_DF:
                    field[0] = (UINT32)IPHDR_GET_DF(ip_header);
                    break;
                case DIVERT_FILTER_FIELD_IP_MF:
                    field[0] = (UINT32)IPHDR_GET_MF(ip_header);
                    break;
                case DIVERT_FILTER_FIELD_IP_FRAGOFF:
                    field[0] = (UINT32)RtlUshortByteSwap(
                        IPHDR_GET_FRAGOFF(ip_header));
                    break;
                case DIVERT_FILTER_FIELD_IP_TTL:
                    field[0] = (UINT32)ip_header->TTL;
                    break;
                case DIVERT_FILTER_FIELD_IP_PROTOCOL:
                    field[0] = (UINT32)ip_header->Protocol;
                    break;
                case DIVERT_FILTER_FIELD_IP_CHECKSUM:
                    field[0] = (UINT32)RtlUshortByteSwap(ip_header->Checksum);
                    break;
                case DIVERT_FILTER_FIELD_IP_SRCADDR:
                    field[0] = (UINT32)RtlUlongByteSwap(ip_header->SrcAddr);
                    break;
                case DIVERT_FILTER_FIELD_IP_DSTADDR:
                    field[0] = (UINT32)RtlUlongByteSwap(ip_header->DstAddr);
                    break;
                case DIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS:
                    field[0] = (UINT32)IPV6HDR_GET_TRAFFICCLASS(ipv6_header);
                    break;
                case DIVERT_FILTER_FIELD_IPV6_FLOWLABEL:
                    field[0] = (UINT32)RtlUlongByteSwap(
                        IPV6HDR_GET_FLOWLABEL(ipv6_header));
                    break;
                case DIVERT_FILTER_FIELD_IPV6_LENGTH:
                    field[0] = (UINT32)RtlUshortByteSwap(ipv6_header->Length);
                    break;
                case DIVERT_FILTER_FIELD_IPV6_NEXTHDR:
                    field[0] = (UINT32)ipv6_header->NextHdr;
                    break;
                case DIVERT_FILTER_FIELD_IPV6_HOPLIMIT:
                    field[0] = (UINT32)ipv6_header->HopLimit;
                    break;
                case DIVERT_FILTER_FIELD_IPV6_SRCADDR:
                    field[0] =
                        (UINT32)RtlUlongByteSwap(ipv6_header->SrcAddr[3]);
                    field[1] =
                        (UINT32)RtlUlongByteSwap(ipv6_header->SrcAddr[2]);
                    field[2] =
                        (UINT32)RtlUlongByteSwap(ipv6_header->SrcAddr[1]);
                    field[3] =
                        (UINT32)RtlUlongByteSwap(ipv6_header->SrcAddr[0]);
                    break;
                case DIVERT_FILTER_FIELD_IPV6_DSTADDR:
                    field[0] =
                        (UINT32)RtlUlongByteSwap(ipv6_header->DstAddr[3]);
                    field[1] =
                        (UINT32)RtlUlongByteSwap(ipv6_header->DstAddr[2]);
                    field[2] =
                        (UINT32)RtlUlongByteSwap(ipv6_header->DstAddr[1]);
                    field[3] =
                        (UINT32)RtlUlongByteSwap(ipv6_header->DstAddr[0]);
                    break;
                case DIVERT_FILTER_FIELD_ICMP_TYPE:
                    field[0] = (UINT32)icmp_header->Type;
                    break;
                case DIVERT_FILTER_FIELD_ICMP_CODE:
                    field[0] = (UINT32)icmp_header->Code;
                    break;
                case DIVERT_FILTER_FIELD_ICMP_CHECKSUM:
                    field[0] =
                        (UINT32)RtlUshortByteSwap(icmp_header->Checksum);
                    break;
                case DIVERT_FILTER_FIELD_ICMP_BODY:
                    field[0] = (UINT32)RtlUlongByteSwap(icmp_header->Body);
                    break;
                case DIVERT_FILTER_FIELD_ICMPV6_TYPE:
                    field[0] = (UINT32)icmpv6_header->Type;
                    break;
                case DIVERT_FILTER_FIELD_ICMPV6_CODE:
                    field[0] = (UINT32)icmpv6_header->Code;
                    break;
                case DIVERT_FILTER_FIELD_ICMPV6_CHECKSUM:
                    field[0] = (UINT32)icmpv6_header->Checksum;
                    break;
                case DIVERT_FILTER_FIELD_ICMPV6_BODY:
                    field[0] = (UINT32)icmpv6_header->Body;
                    break;
                case DIVERT_FILTER_FIELD_TCP_SRCPORT:
                    field[0] = (UINT32)RtlUshortByteSwap(tcp_header->SrcPort);
                    break;
                case DIVERT_FILTER_FIELD_TCP_DSTPORT:
                    field[0] = (UINT32)RtlUshortByteSwap(tcp_header->DstPort);
                    break;
                case DIVERT_FILTER_FIELD_TCP_SEQNUM:
                    field[0] = (UINT32)RtlUlongByteSwap(tcp_header->SeqNum);
                    break;
                case DIVERT_FILTER_FIELD_TCP_ACKNUM:
                    field[0] = (UINT32)RtlUlongByteSwap(tcp_header->AckNum);
                    break;
                case DIVERT_FILTER_FIELD_TCP_HDRLENGTH:
                    field[0] = (UINT32)tcp_header->HdrLength;
                    break;
                case DIVERT_FILTER_FIELD_TCP_URG:
                    field[0] = (UINT32)tcp_header->Urg;
                    break;
                case DIVERT_FILTER_FIELD_TCP_ACK:
                    field[0] = (UINT32)tcp_header->Ack;
                    break;
                case DIVERT_FILTER_FIELD_TCP_PSH:
                    field[0] = (UINT32)tcp_header->Psh;
                    break;
                case DIVERT_FILTER_FIELD_TCP_RST:
                    field[0] = (UINT32)tcp_header->Rst;
                    break;
                case DIVERT_FILTER_FIELD_TCP_SYN:
                    field[0] = (UINT32)tcp_header->Syn;
                    break;
                case DIVERT_FILTER_FIELD_TCP_FIN:
                    field[0] = (UINT32)tcp_header->Fin;
                    break;
                case DIVERT_FILTER_FIELD_TCP_WINDOW:
                    field[0] = (UINT32)RtlUshortByteSwap(tcp_header->Window);
                    break;
                case DIVERT_FILTER_FIELD_TCP_CHECKSUM:
                    field[0] = (UINT32)RtlUshortByteSwap(tcp_header->Checksum);
                    break;
                case DIVERT_FILTER_FIELD_TCP_URGPTR:
                    field[0] = (UINT32)RtlUshortByteSwap(tcp_header->UrgPtr);
                    break;
                case DIVERT_FILTER_FIELD_TCP_PAYLOADLENGTH:
                    field[0] = (UINT32)(tot_len - ip_header_len -
                        tcp_header->HdrLength*sizeof(UINT32));
                    break;
                case DIVERT_FILTER_FIELD_UDP_SRCPORT:
                    field[0] = (UINT32)RtlUshortByteSwap(udp_header->SrcPort);
                    break;
                case DIVERT_FILTER_FIELD_UDP_DSTPORT:
                    field[0] = (UINT32)RtlUshortByteSwap(udp_header->DstPort);
                    break;
                case DIVERT_FILTER_FIELD_UDP_LENGTH:
                    field[0] = (UINT32)RtlUshortByteSwap(udp_header->Length);
                    break;
                case DIVERT_FILTER_FIELD_UDP_CHECKSUM:
                    field[0] = (UINT32)RtlUshortByteSwap(udp_header->Checksum);
                    break;
                case DIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH:
                    field[0] = (UINT32)(tot_len - ip_header_len -
                        sizeof(struct udphdr));
                    break;
                default:
                    field[0] = 0;
                    break;
            }
            switch (filter[ip].test)
            {
                case DIVERT_FILTER_TEST_EQ:
                    result = (field[0] == filter[ip].arg[0] &&
                              field[1] == filter[ip].arg[1] &&
                              field[2] == filter[ip].arg[2] &&
                              field[3] == filter[ip].arg[3]);
                    break;
                case DIVERT_FILTER_TEST_NEQ:
                    result = (field[0] != filter[ip].arg[0] ||
                              field[1] != filter[ip].arg[1] ||
                              field[2] != filter[ip].arg[2] ||
                              field[3] != filter[ip].arg[3]);
                    break;
                case DIVERT_FILTER_TEST_LT:
                    result = (field[3] < filter[ip].arg[3] ||
                             (field[3] == filter[ip].arg[3] &&
                              field[2] < filter[ip].arg[2] ||
                             (field[2] == filter[ip].arg[2] && 
                              field[1] < filter[ip].arg[1] ||
                             (field[1] == filter[ip].arg[1] &&
                              field[0] < filter[ip].arg[0]))));
                    break;
                case DIVERT_FILTER_TEST_LEQ:
                    result = (field[3] < filter[ip].arg[3] ||
                             (field[3] == filter[ip].arg[3] &&
                              field[2] < filter[ip].arg[2] ||
                             (field[2] == filter[ip].arg[2] && 
                              field[1] < filter[ip].arg[1] ||
                             (field[1] == filter[ip].arg[1] &&
                              field[0] <= filter[ip].arg[0]))));
                    break;
                case DIVERT_FILTER_TEST_GT:
                    result = (field[3] > filter[ip].arg[3] ||
                             (field[3] == filter[ip].arg[3] &&
                              field[2] > filter[ip].arg[2] ||
                             (field[2] == filter[ip].arg[2] && 
                              field[1] > filter[ip].arg[1] ||
                             (field[1] == filter[ip].arg[1] &&
                              field[0] > filter[ip].arg[0]))));
                    break;
                case DIVERT_FILTER_TEST_GEQ:
                    result = (field[3] > filter[ip].arg[3] ||
                             (field[3] == filter[ip].arg[3] &&
                              field[2] > filter[ip].arg[2] ||
                             (field[2] == filter[ip].arg[2] && 
                              field[1] > filter[ip].arg[1] ||
                             (field[1] == filter[ip].arg[1] &&
                              field[0] >= filter[ip].arg[0]))));
                    break;
                default:
                    result = FALSE;
                    break;
            }
        }
        ip = (result? filter[ip].success: filter[ip].failure);
        if (ip == DIVERT_FILTER_RESULT_ACCEPT)
        {
            return TRUE;
        }
        if (ip == DIVERT_FILTER_RESULT_REJECT)
        {
            return FALSE;
        }
    }
    DEBUG("FILTER: REJECT (filter TTL exceeded)");
    return FALSE;
}

/*
 * Analyze the given filter.
 */
static void divert_filter_analyze(filter_t filter, BOOL *is_inbound,
    BOOL *is_outbound, BOOL *is_ipv4, BOOL *is_ipv6)
{
    BOOL result;

    // False filter?
    result = divert_filter_test(filter, 0, DIVERT_FILTER_PROTOCOL_NONE,
        DIVERT_FILTER_FIELD_ZERO, 0);
    if (!result)
    {
        *is_inbound  = FALSE;
        *is_outbound = FALSE;
        *is_ipv4     = FALSE;
        *is_ipv6     = FALSE;
        return;
    }

    // Inbound?
    result = divert_filter_test(filter, 0, DIVERT_FILTER_PROTOCOL_NONE,
        DIVERT_FILTER_FIELD_INBOUND, 1);
    if (result)
    {
        result = divert_filter_test(filter, 0, DIVERT_FILTER_PROTOCOL_NONE,
            DIVERT_FILTER_FIELD_OUTBOUND, 0);
    }
    *is_inbound = result;

    // Outbound?
    result = divert_filter_test(filter, 0, DIVERT_FILTER_PROTOCOL_NONE,
        DIVERT_FILTER_FIELD_OUTBOUND, 1);
    if (result)
    {
        result = divert_filter_test(filter, 0, DIVERT_FILTER_PROTOCOL_NONE,
            DIVERT_FILTER_FIELD_INBOUND, 0);
    }
    *is_outbound = result;

    // IPv4?
    result = divert_filter_test(filter, 0, DIVERT_FILTER_PROTOCOL_NONE,
        DIVERT_FILTER_FIELD_IP, 1);
    if (result)
    {
        result = divert_filter_test(filter, 0, DIVERT_FILTER_PROTOCOL_NONE,
            DIVERT_FILTER_FIELD_IPV6, 0);
    }
    *is_ipv4 = result;

    // Ipv6?
    result = divert_filter_test(filter, 0, DIVERT_FILTER_PROTOCOL_NONE,
        DIVERT_FILTER_FIELD_IPV6, 1);
    if (result)
    {
        result = divert_filter_test(filter, 0, DIVERT_FILTER_PROTOCOL_NONE,
            DIVERT_FILTER_FIELD_IP, 0);
    }
    *is_ipv6 = result;
}

/*
 * Test a filter for any packet where field = arg.
 */
static BOOL divert_filter_test(filter_t filter, UINT8 ip, UINT8 protocol,
    UINT8 field, UINT32 arg)
{
    BOOL known = FALSE;
    BOOL result = FALSE;

    if (ip == DIVERT_FILTER_RESULT_ACCEPT)
    {
        return TRUE;
    }
    if (ip == DIVERT_FILTER_RESULT_REJECT)
    {
        return FALSE;
    }
    if (ip > DIVERT_FILTER_MAXLEN)
    {
        return FALSE;
    }

    if (filter[ip].protocol == protocol &&
        filter[ip].field == field)
    {
        known = TRUE;
        switch (filter[ip].test)
        {
            case DIVERT_FILTER_TEST_EQ:
                result = (arg == filter[ip].arg[0]);
                break;
            case DIVERT_FILTER_TEST_NEQ:
                result = (arg != filter[ip].arg[0]);
                break;
            case DIVERT_FILTER_TEST_LT:
                result = (arg < filter[ip].arg[0]);
                break;
            case DIVERT_FILTER_TEST_LEQ:
                result = (arg <= filter[ip].arg[0]);
                break;
            case DIVERT_FILTER_TEST_GT:
                result = (arg > filter[ip].arg[0]);
                break;
            case DIVERT_FILTER_TEST_GEQ:
                result = (arg >= filter[ip].arg[0]);
                break;
            default:
                result = FALSE;
                break;
        }
    }

    if (!known)
    {
        result = divert_filter_test(filter, filter[ip].success, protocol,
            field, arg);
        if (result)
        {
            return TRUE;
        }
        return divert_filter_test(filter, filter[ip].failure, protocol, field,
            arg);
    }
    else
    {
        ip = (result? filter[ip].success: filter[ip].failure);
        return divert_filter_test(filter, ip, protocol, field, arg);
    }
}

/*
 * Compile a divert filter from an IOCTL.
 */
static BOOL divert_filter_compile(divert_ioctl_filter_t ioctl_filter,
    size_t ioctl_filter_len, filter_t filter)
{
    struct filter_s filter0[DIVERT_FILTER_MAXLEN];
    UINT8 i;
    UINT length;
    UINT64 *src, *dst;

    if (ioctl_filter_len % sizeof(struct divert_ioctl_filter_s) != 0)
    {
        return FALSE;
    }
    length = ioctl_filter_len / sizeof(struct divert_ioctl_filter_s);
    if (length >= DIVERT_FILTER_MAXLEN)
    {
        return FALSE;
    }

    for (i = 0; i < length; i++)
    {
        if (ioctl_filter[i].field > DIVERT_FILTER_FIELD_MAX ||
            ioctl_filter[i].test > DIVERT_FILTER_TEST_MAX)
        {
            return FALSE;
        }
        switch (ioctl_filter[i].success)
        {
            case DIVERT_FILTER_RESULT_ACCEPT: case DIVERT_FILTER_RESULT_REJECT:
                break;
            default:
                if (ioctl_filter[i].success <= i ||
                    ioctl_filter[i].success >= length)
                {
                    return FALSE;
                }
                break;
        }
        switch (ioctl_filter[i].failure)
        {
            case DIVERT_FILTER_RESULT_ACCEPT: case DIVERT_FILTER_RESULT_REJECT:
                break;
            default:
                if (ioctl_filter[i].failure <= i ||
                    ioctl_filter[i].failure >= length)
                {
                    return FALSE;
                }
                break;
        }

        // Enforce size limits:
        if (ioctl_filter[i].field != DIVERT_FILTER_FIELD_IPV6_SRCADDR &&
            ioctl_filter[i].field != DIVERT_FILTER_FIELD_IPV6_DSTADDR)
        {
            if (ioctl_filter[i].arg[1] != 0 ||
                ioctl_filter[i].arg[2] != 0 ||
                ioctl_filter[i].arg[3] != 0)
            {
                return FALSE;
            }
        }
        switch (ioctl_filter[i].field)
        {
            case DIVERT_FILTER_FIELD_ZERO:
            case DIVERT_FILTER_FIELD_INBOUND:
            case DIVERT_FILTER_FIELD_OUTBOUND:
            case DIVERT_FILTER_FIELD_IP:
            case DIVERT_FILTER_FIELD_IPV6:
            case DIVERT_FILTER_FIELD_ICMP:
            case DIVERT_FILTER_FIELD_ICMPV6:
            case DIVERT_FILTER_FIELD_TCP:
            case DIVERT_FILTER_FIELD_UDP:
            case DIVERT_FILTER_FIELD_IP_DF:
            case DIVERT_FILTER_FIELD_IP_MF:
            case DIVERT_FILTER_FIELD_TCP_URG:
            case DIVERT_FILTER_FIELD_TCP_ACK:
            case DIVERT_FILTER_FIELD_TCP_PSH:
            case DIVERT_FILTER_FIELD_TCP_RST:
            case DIVERT_FILTER_FIELD_TCP_SYN:
            case DIVERT_FILTER_FIELD_TCP_FIN:
                if (ioctl_filter[i].arg[0] > 1)
                {
                    return FALSE;
                }
                break;
            case DIVERT_FILTER_FIELD_IP_HDRLENGTH:
            case DIVERT_FILTER_FIELD_TCP_HDRLENGTH:
                if (ioctl_filter[i].arg[0] > 0x0F)
                {
                    return FALSE;
                }
                break;
            case DIVERT_FILTER_FIELD_IP_TTL:
            case DIVERT_FILTER_FIELD_IP_PROTOCOL:
            case DIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS:
            case DIVERT_FILTER_FIELD_IPV6_NEXTHDR:
            case DIVERT_FILTER_FIELD_IPV6_HOPLIMIT:
            case DIVERT_FILTER_FIELD_ICMP_TYPE:
            case DIVERT_FILTER_FIELD_ICMP_CODE:
            case DIVERT_FILTER_FIELD_ICMPV6_TYPE:
            case DIVERT_FILTER_FIELD_ICMPV6_CODE:
                if (ioctl_filter[i].arg[0] > UINT8_MAX)
                {
                    return FALSE;
                }
                break;
            case DIVERT_FILTER_FIELD_IP_FRAGOFF:
                if (ioctl_filter[i].arg[0] > 0x1FFF)
                {
                    return FALSE;
                }
                break;
            case DIVERT_FILTER_FIELD_IP_TOS:
            case DIVERT_FILTER_FIELD_IP_LENGTH:
            case DIVERT_FILTER_FIELD_IP_ID:
            case DIVERT_FILTER_FIELD_IP_CHECKSUM:
            case DIVERT_FILTER_FIELD_IPV6_LENGTH:
            case DIVERT_FILTER_FIELD_ICMP_CHECKSUM:
            case DIVERT_FILTER_FIELD_ICMPV6_CHECKSUM:
            case DIVERT_FILTER_FIELD_TCP_SRCPORT:
            case DIVERT_FILTER_FIELD_TCP_DSTPORT:
            case DIVERT_FILTER_FIELD_TCP_WINDOW:
            case DIVERT_FILTER_FIELD_TCP_CHECKSUM:
            case DIVERT_FILTER_FIELD_TCP_URGPTR:
            case DIVERT_FILTER_FIELD_TCP_PAYLOADLENGTH:
            case DIVERT_FILTER_FIELD_UDP_SRCPORT:
            case DIVERT_FILTER_FIELD_UDP_DSTPORT:
            case DIVERT_FILTER_FIELD_UDP_LENGTH:
            case DIVERT_FILTER_FIELD_UDP_CHECKSUM:
            case DIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH:
                if (ioctl_filter[i].arg[0] > UINT16_MAX)
                {
                    return FALSE;
                }
                break;
            case DIVERT_FILTER_FIELD_IPV6_FLOWLABEL:
                if (ioctl_filter[i].arg[0] > 0x000FFFFF)
                {
                    return FALSE;
                }
                break;
            default:
                break;
        }
        filter0[i].field   = ioctl_filter[i].field;
        filter0[i].test    = ioctl_filter[i].test;
        filter0[i].success = ioctl_filter[i].success;
        filter0[i].failure = ioctl_filter[i].failure;
        filter0[i].arg[0]  = ioctl_filter[i].arg[0];
        filter0[i].arg[1]  = ioctl_filter[i].arg[1];
        filter0[i].arg[2]  = ioctl_filter[i].arg[2];
        filter0[i].arg[3]  = ioctl_filter[i].arg[3];

        // Protocol selection:
        switch (ioctl_filter[i].field)
        {
            case DIVERT_FILTER_FIELD_ZERO:
            case DIVERT_FILTER_FIELD_INBOUND:
            case DIVERT_FILTER_FIELD_OUTBOUND:
            case DIVERT_FILTER_FIELD_IFIDX:
            case DIVERT_FILTER_FIELD_SUBIFIDX:
            case DIVERT_FILTER_FIELD_IP:
            case DIVERT_FILTER_FIELD_IPV6:
            case DIVERT_FILTER_FIELD_ICMP:
            case DIVERT_FILTER_FIELD_ICMPV6:
            case DIVERT_FILTER_FIELD_TCP:
            case DIVERT_FILTER_FIELD_UDP:
                filter0[i].protocol = DIVERT_FILTER_PROTOCOL_NONE;
                break;
            case DIVERT_FILTER_FIELD_IP_HDRLENGTH:
            case DIVERT_FILTER_FIELD_IP_TOS:
            case DIVERT_FILTER_FIELD_IP_LENGTH:
            case DIVERT_FILTER_FIELD_IP_ID:
            case DIVERT_FILTER_FIELD_IP_DF:
            case DIVERT_FILTER_FIELD_IP_MF:
            case DIVERT_FILTER_FIELD_IP_FRAGOFF:
            case DIVERT_FILTER_FIELD_IP_TTL:
            case DIVERT_FILTER_FIELD_IP_PROTOCOL:
            case DIVERT_FILTER_FIELD_IP_CHECKSUM:
            case DIVERT_FILTER_FIELD_IP_SRCADDR:
            case DIVERT_FILTER_FIELD_IP_DSTADDR:
                filter0[i].protocol = DIVERT_FILTER_PROTOCOL_IP;
                break;
            case DIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS:
            case DIVERT_FILTER_FIELD_IPV6_FLOWLABEL:
            case DIVERT_FILTER_FIELD_IPV6_LENGTH:
            case DIVERT_FILTER_FIELD_IPV6_NEXTHDR:
            case DIVERT_FILTER_FIELD_IPV6_HOPLIMIT:
            case DIVERT_FILTER_FIELD_IPV6_SRCADDR:
            case DIVERT_FILTER_FIELD_IPV6_DSTADDR:
                filter0[i].protocol = DIVERT_FILTER_PROTOCOL_IPV6;
                break;
            case DIVERT_FILTER_FIELD_ICMP_TYPE:
            case DIVERT_FILTER_FIELD_ICMP_CODE:
            case DIVERT_FILTER_FIELD_ICMP_CHECKSUM:
            case DIVERT_FILTER_FIELD_ICMP_BODY:
                filter0[i].protocol = DIVERT_FILTER_PROTOCOL_ICMP;
                break;
            case DIVERT_FILTER_FIELD_ICMPV6_TYPE:
            case DIVERT_FILTER_FIELD_ICMPV6_CODE:
            case DIVERT_FILTER_FIELD_ICMPV6_CHECKSUM:
            case DIVERT_FILTER_FIELD_ICMPV6_BODY:
                filter0[i].protocol = DIVERT_FILTER_PROTOCOL_ICMPV6;
                break;
            case DIVERT_FILTER_FIELD_TCP_SRCPORT:
            case DIVERT_FILTER_FIELD_TCP_DSTPORT:
            case DIVERT_FILTER_FIELD_TCP_SEQNUM:
            case DIVERT_FILTER_FIELD_TCP_ACKNUM:
            case DIVERT_FILTER_FIELD_TCP_HDRLENGTH:
            case DIVERT_FILTER_FIELD_TCP_URG:
            case DIVERT_FILTER_FIELD_TCP_ACK:
            case DIVERT_FILTER_FIELD_TCP_PSH:
            case DIVERT_FILTER_FIELD_TCP_RST:
            case DIVERT_FILTER_FIELD_TCP_SYN:
            case DIVERT_FILTER_FIELD_TCP_FIN:
            case DIVERT_FILTER_FIELD_TCP_WINDOW:
            case DIVERT_FILTER_FIELD_TCP_CHECKSUM:
            case DIVERT_FILTER_FIELD_TCP_URGPTR:
            case DIVERT_FILTER_FIELD_TCP_PAYLOADLENGTH:
                filter0[i].protocol = DIVERT_FILTER_PROTOCOL_TCP;
                break;
            case DIVERT_FILTER_FIELD_UDP_SRCPORT:
            case DIVERT_FILTER_FIELD_UDP_DSTPORT:
            case DIVERT_FILTER_FIELD_UDP_LENGTH:
            case DIVERT_FILTER_FIELD_UDP_CHECKSUM:
            case DIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH:
                filter0[i].protocol = DIVERT_FILTER_PROTOCOL_UDP;
                break;
            default:
                return FALSE;
        }
    }
    RtlMoveMemory(filter, filter0, i*sizeof(struct filter_s));
    
    return TRUE;
}

