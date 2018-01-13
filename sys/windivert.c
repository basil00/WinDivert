/*
 * windivert.c
 * (C) 2018, all rights reserved,
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <wdf.h>
#include <stdarg.h>
#include <ntstrsafe.h>
#define INITGUID
#include <guiddef.h>

#include "windivert_device.h"

/*
 * WDK function declaration cruft.
 */
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD windivert_unload;
EVT_WDF_IO_IN_CALLER_CONTEXT windivert_caller_context;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL windivert_ioctl;
EVT_WDF_DEVICE_FILE_CREATE windivert_create;
EVT_WDF_FILE_CLEANUP windivert_cleanup;
EVT_WDF_FILE_CLOSE windivert_close;
EVT_WDF_OBJECT_CONTEXT_DESTROY windivert_destroy;
EVT_WDF_WORKITEM windivert_worker;

/*
 * Debugging macros.
 */
// #define DEBUG_ON
#define DEBUG_BUFSIZE       256

#ifdef DEBUG_ON
static void DEBUG(PCCH format, ...)
{
    va_list args;
    char buf[DEBUG_BUFSIZE+1];
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }
    va_start(args, format);
    RtlStringCbVPrintfA(buf, DEBUG_BUFSIZE, format, args);
    DbgPrint("WINDIVERT: %s\n", buf);
    va_end(args);
}
static void DEBUG_ERROR(PCCH format, NTSTATUS status, ...)
{
    va_list args;
    char buf[DEBUG_BUFSIZE+1];
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }
    va_start(args, status);
    RtlStringCbVPrintfA(buf, DEBUG_BUFSIZE, format, args);
    DbgPrint("WINDIVERT: *** ERROR ***: (status = %x): %s\n", status, buf);
    va_end(args);
}
#else       // DEBUG_ON
#define DEBUG(format, ...)
#define DEBUG_ERROR(format, status, ...)
#endif

#define WINDIVERT_TAG                           'viDW'

/*
 * WinDivert packet filter.
 */
struct filter_s
{
    UINT8  protocol:4;                          // field's protocol
    UINT8  test:4;                              // Filter test
    UINT8  field;                               // Field of interest
    UINT16 success;                             // Success continuation
    UINT16 failure;                             // Fail continuation
    UINT32 arg[4];                              // Comparison argument
};
typedef struct filter_s *filter_t;
#define WINDIVERT_FILTER_PROTOCOL_NONE          0
#define WINDIVERT_FILTER_PROTOCOL_IP            1
#define WINDIVERT_FILTER_PROTOCOL_IPV6          2
#define WINDIVERT_FILTER_PROTOCOL_ICMP          3
#define WINDIVERT_FILTER_PROTOCOL_ICMPV6        4
#define WINDIVERT_FILTER_PROTOCOL_TCP           5
#define WINDIVERT_FILTER_PROTOCOL_UDP           6

/*
 * WinDivert context information.
 */
#define WINDIVERT_CONTEXT_SIZE                  (sizeof(struct context_s))
#define WINDIVERT_CONTEXT_MAXLAYERS             4
#define WINDIVERT_CONTEXT_MAXWORKERS            1
#define WINDIVERT_CONTEXT_OUTBOUND_IPV4_LAYER   0
#define WINDIVERT_CONTEXT_INBOUND_IPV4_LAYER    1
#define WINDIVERT_CONTEXT_OUTBOUND_IPV6_LAYER   2
#define WINDIVERT_CONTEXT_INBOUND_IPV6_LAYER    3
typedef enum
{
    WINDIVERT_CONTEXT_STATE_OPENING = 0xA0,     // Context is opening.
    WINDIVERT_CONTEXT_STATE_OPEN    = 0xB1,     // Context is open.
    WINDIVERT_CONTEXT_STATE_CLOSING = 0xC2,     // Context is closing.
    WINDIVERT_CONTEXT_STATE_CLOSED  = 0xD3,     // Context is closed.
    WINDIVERT_CONTEXT_STATE_INVALID = 0xE4      // Context is invalid.
} context_state_t;
struct context_s
{
    context_state_t state;                      // Context's state.
    KSPIN_LOCK lock;                            // Context-wide lock.
    WDFDEVICE device;                           // Context's device.
    WDFFILEOBJECT object;                       // Context's parent object.
    LIST_ENTRY work_queue;                      // Work queue.
    ULONG work_queue_length;                    // Work queue length.
    LIST_ENTRY packet_queue;                    // Packet queue.
    ULONG packet_queue_length;                  // Packet queue length.
    ULONG packet_queue_maxlength;               // Packet queue max length.
    ULONG packet_queue_size;                    // Packet queue size (in bytes).
    ULONG packet_queue_maxsize;                 // Packet queue max size.
    LONGLONG packet_queue_maxcounts;            // Packet queue max counts.
    ULONG packet_queue_maxtime;                 // Packet queue max time.
    WDFQUEUE read_queue;                        // Read queue.
    WDFWORKITEM workers[WINDIVERT_CONTEXT_MAXWORKERS];
                                                // Read workers.
    UINT8 worker_curr;                          // Current read worker.
    UINT8 layer;                                // Context's layer.
    UINT64 flags;                               // Context's flags.
    UINT32 priority;                            // Context's priority.
    GUID callout_guid[WINDIVERT_CONTEXT_MAXLAYERS];
                                                // Callout GUIDs.
    GUID filter_guid[WINDIVERT_CONTEXT_MAXLAYERS];
                                                // Filter GUIDs.
    BOOL installed[WINDIVERT_CONTEXT_MAXLAYERS];
                                                // What is installed?
    BOOL on;                                    // Is filtering on?
    HANDLE engine_handle;                       // WFP engine handle.
    filter_t filter;                            // Packet filter.
};
typedef struct context_s context_s;
typedef struct context_s *context_t;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(context_s, windivert_context_get);

#define WINDIVERT_TIMEOUT(context, t0, t1)                                  \
    (((t1) >= (t0)? (t1) - (t0): (t0) - (t1)) >                             \
        (context)->packet_queue_maxcounts)

/*
 * WinDivert Layer information.
 */
typedef void (*windivert_callout_t)(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
struct layer_s
{
    wchar_t *sublayer_name;                 // Sub-layer name.
    wchar_t *sublayer_desc;                 // Sub-layer description.
    wchar_t *callout_name;                  // Call-out name.
    wchar_t *callout_desc;                  // Call-out description.
    wchar_t *filter_name;                   // Filter name.
    wchar_t *filter_desc;                   // Filter description.
    GUID layer_guid;                        // WFP layer GUID.
    GUID sublayer_guid;                     // Sub-layer GUID.
    windivert_callout_t callout;            // Call-out.
};
typedef struct layer_s *layer_t;

/*
 * WinDivert request context.
 */
struct req_context_s
{
    PWINDIVERT_ADDRESS addr;                // Pointer to address structure.
};
typedef struct req_context_s req_context_s;
typedef struct req_context_s *req_context_t;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(req_context_s, windivert_req_context_get);

/*
 * WinDivert packet structure.
 */
#define WINDIVERT_WORK_QUEUE_LEN_MAX        2048
struct packet_s
{
    LIST_ENTRY entry;                       // Entry for queue.
    UINT8 direction;                        // Packet direction.
    BOOL is_ipv4:1;                         // Is IPv4?
    BOOL forward:1;                         // Is forward?
    BOOL impostor:1;                        // Is Impostor?
    BOOL loopback:1;                        // Is loopback?
    BOOL match:1;                           // Matches filter?
    UINT32 if_idx;                          // Interface index.
    UINT32 sub_if_idx;                      // Sub-interface index.
    UINT32 priority;                        // Packet priority.
    LONGLONG timestamp;                     // Packet timestamp.
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO checksums;
                                            // Checksum information.
    size_t data_len;                        // Length of `data'.
    char *data;                             // Packet data.
};
typedef struct packet_s *packet_t;

/*
 * IPv4/IPv6 pseudo headers.
 */
typedef struct
{
    UINT32 SrcAddr;
    UINT32 DstAddr;
    UINT8  Zero;
    UINT8  Protocol;
    UINT16 Length;
} WINDIVERT_PSEUDOHDR, *PWINDIVERT_PSEUDOHDR;

typedef struct
{
    UINT32 SrcAddr[4];
    UINT32 DstAddr[4];
    UINT32 Length;
    UINT32 Zero:24;
    UINT32 NextHdr:8;
} WINDIVERT_PSEUDOV6HDR, *PWINDIVERT_PSEUDOV6HDR;

/*
 * Misc.
 */
#define UINT8_MAX       0xFF
#define UINT16_MAX      0xFFFF
#define UINT32_MAX      0xFFFFFFFF

/*
 * Global state.
 */
static HANDLE inject_handle = NULL;
static HANDLE injectv6_handle = NULL;
static NDIS_HANDLE nbl_pool_handle = NULL;
static NDIS_HANDLE nb_pool_handle = NULL;
static HANDLE engine_handle = NULL;
static LONG priority_counter = 0;
static LONGLONG counts_per_ms = 0;
static POOL_TYPE non_paged_pool = NonPagedPool;

/*
 * Priorities.
 */
#define WINDIVERT_CONTEXT_PRIORITY(priority0)                               \
    windivert_context_priority(priority0)
static UINT32 windivert_context_priority(UINT32 priority0)
{
    UINT16 priority1 = (UINT16)InterlockedIncrement(&priority_counter);
    priority0 -= WINDIVERT_PRIORITY_MIN;
    return ((priority0 << 16) | ((UINT32)priority1 & 0x0000FFFF));
}

#define WINDIVERT_FILTER_WEIGHT(priority)                                   \
    ((UINT64)(UINT32_MAX - (priority)))

/*
 * Prototypes.
 */
static void windivert_driver_unload(void);
extern VOID windivert_ioctl(IN WDFQUEUE queue, IN WDFREQUEST request,
    IN size_t in_length, IN size_t out_len, IN ULONG code);
static NTSTATUS windivert_read(context_t context, WDFREQUEST request);
extern VOID windivert_worker(IN WDFWORKITEM item);
static void windivert_read_service(context_t context);
extern VOID windivert_create(IN WDFDEVICE device, IN WDFREQUEST request,
    IN WDFFILEOBJECT object);
static NTSTATUS windivert_install_sublayer(layer_t layer);
static NTSTATUS windivert_install_callouts(context_t context, UINT8 layer,
    BOOL is_inbound, BOOL is_outbound, BOOL is_ipv4, BOOL is_ipv6);
static NTSTATUS windivert_install_callout(context_t context, UINT idx,
    layer_t layer);
static void windivert_uninstall_callouts(context_t context,
    context_state_t state);
extern VOID windivert_cleanup(IN WDFFILEOBJECT object);
extern VOID windivert_close(IN WDFFILEOBJECT object);
extern VOID windivert_destroy(IN WDFOBJECT object);
extern NTSTATUS windivert_write(context_t context, WDFREQUEST request,
    PWINDIVERT_ADDRESS addr);
extern void NTAPI windivert_inject_complete(VOID *context,
    NET_BUFFER_LIST *packets, BOOLEAN dispatch_level);
static NTSTATUS windivert_notify_callout(IN FWPS_CALLOUT_NOTIFY_TYPE type,
    IN const GUID *filter_key, IN const FWPS_FILTER0 *filter);
static void windivert_classify_outbound_network_v4_callout(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_classify_inbound_network_v4_callout(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_classify_outbound_network_v6_callout(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_classify_inbound_network_v6_callout(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_classify_forward_network_v4_callout(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_classify_forward_network_v6_callout(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_classify_callout(context_t context, IN UINT8 direction,
    IN UINT32 if_idx, IN UINT32 sub_if_idx, IN BOOL is_ipv4,
    IN BOOL loopback, IN UINT advance, IN OUT void *data,
    IN UINT64 flow_context, OUT FWPS_CLASSIFY_OUT0 *result);
static BOOL windivert_queue_work(context_t context, BOOL sniff_mode,
    BOOL drop_mode, PNET_BUFFER_LIST buffers, PNET_BUFFER buffer,
    UINT8 direction, UINT32 if_idx, UINT32 sub_if_idx, BOOL is_ipv4,
    BOOL forward, BOOL impostor, BOOL loopback, BOOL match, UINT32 priority,
    LONGLONG timestamp);
static void windivert_queue_packet(context_t context, packet_t packet);
static void windivert_reinject_packet(packet_t packet);
static void windivert_free_packet(packet_t packet);
static BOOL windivert_decrement_ttl(PVOID data, BOOL is_ipv4, BOOL checksum);
static UINT8 windivert_skip_headers(UINT8 proto, UINT8 **header, size_t *len);
static int windivert_big_num_compare(const UINT32 *a, const UINT32 *b);
static BOOL windivert_filter(PNET_BUFFER buffer, UINT32 if_idx,
    UINT32 sub_if_idx, BOOL outbound, BOOL is_ipv4, BOOL impostor,
    BOOL loopback, filter_t filter);
static filter_t windivert_filter_compile(windivert_ioctl_filter_t ioctl_filter,
    size_t ioctl_filter_len);
static void windivert_filter_analyze(filter_t filter, BOOL *is_inbound,
    BOOL *is_outbound, BOOL *ip_ipv4, BOOL *is_ipv6);
static BOOL windivert_filter_test(filter_t filter, UINT16 ip, UINT8 protocol,
    UINT8 field, UINT32 arg);

/*
 * WinDivert sublayer GUIDs
 */
DEFINE_GUID(WINDIVERT_SUBLAYER_INBOUND_IPV4_GUID,
    0x09C273C5, 0x0FB1, 0x4453,
    0x95, 0xDF, 0x7E, 0x1C, 0x28, 0x78, 0xED, 0xDF);
DEFINE_GUID(WINDIVERT_SUBLAYER_OUTBOUND_IPV4_GUID,
    0x11C342F5, 0x4276, 0x494F,
    0xBB, 0x30, 0x84, 0x55, 0x78, 0x6C, 0x67, 0x30);
DEFINE_GUID(WINDIVERT_SUBLAYER_INBOUND_IPV6_GUID,
    0x2E5F6801, 0xE721, 0x4A0D,
    0x8D, 0x48, 0xC8, 0x1D, 0x4F, 0x25, 0x45, 0x93);
DEFINE_GUID(WINDIVERT_SUBLAYER_OUTBOUND_IPV6_GUID,
    0xB6511564, 0xD5E6, 0x44C8,
    0x9C, 0x73, 0xBB, 0x22, 0x15, 0x39, 0xEB, 0x8A);
DEFINE_GUID(WINDIVERT_SUBLAYER_FORWARD_IPV4_GUID,
    0xEC5C40E3, 0xE508, 0x408B,
    0xB9, 0x86, 0x58, 0xDE, 0xC7, 0x5F, 0x86, 0xE4);
DEFINE_GUID(WINDIVERT_SUBLAYER_FORWARD_IPV6_GUID,
    0xE70D0973, 0x935F, 0x4790,
    0x8E, 0x64, 0xF7, 0xF7, 0x36, 0x27, 0xA5, 0x8F);

/*
 * WinDivert supported layers.
 */
static struct layer_s layer_inbound_network_ipv4_0 =
{
    L"" WINDIVERT_DEVICE_NAME L"_SubLayerInboundNetworkIPv4",
    L"" WINDIVERT_DEVICE_NAME L" sublayer network (inbound IPv4)",
    L"" WINDIVERT_DEVICE_NAME L"_CalloutInboundNetworkIPv4",
    L"" WINDIVERT_DEVICE_NAME L" callout network (inbound IPv4)",
    L"" WINDIVERT_DEVICE_NAME L"_FilterInboundNetworkIPv4",
    L"" WINDIVERT_DEVICE_NAME L" filter network (inbound IPv4)",
    {0},
    {0},
    windivert_classify_inbound_network_v4_callout,
};
static layer_t layer_inbound_network_ipv4 = &layer_inbound_network_ipv4_0;

static struct layer_s layer_outbound_network_ipv4_0 =
{
    L"" WINDIVERT_DEVICE_NAME L"_SubLayerOutboundNetworkIPv4",
    L"" WINDIVERT_DEVICE_NAME L" sublayer network (outbound IPv4)",
    L"" WINDIVERT_DEVICE_NAME L"_CalloutOutboundNetworkIPv4",
    L"" WINDIVERT_DEVICE_NAME L" callout network (outbound IPv4)",
    L"" WINDIVERT_DEVICE_NAME L"_FilterOutboundNetworkIPv4",
    L"" WINDIVERT_DEVICE_NAME L" filter network (outbound IPv4)",
    {0},
    {0},
    windivert_classify_outbound_network_v4_callout,
};
static layer_t layer_outbound_network_ipv4 = &layer_outbound_network_ipv4_0;

static struct layer_s layer_inbound_network_ipv6_0 =
{
    L"" WINDIVERT_DEVICE_NAME L"_SubLayerInboundNetworkIPv6",
    L"" WINDIVERT_DEVICE_NAME L" sublayer network (inbound IPv6)",
    L"" WINDIVERT_DEVICE_NAME L"_CalloutInboundNetworkIPv6",
    L"" WINDIVERT_DEVICE_NAME L" callout network (inbound IPv6)",
    L"" WINDIVERT_DEVICE_NAME L"_FilterInboundNetworkIPv6",
    L"" WINDIVERT_DEVICE_NAME L" filter network (inbound IPv6)",
    {0},
    {0},
    windivert_classify_inbound_network_v6_callout,
};
static layer_t layer_inbound_network_ipv6 = &layer_inbound_network_ipv6_0;

static struct layer_s layer_outbound_network_ipv6_0 =
{
    L"" WINDIVERT_DEVICE_NAME L"_SubLayerOutboundNetworkIPv6",
    L"" WINDIVERT_DEVICE_NAME L" sublayer network (outbound IPv6)",
    L"" WINDIVERT_DEVICE_NAME L"_CalloutOutboundNetworkIPv6",
    L"" WINDIVERT_DEVICE_NAME L" callout network (outbound IPv6)",
    L"" WINDIVERT_DEVICE_NAME L"_FilterOutboundNetworkIPv6",
    L"" WINDIVERT_DEVICE_NAME L" filter network (outbound IPv6)",
    {0},
    {0},
    windivert_classify_outbound_network_v6_callout,
};
static layer_t layer_outbound_network_ipv6 = &layer_outbound_network_ipv6_0;

static struct layer_s layer_forward_network_ipv4_0 =
{
    L"" WINDIVERT_DEVICE_NAME L"_SubLayerForwardNetworkIPv4",
    L"" WINDIVERT_DEVICE_NAME L" sublayer network (forward IPv4)",
    L"" WINDIVERT_DEVICE_NAME L"_CalloutForwardNetworkIPv4",
    L"" WINDIVERT_DEVICE_NAME L" callout network (forward IPv4)",
    L"" WINDIVERT_DEVICE_NAME L"_FilterForwardNetworkIPv4",
    L"" WINDIVERT_DEVICE_NAME L" filter network (forward IPv4)",
    {0},
    {0},
    windivert_classify_forward_network_v4_callout,
};
static layer_t layer_forward_network_ipv4 = &layer_forward_network_ipv4_0;

static struct layer_s layer_forward_network_ipv6_0 =
{
    L"" WINDIVERT_DEVICE_NAME L"_SubLayerForwardNetworkIPv6",
    L"" WINDIVERT_DEVICE_NAME L" sublayer network (forward IPv6)",
    L"" WINDIVERT_DEVICE_NAME L"_CalloutForwardNetworkIPv6",
    L"" WINDIVERT_DEVICE_NAME L" callout network (forward IPv6)",
    L"" WINDIVERT_DEVICE_NAME L"_FilterForwardNetworkIPv6",
    L"" WINDIVERT_DEVICE_NAME L" filter network (forward IPv6)",
    {0},
    {0},
    windivert_classify_forward_network_v6_callout,
};
static layer_t layer_forward_network_ipv6 = &layer_forward_network_ipv6_0;

/*
 * WinDivert malloc/free.
 */
static PVOID windivert_malloc(SIZE_T size, BOOL paged)
{
    POOL_TYPE pool = (paged? PagedPool: non_paged_pool);
    return ExAllocatePoolWithTag(pool, size, WINDIVERT_TAG);
}
static VOID windivert_free(PVOID ptr)
{
    if (ptr != NULL)
    {
        ExFreePoolWithTag(ptr, WINDIVERT_TAG);
    }
}

/*
 * WinDivert driver entry routine.
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
    NET_BUFFER_LIST_POOL_PARAMETERS nbl_pool_params;
    NET_BUFFER_POOL_PARAMETERS nb_pool_params;
    RTL_OSVERSIONINFOW version;
    LARGE_INTEGER freq;
    NTSTATUS status;
    DECLARE_CONST_UNICODE_STRING(device_name,
        L"\\Device\\" WINDIVERT_DEVICE_NAME);
    DECLARE_CONST_UNICODE_STRING(dos_device_name,
        L"\\??\\" WINDIVERT_DEVICE_NAME);

    DEBUG("LOAD: loading WinDivert driver");

    // Use the "no execute" pool if available:
    status = RtlGetVersion(&version);
    if (NT_SUCCESS(status))
    {
        if (version.dwMajorVersion > 6 ||
            (version.dwMajorVersion == 6 && version.dwMinorVersion >= 2))
        {
            non_paged_pool = (POOL_TYPE)512;    // NonPagedPoolNx (documented)
        }
    }

    // Initialize timer info.
    KeQueryPerformanceCounter(&freq);
    counts_per_ms = freq.QuadPart / 1000;
    counts_per_ms = (counts_per_ms == 0? 1: counts_per_ms);

    // Initialize the layers.
    layer_inbound_network_ipv4->layer_guid = FWPM_LAYER_INBOUND_IPPACKET_V4;
    layer_outbound_network_ipv4->layer_guid = FWPM_LAYER_OUTBOUND_IPPACKET_V4;
    layer_inbound_network_ipv6->layer_guid = FWPM_LAYER_INBOUND_IPPACKET_V6;
    layer_outbound_network_ipv6->layer_guid = FWPM_LAYER_OUTBOUND_IPPACKET_V6;
    layer_forward_network_ipv4->layer_guid = FWPM_LAYER_IPFORWARD_V4;
    layer_forward_network_ipv6->layer_guid = FWPM_LAYER_IPFORWARD_V6;
    layer_inbound_network_ipv4->sublayer_guid =
        WINDIVERT_SUBLAYER_INBOUND_IPV4_GUID;
    layer_outbound_network_ipv4->sublayer_guid = 
        WINDIVERT_SUBLAYER_OUTBOUND_IPV4_GUID;
    layer_inbound_network_ipv6->sublayer_guid = 
        WINDIVERT_SUBLAYER_INBOUND_IPV6_GUID;
    layer_outbound_network_ipv6->sublayer_guid =
        WINDIVERT_SUBLAYER_OUTBOUND_IPV6_GUID;
    layer_forward_network_ipv4->sublayer_guid =
        WINDIVERT_SUBLAYER_FORWARD_IPV4_GUID;
    layer_forward_network_ipv6->sublayer_guid =
        WINDIVERT_SUBLAYER_FORWARD_IPV6_GUID;

    // Configure ourself as a non-PnP driver:
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = windivert_unload;
    status = WdfDriverCreate(driver_obj, reg_path, WDF_NO_OBJECT_ATTRIBUTES,
        &config, &driver);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WDF driver", status);
        goto driver_entry_exit;
    }
    device_init = WdfControlDeviceInitAllocate(driver,
        &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (device_init == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DEBUG_ERROR("failed to allocate WDF control device init structure",
            status);
        goto driver_entry_exit;
    }
    WdfDeviceInitSetDeviceType(device_init, FILE_DEVICE_NETWORK);
    WdfDeviceInitSetIoType(device_init, WdfDeviceIoDirect);
    status = WdfDeviceInitAssignName(device_init, &device_name);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WDF device name", status);
        WdfDeviceInitFree(device_init);
        goto driver_entry_exit;
    }
    WDF_FILEOBJECT_CONFIG_INIT(&file_config, windivert_create, windivert_close,
        windivert_cleanup);
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&obj_attrs, context_s);
    obj_attrs.ExecutionLevel = WdfExecutionLevelPassive;
    obj_attrs.SynchronizationScope = WdfSynchronizationScopeNone;
    obj_attrs.EvtDestroyCallback = windivert_destroy;
    WdfDeviceInitSetFileObjectConfig(device_init, &file_config, &obj_attrs);
    WdfDeviceInitSetIoInCallerContextCallback(device_init,
        windivert_caller_context);
    WDF_OBJECT_ATTRIBUTES_INIT(&obj_attrs);
    status = WdfDeviceCreate(&device_init, &obj_attrs, &device);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WDF control device", status);
        WdfDeviceInitFree(device_init);
        goto driver_entry_exit;
    }
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue_config,
        WdfIoQueueDispatchParallel);
    queue_config.EvtIoRead          = NULL;
    queue_config.EvtIoWrite         = NULL;
    queue_config.EvtIoDeviceControl = windivert_ioctl;
    WDF_OBJECT_ATTRIBUTES_INIT(&obj_attrs);
    obj_attrs.ExecutionLevel = WdfExecutionLevelPassive;
    obj_attrs.SynchronizationScope = WdfSynchronizationScopeNone;
    status = WdfIoQueueCreate(device, &queue_config, &obj_attrs, &queue);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create default WDF queue", status);
        goto driver_entry_exit;
    }
    status = WdfDeviceCreateSymbolicLink(device, &dos_device_name);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create device symbolic link", status);
        goto driver_entry_exit;
    }
    WdfControlFinishInitializing(device);

    // Create the packet injection handles.
    status = FwpsInjectionHandleCreate0(AF_INET, 
        FWPS_INJECTION_TYPE_NETWORK | FWPS_INJECTION_TYPE_FORWARD,
        &inject_handle);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WFP packet injection handle", status);
        goto driver_entry_exit;
    }
    status = FwpsInjectionHandleCreate0(AF_INET6, 
        FWPS_INJECTION_TYPE_NETWORK | FWPS_INJECTION_TYPE_FORWARD,
        &injectv6_handle);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WFP ipv6 packet injection handle",
            status);
        goto driver_entry_exit;
    }

    // Create a NET_BUFFER_LIST pool handle.
    RtlZeroMemory(&nbl_pool_params, sizeof(nbl_pool_params));
    nbl_pool_params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nbl_pool_params.Header.Revision =
        NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    nbl_pool_params.Header.Size = sizeof(nbl_pool_params);
    nbl_pool_params.fAllocateNetBuffer = TRUE;
    nbl_pool_params.PoolTag = WINDIVERT_TAG;
    nbl_pool_params.DataSize = 0;
    nbl_pool_handle = NdisAllocateNetBufferListPool(NULL, &nbl_pool_params);
    if (nbl_pool_handle == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DEBUG_ERROR("failed to allocate net buffer list pool", status);
        goto driver_entry_exit;
    }

    // Create a NET_BUFFER pool handle.
    RtlZeroMemory(&nb_pool_params, sizeof(nb_pool_params));
    nb_pool_params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nb_pool_params.Header.Revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    nb_pool_params.Header.Size =
        NDIS_SIZEOF_NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    nb_pool_params.PoolTag = WINDIVERT_TAG;
    nb_pool_params.DataSize = 0;
    nb_pool_handle = NdisAllocateNetBufferPool(NULL, &nb_pool_params);
    if (nb_pool_handle == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DEBUG_ERROR("failed to allocate net buffer pool", status);
        goto driver_entry_exit;
    }

    // Open a handle to the filter engine:
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL,
        &engine_handle);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WFP engine handle", status);
        goto driver_entry_exit;
    }

    // Register WFP sub-layers:
    status = FwpmTransactionBegin0(engine_handle, 0);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to begin WFP transaction", status);
        goto driver_entry_exit;
    }
    status = windivert_install_sublayer(layer_inbound_network_ipv4);
    if (!NT_SUCCESS(status))
    {
driver_entry_sublayer_error:
        DEBUG_ERROR("failed to install WFP sub-layer", status);
        FwpmTransactionAbort0(engine_handle);
        goto driver_entry_exit;
    }
    status = windivert_install_sublayer(layer_outbound_network_ipv4);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = windivert_install_sublayer(layer_inbound_network_ipv6);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = windivert_install_sublayer(layer_outbound_network_ipv6);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = windivert_install_sublayer(layer_forward_network_ipv4);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = windivert_install_sublayer(layer_forward_network_ipv6);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = FwpmTransactionCommit0(engine_handle);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to commit WFP transaction", status);
        goto driver_entry_exit;
    }

driver_entry_exit:

    if (!NT_SUCCESS(status))
    {
        windivert_driver_unload();
    }

    return status;
}

/*
 * WinDivert driver unload routine.
 */
extern VOID windivert_unload(IN WDFDRIVER Driver)
{
    windivert_driver_unload();
}

/*
 * WinDivert driver unload.
 */
static void windivert_driver_unload(void)
{
    NTSTATUS status;

    DEBUG("UNLOAD: unloading the WinDivert driver");

    if (inject_handle != NULL)
    {
        FwpsInjectionHandleDestroy0(inject_handle);
    }
    if (injectv6_handle != NULL)
    {
        FwpsInjectionHandleDestroy0(injectv6_handle);
    }
    if (nbl_pool_handle != NULL)
    {
        NdisFreeNetBufferListPool(nbl_pool_handle);
    }
    if (nb_pool_handle != NULL)
    {
        NdisFreeNetBufferPool(nb_pool_handle);
    }
    if (engine_handle != NULL)
    {
        status = FwpmTransactionBegin0(engine_handle, 0);
        if (!NT_SUCCESS(status))
        {
            DEBUG_ERROR("failed to begin WFP transaction", status);
            FwpmEngineClose0(engine_handle);
            return;
        }
        FwpmSubLayerDeleteByKey0(engine_handle,
            &layer_inbound_network_ipv4->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            &layer_outbound_network_ipv4->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            &layer_inbound_network_ipv6->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            &layer_outbound_network_ipv6->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            &layer_forward_network_ipv4->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            &layer_forward_network_ipv6->sublayer_guid);
        status = FwpmTransactionCommit0(engine_handle);
        if (!NT_SUCCESS(status))
        {
            DEBUG_ERROR("failed to commit WFP transaction", status);
        }
        FwpmEngineClose0(engine_handle);
    }
}

/*
 * Register a sub-layer.
 */
static NTSTATUS windivert_install_sublayer(layer_t layer)
{
    FWPM_SUBLAYER0 sublayer;
    NTSTATUS status;

    RtlZeroMemory(&sublayer, sizeof(sublayer));
    sublayer.subLayerKey = layer->sublayer_guid;
    sublayer.displayData.name        = layer->sublayer_name;
    sublayer.displayData.description = layer->sublayer_desc;
    sublayer.weight = UINT16_MAX;

    status = FwpmSubLayerAdd0(engine_handle, &sublayer, NULL);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to add WFP sub-layer", status);
    }
    
    return status;
}

/*
 * WinDivert create routine.
 */
extern VOID windivert_create(IN WDFDEVICE device, IN WDFREQUEST request,
    IN WDFFILEOBJECT object)
{
    WDF_IO_QUEUE_CONFIG queue_config;
    WDF_WORKITEM_CONFIG item_config;
    WDF_OBJECT_ATTRIBUTES obj_attrs;
    FWPM_SESSION0 session;
    NTSTATUS status = STATUS_SUCCESS;
    UINT8 i;
    context_t context = windivert_context_get(object);

    DEBUG("CREATE: creating a new WinDivert context (context=%p)", context);

    // Initialise the new context:
    context->state  = WINDIVERT_CONTEXT_STATE_OPENING;
    context->device = device;
    context->object = object;
    context->work_queue_length = 0;
    context->packet_queue_length = 0;
    context->packet_queue_maxlength = WINDIVERT_PARAM_QUEUE_LEN_DEFAULT;
    context->packet_queue_size = 0;
    context->packet_queue_maxsize = WINDIVERT_PARAM_QUEUE_SIZE_DEFAULT;
    context->packet_queue_maxcounts =
        WINDIVERT_PARAM_QUEUE_TIME_DEFAULT * counts_per_ms;
    context->packet_queue_maxtime = WINDIVERT_PARAM_QUEUE_TIME_DEFAULT;
    context->layer = WINDIVERT_LAYER_DEFAULT;
    context->flags = 0;
    context->priority = WINDIVERT_CONTEXT_PRIORITY(WINDIVERT_PRIORITY_DEFAULT);
    context->filter = NULL;
    for (i = 0; i < WINDIVERT_CONTEXT_MAXWORKERS; i++)
    {
        context->workers[i] = NULL;
    }
    context->worker_curr = 0;
    for (i = 0; i < WINDIVERT_CONTEXT_MAXLAYERS; i++)
    {
        context->installed[i] = FALSE;
    }
    context->on = FALSE;
    KeInitializeSpinLock(&context->lock);
    InitializeListHead(&context->work_queue);
    InitializeListHead(&context->packet_queue);
    for (i = 0; i < WINDIVERT_CONTEXT_MAXLAYERS; i++)
    {
        status = ExUuidCreate(&context->callout_guid[i]);
        if (!NT_SUCCESS(status))
        {
            DEBUG_ERROR("failed to create callout GUID", status);
            goto windivert_create_exit;
        }
        status = ExUuidCreate(&context->filter_guid[i]);
        if (!NT_SUCCESS(status))
        {
            DEBUG_ERROR("failed to create filter GUID", status);
            goto windivert_create_exit;
        }
    }
    WDF_IO_QUEUE_CONFIG_INIT(&queue_config, WdfIoQueueDispatchManual);
    status = WdfIoQueueCreate(device, &queue_config, WDF_NO_OBJECT_ATTRIBUTES,
        &context->read_queue);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create I/O read queue", status);
        goto windivert_create_exit;
    }
    WDF_WORKITEM_CONFIG_INIT(&item_config, windivert_worker);
    item_config.AutomaticSerialization = FALSE;
    WDF_OBJECT_ATTRIBUTES_INIT(&obj_attrs);
    obj_attrs.ParentObject = (WDFOBJECT)object;
    for (i = 0; i < WINDIVERT_CONTEXT_MAXWORKERS; i++)
    {
        status = WdfWorkItemCreate(&item_config, &obj_attrs,
            context->workers + i);
        if (!NT_SUCCESS(status))
        {
            DEBUG_ERROR("failed to create read service work item", status);
            goto windivert_create_exit;
        }
    }
    RtlZeroMemory(&session, sizeof(session));
    session.flags |= FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session,
        &context->engine_handle);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WFP engine handle", status);
        goto windivert_create_exit;
    }
    context->state = WINDIVERT_CONTEXT_STATE_OPEN;

windivert_create_exit:

    // Clean-up on error:
    if (!NT_SUCCESS(status))
    {
        context->state = WINDIVERT_CONTEXT_STATE_INVALID;
        if (context->read_queue != NULL)
        {
            WdfObjectDelete(context->read_queue);
        }
        for (i = 0; i < WINDIVERT_CONTEXT_MAXWORKERS; i++)
        {
            if (context->workers[i] != NULL)
            {
                WdfObjectDelete(context->workers[i]);
            }
        }
        if (context->engine_handle != NULL)
        {
            FwpmEngineClose0(context->engine_handle);
        }
    }

    WdfRequestComplete(request, status);
}

/*
 * Register all WFP callouts.
 */
static NTSTATUS windivert_install_callouts(context_t context, UINT8 layer,
    BOOL is_inbound, BOOL is_outbound, BOOL is_ipv4, BOOL is_ipv6)
{
    UINT8 i, j;
    layer_t layers[WINDIVERT_CONTEXT_MAXLAYERS];
    NTSTATUS status = STATUS_SUCCESS;

    i = 0;
    switch (layer)
    {
        case WINDIVERT_LAYER_NETWORK:
            if (is_inbound && is_ipv4)
            {
                layers[i++] = layer_inbound_network_ipv4;
            }
            if (is_outbound && is_ipv4)
            {
                layers[i++] = layer_outbound_network_ipv4;
            }
            if (is_inbound && is_ipv6)
            {
                layers[i++] = layer_inbound_network_ipv6;
            }
            if (is_outbound && is_ipv6)
            {
                layers[i++] = layer_outbound_network_ipv6;
            }
            break;

        case WINDIVERT_LAYER_NETWORK_FORWARD:
            if (is_ipv4)
            {
                layers[i++] = layer_forward_network_ipv4;
            }
            if (is_ipv6)
            {
                layers[i++] = layer_forward_network_ipv6;
            }
            break;

        default:
            return STATUS_INVALID_PARAMETER;
    }

    for (j = 0; j < i; j++)
    {
        status = windivert_install_callout(context, j, layers[j]);
        if (!NT_SUCCESS(status))
        {
            goto windivert_install_callouts_exit;
        }
    }

windivert_install_callouts_exit:

    if (!NT_SUCCESS(status))
    {
        windivert_uninstall_callouts(context, WINDIVERT_CONTEXT_STATE_OPEN);
    }

    return status;
}

/*
 * Register a WFP callout.
 */
static NTSTATUS windivert_install_callout(context_t context, UINT idx,
    layer_t layer)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    FWPS_CALLOUT0 scallout;
    FWPM_CALLOUT0 mcallout;
    FWPM_FILTER0 filter;
    UINT64 weight;
    UINT32 priority;
    GUID callout_guid, filter_guid;
    WDFDEVICE device;
    HANDLE engine_handle;
    NTSTATUS status;

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != WINDIVERT_CONTEXT_STATE_OPEN)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        status = STATUS_INVALID_DEVICE_STATE;
        return status;
    }
    priority = context->priority;
    callout_guid = context->callout_guid[idx];
    filter_guid = context->filter_guid[idx];
    device = context->device;
    engine_handle = context->engine_handle;
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    weight = WINDIVERT_FILTER_WEIGHT(priority);
    
    RtlZeroMemory(&scallout, sizeof(scallout));
    scallout.calloutKey              = callout_guid;
    scallout.classifyFn              = layer->callout;
    scallout.notifyFn                = windivert_notify_callout;
    scallout.flowDeleteFn            = NULL;
    RtlZeroMemory(&mcallout, sizeof(mcallout));
    mcallout.calloutKey              = callout_guid;
    mcallout.displayData.name        = layer->callout_name;
    mcallout.displayData.description = layer->callout_desc;
    mcallout.applicableLayer         = layer->layer_guid;
    RtlZeroMemory(&filter, sizeof(filter));
    filter.filterKey                 = filter_guid;
    filter.layerKey                  = layer->layer_guid;
    filter.displayData.name          = layer->filter_name;
    filter.displayData.description   = layer->filter_desc;
    filter.action.type               = FWP_ACTION_CALLOUT_UNKNOWN;
    filter.action.calloutKey         = callout_guid;
    filter.subLayerKey               = layer->sublayer_guid;
    filter.weight.type               = FWP_UINT64;
    filter.weight.uint64             = &weight;
    filter.rawContext                = (UINT64)context;
    status = FwpsCalloutRegister0(WdfDeviceWdmGetDeviceObject(device),
        &scallout, NULL);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to install WFP callout", status);
        return status;
    }
    status = FwpmTransactionBegin0(engine_handle, 0);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to begin WFP transaction", status);
        FwpsCalloutUnregisterByKey0(&callout_guid);
        return status;
    }
    status = FwpmCalloutAdd0(engine_handle, &mcallout, NULL, NULL);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to add WFP callout", status);
        goto windivert_install_callout_error;
    }
    status = FwpmFilterAdd0(engine_handle, &filter, NULL, NULL);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to add WFP filter", status);
        goto windivert_install_callout_error;
    }
    status = FwpmTransactionCommit0(engine_handle);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to commit WFP transaction", status);
        FwpsCalloutUnregisterByKey0(&callout_guid);
        return status;
    }

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != WINDIVERT_CONTEXT_STATE_OPEN)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        FwpsCalloutUnregisterByKey0(&callout_guid);
        status = STATUS_INVALID_DEVICE_STATE;
        return status;
    }
    context->installed[idx] = TRUE;
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    return STATUS_SUCCESS;

windivert_install_callout_error:
    FwpmTransactionAbort0(engine_handle);
    FwpsCalloutUnregisterByKey0(&callout_guid);
    return status;
}

/*
 * WinDivert uninstall callouts routine.
 */
static void windivert_uninstall_callouts(context_t context,
    context_state_t state)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    UINT i;
    HANDLE engine_handle;
    BOOL installed;
    GUID callout_guid, filter_guid;
    NTSTATUS status;

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != state)
    {
windivert_uninstall_callouts_error:
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        status = STATUS_INVALID_DEVICE_STATE;
        DEBUG_ERROR("failed to delete filters and callouts", status);
        return;
    }
    engine_handle = context->engine_handle;
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    status = FwpmTransactionBegin0(engine_handle, 0);
    if (!NT_SUCCESS(status))
    {
        // If the userspace app closes without closing the handle to
        // WinDivert, any actions on engine_handle fail because the
        // RPC handle was closed first. So, this path is "normal" if
        // the user's app crashed or never closed the WinDivert handle.
        DEBUG_ERROR("failed to begin WFP transaction", status);
        goto unregister_callouts;
    }
    for (i = 0; i < WINDIVERT_CONTEXT_MAXLAYERS; i++)
    {
        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
        if (context->state != state)
        {
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            FwpmTransactionAbort0(engine_handle);
            status = STATUS_INVALID_DEVICE_STATE;
            DEBUG_ERROR("failed to delete filters and callouts", status);
            return;
        }
        installed = context->installed[i];
        callout_guid = context->callout_guid[i];
        filter_guid = context->filter_guid[i];
        KeReleaseInStackQueuedSpinLock(&lock_handle);

	    if (!installed)
	    {
	        continue;
	    }
        status = FwpmFilterDeleteByKey0(engine_handle, &filter_guid);
        if (!NT_SUCCESS(status))
        {
            DEBUG_ERROR("failed to delete filter", status);
            break;
        }
        status = FwpmCalloutDeleteByKey0(engine_handle, &callout_guid);
        if (!NT_SUCCESS(status))
        {
            DEBUG_ERROR("failed to delete callout", status);
            break;
        }
    }
    if (!NT_SUCCESS(status))
    {
        FwpmTransactionAbort0(engine_handle);
        goto unregister_callouts;
    }
    status = FwpmTransactionCommit0(engine_handle);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to commit WFP transaction", status);
        //fallthrough
    }
unregister_callouts:
    for (i = 0; i < WINDIVERT_CONTEXT_MAXLAYERS; i++)
    {
        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
        if (context->state != state)
        {
            goto windivert_uninstall_callouts_error;
        }
        installed = context->installed[i];
        callout_guid = context->callout_guid[i];
        context->installed[i] = FALSE;
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        if (!installed)
        {
            continue;
        }
        FwpsCalloutUnregisterByKey0(&callout_guid);
    }
}

/*
 * Divert cleanup routine.
 */
extern VOID windivert_cleanup(IN WDFFILEOBJECT object)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    PLIST_ENTRY entry;
    UINT i;
    context_t context = windivert_context_get(object);
    packet_t work, packet;
    WDFQUEUE read_queue;
    WDFWORKITEM worker;
    LONGLONG timestamp;
    BOOL sniff_mode, timeout, forward;
    UINT priority;
    NTSTATUS status;
    
    DEBUG("CLEANUP: cleaning up WinDivert context (context=%p)", context);

    timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != WINDIVERT_CONTEXT_STATE_OPEN)
    {
windivert_cleanup_error:
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        status = STATUS_INVALID_DEVICE_STATE;
        DEBUG_ERROR("failed to verify state for cleanup routine", status);
        return;
    }
    context->state = WINDIVERT_CONTEXT_STATE_CLOSING;
    sniff_mode = ((context->flags & WINDIVERT_FLAG_SNIFF) != 0);
    forward = (context->layer == WINDIVERT_LAYER_NETWORK_FORWARD);
    priority = context->priority;
    while (!IsListEmpty(&context->packet_queue))
    {
        entry = RemoveHeadList(&context->packet_queue);
        packet = CONTAINING_RECORD(entry, struct packet_s, entry);
        context->packet_queue_length--;
        context->packet_queue_size -= packet->data_len;
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        timeout = WINDIVERT_TIMEOUT(context, packet->timestamp, timestamp);
        if (!timeout)
        {
            windivert_reinject_packet(packet);
        }
        else
        {
            windivert_free_packet(packet);
        }
        timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
        if (context->state != WINDIVERT_CONTEXT_STATE_CLOSING)
        {
            goto windivert_cleanup_error;
        }
    }
    while (!IsListEmpty(&context->work_queue))
    {
        entry = RemoveHeadList(&context->work_queue);
        context->work_queue_length--;
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        work = CONTAINING_RECORD(entry, struct packet_s, entry);
        timeout = WINDIVERT_TIMEOUT(context, work->timestamp, timestamp);
        if (!timeout)
        {
            windivert_reinject_packet(work);
        }
        else
        {
            windivert_free_packet(work);
        }
        timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
        if (context->state != WINDIVERT_CONTEXT_STATE_CLOSING)
        {
            goto windivert_cleanup_error;
        }
    }
    read_queue = context->read_queue;
    KeReleaseInStackQueuedSpinLock(&lock_handle);
    WdfIoQueuePurge(read_queue, NULL, NULL);
    WdfObjectDelete(read_queue);
    for (i = 0; i < WINDIVERT_CONTEXT_MAXWORKERS; i++)
    {
        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
        if (context->state != WINDIVERT_CONTEXT_STATE_CLOSING)
        {
            goto windivert_cleanup_error;
        }
        worker = context->workers[i];
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        WdfWorkItemFlush(worker);
        WdfObjectDelete(worker);
    }
    windivert_uninstall_callouts(context, WINDIVERT_CONTEXT_STATE_CLOSING);
    FwpmEngineClose0(context->engine_handle);
}

/*
 * WinDivert close routine.
 */
extern VOID windivert_close(IN WDFFILEOBJECT object)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    context_t context = windivert_context_get(object);
    NTSTATUS status;
    
    DEBUG("CLOSE: closing WinDivert context (context=%p)", context);
    
    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != WINDIVERT_CONTEXT_STATE_CLOSING)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        status = STATUS_INVALID_DEVICE_STATE;
        DEBUG_ERROR("failed to verify state for close routine", status);
        return;
    }
    context->state = WINDIVERT_CONTEXT_STATE_CLOSED;
    KeReleaseInStackQueuedSpinLock(&lock_handle);
}

/*
 * WinDivert destroy routine.
 */
extern VOID windivert_destroy(IN WDFOBJECT object)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    context_t context = windivert_context_get((WDFFILEOBJECT)object);
    filter_t filter;
    NTSTATUS status;

    DEBUG("DESTROY: destroying WinDivert context (context=%p)", context);

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != WINDIVERT_CONTEXT_STATE_CLOSED)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        status = STATUS_INVALID_DEVICE_STATE;
        DEBUG_ERROR("failed to verify state for destroy routine", status);
        return;
    }
    filter = context->filter;
    KeReleaseInStackQueuedSpinLock(&lock_handle);
    windivert_free(filter);
}

/*
 * WinDivert read routine.
 */
static NTSTATUS windivert_read(context_t context, WDFREQUEST request)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    NTSTATUS status = STATUS_SUCCESS;

    DEBUG("READ: reading diverted packet (context=%p, request=%p)", context,
        request);

    // Forward the request to the pending read queue:
    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != WINDIVERT_CONTEXT_STATE_OPEN)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        return STATUS_INVALID_DEVICE_STATE;
    }
    status = WdfRequestForwardToIoQueue(request, context->read_queue);
    KeReleaseInStackQueuedSpinLock(&lock_handle);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to forward I/O request to read queue", status);
        return status;
    }

    // Service the read request:
    windivert_read_service(context);

    return STATUS_SUCCESS;
}

/*
 * WinDivert service a single read request.
 */
static void windivert_read_service_request(packet_t packet, WDFREQUEST request)
{
    PMDL dst_mdl;
    PVOID dst, src;
    ULONG dst_len, src_len;
    req_context_t req_context;
    PWINDIVERT_ADDRESS addr;
    NTSTATUS status;

    DEBUG("SERVICE: servicing read request (request=%p, packet=%p)", request,
        packet);
        
    status = WdfRequestRetrieveOutputWdmMdl(request, &dst_mdl);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to retrieve output MDL", status);
        goto windivert_read_service_request_exit;
    }
    dst = MmGetSystemAddressForMdlSafe(dst_mdl, NormalPagePriority);
    if (dst == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DEBUG_ERROR("failed to get address of output MDL", status);
        goto windivert_read_service_request_exit;
    }

    dst_len = MmGetMdlByteCount(dst_mdl);
    src_len = packet->data_len;
    dst_len = (src_len < dst_len? src_len: dst_len);
    src = packet->data;
    RtlCopyMemory(dst, src, dst_len);

    // Write the address information.
    req_context = windivert_req_context_get(request);
    addr = req_context->addr;
    if (addr != NULL)
    {
        addr->Timestamp = (INT64)packet->timestamp;
        addr->IfIdx = packet->if_idx;
        addr->SubIfIdx = packet->sub_if_idx;
        addr->Direction = packet->direction;
        addr->Loopback = (packet->loopback? 1: 0);
        addr->Impostor = (packet->impostor? 1: 0);
        if (packet->loopback)
        {
            addr->PseudoIPChecksum = addr->PseudoTCPChecksum =
                addr->PseudoUDPChecksum = 1;
        }
        else if (packet->forward)
        {
            addr->PseudoIPChecksum = addr->PseudoTCPChecksum =
                addr->PseudoUDPChecksum = 0;
        }
        else if (packet->direction == WINDIVERT_DIRECTION_OUTBOUND)
        {
            addr->PseudoIPChecksum =
                (UINT8)packet->checksums.Transmit.IpHeaderChecksum;
            addr->PseudoTCPChecksum =
                (UINT8)packet->checksums.Transmit.TcpChecksum;
            addr->PseudoUDPChecksum =
                (UINT8)packet->checksums.Transmit.UdpChecksum;
        }
        else
        {
            addr->PseudoIPChecksum =
                (UINT8)packet->checksums.Receive.IpChecksumSucceeded;
            addr->PseudoTCPChecksum =
                (UINT8)packet->checksums.Receive.TcpChecksumSucceeded;
            addr->PseudoUDPChecksum =
                (UINT8)packet->checksums.Receive.UdpChecksumSucceeded;
        }
        addr->Reserved = 0;
    }

windivert_read_service_request_exit:
    if (NT_SUCCESS(status))
    {
        WdfRequestCompleteWithInformation(request, status, dst_len);
    }
    else
    {
        WdfRequestComplete(request, status);
    }
}

/*
 * WinDivert read request service.
 */
static void windivert_read_service(context_t context)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    WDFREQUEST request;
    PLIST_ENTRY entry;
    PMDL dst_mdl;
    PVOID dst, src;
    ULONG dst_len, src_len;
    LONGLONG timestamp;
    BOOL timeout;
    NTSTATUS status;
    packet_t packet;
    req_context_t req_context;
    PWINDIVERT_ADDRESS addr;

    timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    while (context->state == WINDIVERT_CONTEXT_STATE_OPEN &&
           !IsListEmpty(&context->packet_queue))
    {
        entry = RemoveHeadList(&context->packet_queue);
        packet = CONTAINING_RECORD(entry, struct packet_s, entry);
        timeout = WINDIVERT_TIMEOUT(context, packet->timestamp, timestamp);
        request = NULL;
        if (!timeout)
        {
            status = WdfIoQueueRetrieveNextRequest(context->read_queue,
                &request);
            if (!NT_SUCCESS(status))
            {
                InsertHeadList(&context->packet_queue, entry);
                break;
            }
        }
        context->packet_queue_length--;
        context->packet_queue_size -= packet->data_len;
        KeReleaseInStackQueuedSpinLock(&lock_handle);

        if (!timeout)
        {
            windivert_read_service_request(packet, request);
        }

        windivert_free_packet(packet);
        timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    }
    KeReleaseInStackQueuedSpinLock(&lock_handle);
}

/*
 * WinDivert write routine.
 */
static NTSTATUS windivert_write(context_t context, WDFREQUEST request,
    PWINDIVERT_ADDRESS addr)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    PMDL mdl = NULL, mdl_copy = NULL;
    PVOID data, data_copy = NULL;
    UINT data_len;
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_IPV6HDR ipv6_header;
    BOOL is_ipv4;
    UINT8 layer;
    UINT32 priority;
    UINT64 flags;
    HANDLE handle, compl_handle;
    PNET_BUFFER_LIST buffers = NULL;
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO checksums_info;
    NTSTATUS status = STATUS_SUCCESS;

    DEBUG("WRITE: writing/injecting a packet (context=%p, request=%p)",
        context, request);

    if (addr->Direction != WINDIVERT_DIRECTION_INBOUND &&
        addr->Direction != WINDIVERT_DIRECTION_OUTBOUND)
    {
        status = STATUS_INVALID_PARAMETER;
        DEBUG_ERROR("failed to inject packet; invalid direction", status);
        goto windivert_write_exit;
    }

    status = WdfRequestRetrieveOutputWdmMdl(request, &mdl);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to retrieve input MDL", status);
        goto windivert_write_exit;
    }

    data = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    if (data == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DEBUG_ERROR("failed to get MDL address", status);
        goto windivert_write_exit;
    }
    
    data_len = MmGetMdlByteCount(mdl);
    if (data_len > UINT16_MAX || data_len < sizeof(WINDIVERT_IPHDR))
    {
windivert_write_bad_packet:
        status = STATUS_INVALID_PARAMETER;
        DEBUG_ERROR("failed to inject a bad packet", status);
        goto windivert_write_exit;
    }

    data_copy = windivert_malloc(data_len, FALSE);
    if (data_copy == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DEBUG_ERROR("failed to allocate memory for injected packet data",
            status);
        goto windivert_write_exit;
    }

    RtlCopyMemory(data_copy, data, sizeof(WINDIVERT_IPHDR));
    ip_header = (PWINDIVERT_IPHDR)data_copy;
    switch (ip_header->Version)
    {
        case 4:
            if (data_len != RtlUshortByteSwap(ip_header->Length))
            {
                goto windivert_write_bad_packet;
            }
            is_ipv4 = TRUE;
            break;
        case 6:
            if (data_len < sizeof(WINDIVERT_IPV6HDR))
            {
                goto windivert_write_bad_packet;
            }
            ipv6_header = (PWINDIVERT_IPV6HDR)data_copy;
            if (data_len != RtlUshortByteSwap(ipv6_header->Length) +
                    sizeof(WINDIVERT_IPV6HDR))
            {
                goto windivert_write_bad_packet;
            }
            is_ipv4 = FALSE;
            break;
        default:
            goto windivert_write_bad_packet;
    }
    if (data_len > sizeof(WINDIVERT_IPHDR))
    {
        RtlCopyMemory((char *)data_copy + sizeof(WINDIVERT_IPHDR),
            (char *)data + sizeof(WINDIVERT_IPHDR),
            data_len - sizeof(WINDIVERT_IPHDR));
    }
    if (addr->Impostor && !windivert_decrement_ttl(data_copy, is_ipv4,
            (addr->PseudoIPChecksum == 0)))
    {
        status = STATUS_HOPLIMIT_EXCEEDED;
        goto windivert_write_exit;
    }

    mdl_copy = IoAllocateMdl(data_copy, data_len, FALSE, FALSE, NULL);
    if (mdl_copy == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DEBUG_ERROR("failed to allocate MDL for injected packet", status);
        goto windivert_write_exit;
    }

    MmBuildMdlForNonPagedPool(mdl_copy);
    status = FwpsAllocateNetBufferAndNetBufferList0(nbl_pool_handle, 0, 0,
        mdl_copy, 0, data_len, &buffers);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create NET_BUFFER_LIST for injected packet",
            status);
        goto windivert_write_exit;
    }

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != WINDIVERT_CONTEXT_STATE_OPEN)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        status = STATUS_INVALID_DEVICE_STATE;
        goto windivert_write_exit;
    }
    layer = context->layer;
    priority = context->priority;
    flags = context->flags;
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    if (layer != WINDIVERT_LAYER_NETWORK_FORWARD)
    {
        checksums_info.Value = NET_BUFFER_LIST_INFO(buffers,
            TcpIpChecksumNetBufferListInfo);
        if (addr->Direction == WINDIVERT_DIRECTION_OUTBOUND)
        {
            checksums_info.Transmit.TcpChecksum =
                (addr->PseudoTCPChecksum == 0? 0: 1);
            checksums_info.Transmit.UdpChecksum =
                (addr->PseudoUDPChecksum == 0? 0: 1);
            checksums_info.Transmit.IpHeaderChecksum =
                (addr->PseudoIPChecksum == 0? 0: 1);
        }
        else
        {
            checksums_info.Receive.TcpChecksumSucceeded =
                (addr->PseudoTCPChecksum == 0? 0: 1);
            checksums_info.Receive.UdpChecksumSucceeded =
                (addr->PseudoUDPChecksum == 0? 0: 1);
            checksums_info.Receive.IpChecksumSucceeded =
                (addr->PseudoIPChecksum == 0? 0: 1);
        }
        NET_BUFFER_LIST_INFO(buffers, TcpIpChecksumNetBufferListInfo) =
            checksums_info.Value;
    }
    else
    {
        if (addr->PseudoTCPChecksum != 0 || addr->PseudoUDPChecksum != 0 ||
            addr->PseudoIPChecksum != 0)
        {
            status = STATUS_INVALID_PARAMETER;
            goto windivert_write_exit;
        }
    }

    handle = (is_ipv4? inject_handle: injectv6_handle);
    compl_handle = ((flags & WINDIVERT_FLAG_DEBUG) != 0? (HANDLE)request: NULL);
    if (layer == WINDIVERT_LAYER_NETWORK_FORWARD)
    {
        status = FwpsInjectForwardAsync0(handle, (HANDLE)priority, 0,
            (is_ipv4? AF_INET: AF_INET6), UNSPECIFIED_COMPARTMENT_ID,
            addr->IfIdx, buffers, windivert_inject_complete, compl_handle);
    }
    else if (addr->Direction == WINDIVERT_DIRECTION_OUTBOUND)
    {
        status = FwpsInjectNetworkSendAsync0(handle, (HANDLE)priority, 0,
            UNSPECIFIED_COMPARTMENT_ID, buffers, windivert_inject_complete,
            compl_handle);
    }
    else
    {
        status = FwpsInjectNetworkReceiveAsync0(handle, (HANDLE)priority, 0,
            UNSPECIFIED_COMPARTMENT_ID, addr->IfIdx, addr->SubIfIdx, buffers,
            windivert_inject_complete, compl_handle);
    }

windivert_write_exit:

    if (NT_SUCCESS(status))
    {
        if ((flags & WINDIVERT_FLAG_DEBUG) == 0)
        {
            WdfRequestCompleteWithInformation(request, status, data_len);
        }
    }
    else
    {
        DEBUG_ERROR("failed to inject packet", status);
        if (buffers != NULL)
        {
            FwpsFreeNetBufferList0(buffers);
        }
        if (mdl_copy != NULL)
        {
            IoFreeMdl(mdl_copy);
        }
        windivert_free(data_copy);
    }

    return status;
}

/*
 * WinDivert inject complete routine.
 */
static void NTAPI windivert_inject_complete(VOID *context,
    NET_BUFFER_LIST *buffers, BOOLEAN dispatch_level)
{
    PMDL mdl;
    PVOID data;
    PNET_BUFFER buffer;
    size_t length;
    WDFREQUEST request;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(dispatch_level);

    buffer = NET_BUFFER_LIST_FIRST_NB(buffers);
    request = (WDFREQUEST)context;
    if (request != NULL)
    {
        status = NET_BUFFER_LIST_STATUS(buffers);
        length = 0;
        if (NT_SUCCESS(status))
        {
            length = NET_BUFFER_DATA_LENGTH(buffer);
        }
        WdfRequestCompleteWithInformation(request, status, length);
    }
    mdl = NET_BUFFER_FIRST_MDL(buffer);
    data = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    windivert_free(data);
    IoFreeMdl(mdl);
    FwpsFreeNetBufferList0(buffers);
}

/*
 * WinDivert caller context preprocessing.
 */
VOID windivert_caller_context(IN WDFDEVICE device, IN WDFREQUEST request)
{
    PCHAR inbuf;
    size_t inbuflen;
    WDF_REQUEST_PARAMETERS params;
    WDFMEMORY memobj;
    PWINDIVERT_ADDRESS addr = NULL;
    windivert_ioctl_t ioctl;
    WDF_OBJECT_ATTRIBUTES attributes;
    req_context_t req_context = NULL;
    NTSTATUS status;

    WDF_REQUEST_PARAMETERS_INIT(&params);
    WdfRequestGetParameters(request, &params);

    if (params.Type != WdfRequestTypeDeviceControl)
    {
        goto windivert_caller_context_exit;
    }

    // Get and verify the input buffer.
    status = WdfRequestRetrieveInputBuffer(request, 0, &inbuf, &inbuflen);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to retrieve input buffer", status);
        goto windivert_caller_context_error;
    }

    if (inbuflen != sizeof(struct windivert_ioctl_s))
    {
        status = STATUS_INVALID_PARAMETER;
        DEBUG_ERROR("input buffer not an ioctl message header", status);
        goto windivert_caller_context_error;
    }

    ioctl = (windivert_ioctl_t)inbuf;
    if (ioctl->version != WINDIVERT_IOCTL_VERSION ||
        ioctl->magic != WINDIVERT_IOCTL_MAGIC)
    {
        status = STATUS_INVALID_PARAMETER;
        DEBUG_ERROR("input buffer contained a bad ioctl message header",
            status);
        goto windivert_caller_context_error;
    }

    // Probe and lock user buffers here (if required).
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, req_context_s);
    status = WdfObjectAllocateContext(request, &attributes, &req_context);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to allocate request context for ioctl", status);
        goto windivert_caller_context_error;
    }
    switch (params.Parameters.DeviceIoControl.IoControlCode)
    {
        case IOCTL_WINDIVERT_RECV:
            if ((PVOID)ioctl->arg == NULL)
            {
                status = STATUS_INVALID_PARAMETER;
                DEBUG_ERROR("null arg pointer for RECV ioctl", status);
                goto windivert_caller_context_error;
            }
            status = WdfRequestProbeAndLockUserBufferForWrite(request,
                (PVOID)ioctl->arg, sizeof(WINDIVERT_ADDRESS), &memobj);
            if (!NT_SUCCESS(status))
            {
                DEBUG_ERROR("invalid arg pointer for RECV ioctl", status);
                goto windivert_caller_context_error;
            }
            addr = (PWINDIVERT_ADDRESS)WdfMemoryGetBuffer(memobj, NULL);
            break;

        case IOCTL_WINDIVERT_SEND:
            if ((PVOID)ioctl->arg == NULL)
            {
                status = STATUS_INVALID_PARAMETER;
                DEBUG_ERROR("null arg pointer for SEND ioctl", status);
                goto windivert_caller_context_error;
            }
            status = WdfRequestProbeAndLockUserBufferForRead(request,
                (PVOID)ioctl->arg, sizeof(WINDIVERT_ADDRESS), &memobj);
            if (!NT_SUCCESS(status))
            {
                DEBUG_ERROR("invalid arg pointer for SEND ioctl", status);
                goto windivert_caller_context_error;
            }
            addr = (PWINDIVERT_ADDRESS)WdfMemoryGetBuffer(memobj, NULL);
            break;

        case IOCTL_WINDIVERT_START_FILTER:
        case IOCTL_WINDIVERT_SET_LAYER:
        case IOCTL_WINDIVERT_SET_PRIORITY:
        case IOCTL_WINDIVERT_SET_FLAGS:
        case IOCTL_WINDIVERT_SET_PARAM:
        case IOCTL_WINDIVERT_GET_PARAM:
            break;
        
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            DEBUG_ERROR("failed to complete I/O control; invalid request",
                status);
            goto windivert_caller_context_error;
    }
    
    req_context->addr = addr;

windivert_caller_context_exit:

    status = WdfDeviceEnqueueRequest(device, request);
    
windivert_caller_context_error:    
    
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to enqueue request", status);
        WdfRequestComplete(request, status);
    }
}

/*
 * WinDivert I/O control.
 */
extern VOID windivert_ioctl(IN WDFQUEUE queue, IN WDFREQUEST request,
    IN size_t out_length, IN size_t in_length, IN ULONG code)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    PCHAR inbuf, outbuf;
    size_t inbuflen, outbuflen, filter0_len;
    windivert_ioctl_t ioctl;
    windivert_ioctl_filter_t filter0;
    filter_t filter;
    UINT8 layer;
    UINT32 priority;
    UINT64 flags;
    PWINDIVERT_ADDRESS addr;
    req_context_t req_context;
    NTSTATUS status = STATUS_SUCCESS;
    context_t context =
        windivert_context_get(WdfRequestGetFileObject(request));
    UINT64 value, *valptr;
    UNREFERENCED_PARAMETER(queue);

    DEBUG("IOCTL: I/O control request (context=%p)", context);

    // Get the buffers and do sanity checks.
    status = WdfRequestRetrieveInputBuffer(request, 0, &inbuf, &inbuflen);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to retrieve input buffer", status);
        goto windivert_ioctl_exit;
    }
    switch (code)
    {
        case IOCTL_WINDIVERT_START_FILTER: case IOCTL_WINDIVERT_GET_PARAM:
            status = WdfRequestRetrieveOutputBuffer(request, 0, &outbuf,
                &outbuflen);
            if (!NT_SUCCESS(status))
            {
                DEBUG_ERROR("failed to retrieve output buffer", status);
                goto windivert_ioctl_exit;
            }
            break;
        default:
            outbuf = NULL;
            outbuflen = 0;
            break;
    }

    // Handle the ioctl:
    switch (code)
    {
        case IOCTL_WINDIVERT_RECV:
            status = windivert_read(context, request);
            if (NT_SUCCESS(status))
            {
                return;
            }
            break;
        
        case IOCTL_WINDIVERT_SEND:
            
            req_context = windivert_req_context_get(request);
            addr = req_context->addr;
            status = windivert_write(context, request, addr);
            if (NT_SUCCESS(status))
            {
                return;
            }
            break;
        
        case IOCTL_WINDIVERT_START_FILTER:
        {
            BOOL is_inbound, is_outbound, is_ipv4, is_ipv6;

            filter0 = (windivert_ioctl_filter_t)outbuf;
            filter0_len = outbuflen;
            filter = windivert_filter_compile(filter0, filter0_len);
            if (filter == NULL)
            {
                status = STATUS_INVALID_PARAMETER;
                DEBUG_ERROR("failed to compile filter", status);
                goto windivert_ioctl_exit;
            }

            KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
            if (context->state != WINDIVERT_CONTEXT_STATE_OPEN || context->on)
            {
                KeReleaseInStackQueuedSpinLock(&lock_handle);
                windivert_free(filter);
                status = STATUS_INVALID_DEVICE_STATE;
                goto windivert_ioctl_exit;
            }
            context->on = TRUE;
            context->filter = filter;
            layer = context->layer;
            KeReleaseInStackQueuedSpinLock(&lock_handle);

            windivert_filter_analyze(filter, &is_inbound, &is_outbound,
                &is_ipv4, &is_ipv6);
            status = windivert_install_callouts(context, layer, is_inbound,
                is_outbound, is_ipv4, is_ipv6);

            break;
        }

        case IOCTL_WINDIVERT_SET_LAYER:
            ioctl = (windivert_ioctl_t)inbuf;
            if (ioctl->arg > WINDIVERT_LAYER_MAX)
            {
                status = STATUS_INVALID_PARAMETER;
                DEBUG_ERROR("failed to set layer; value too big", status);
                goto windivert_ioctl_exit;
            }
            layer = (UINT8)ioctl->arg;
            KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
            if (context->state != WINDIVERT_CONTEXT_STATE_OPEN || context->on)
            {
                KeReleaseInStackQueuedSpinLock(&lock_handle);
                status = STATUS_INVALID_DEVICE_STATE;
                goto windivert_ioctl_exit;
            }
            context->layer = layer;
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            break;

        case IOCTL_WINDIVERT_SET_PRIORITY:
            ioctl = (windivert_ioctl_t)inbuf;
            if (ioctl->arg < WINDIVERT_PRIORITY_MIN ||
                ioctl->arg > WINDIVERT_PRIORITY_MAX)
            {
                status = STATUS_INVALID_PARAMETER;
                DEBUG_ERROR("failed to set priority; value out of range",
                    status);
                goto windivert_ioctl_exit;
            }
            priority = WINDIVERT_CONTEXT_PRIORITY((UINT32)ioctl->arg);
            KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
            if (context->state != WINDIVERT_CONTEXT_STATE_OPEN || context->on)
            {
                KeReleaseInStackQueuedSpinLock(&lock_handle);
                status = STATUS_INVALID_DEVICE_STATE;
                goto windivert_ioctl_exit;
            }
            context->priority = priority;
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            break;

        case IOCTL_WINDIVERT_SET_FLAGS:
            ioctl = (windivert_ioctl_t)inbuf;
            if (!WINDIVERT_FLAGS_VALID(ioctl->arg))
            {
                status = STATUS_INVALID_PARAMETER;
                DEBUG_ERROR("failed to set flags; invalid flags value",
                    status);
                goto windivert_ioctl_exit;
            }
            flags = ioctl->arg;
            KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
            if (context->state != WINDIVERT_CONTEXT_STATE_OPEN || context->on)
            {
                KeReleaseInStackQueuedSpinLock(&lock_handle);
                status = STATUS_INVALID_DEVICE_STATE;
                goto windivert_ioctl_exit;
            }
            context->flags = flags;
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            break;

        case IOCTL_WINDIVERT_SET_PARAM:
            ioctl = (windivert_ioctl_t)inbuf;
            value = ioctl->arg;
            KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
            if (context->state != WINDIVERT_CONTEXT_STATE_OPEN)
            {
                KeReleaseInStackQueuedSpinLock(&lock_handle);
                status = STATUS_INVALID_DEVICE_STATE;
                goto windivert_ioctl_exit;
            }
            switch ((WINDIVERT_PARAM)ioctl->arg8)
            {
                case WINDIVERT_PARAM_QUEUE_LEN:
                    if (value < WINDIVERT_PARAM_QUEUE_LEN_MIN ||
                        value > WINDIVERT_PARAM_QUEUE_LEN_MAX)
                    {
                        KeReleaseInStackQueuedSpinLock(&lock_handle);
                        status = STATUS_INVALID_PARAMETER;
                        DEBUG_ERROR("failed to set queue length; invalid "
                            "value", status);
                        goto windivert_ioctl_exit;
                    }
                    context->packet_queue_maxlength = (ULONG)value;
                    break;

                case WINDIVERT_PARAM_QUEUE_TIME:
                    if (value < WINDIVERT_PARAM_QUEUE_TIME_MIN ||
                        value > WINDIVERT_PARAM_QUEUE_TIME_MAX)
                    {
                        KeReleaseInStackQueuedSpinLock(&lock_handle);
                        status = STATUS_INVALID_PARAMETER;
                        DEBUG_ERROR("failed to set queue time; invalid "
                            "value", status);
                        goto windivert_ioctl_exit;
                    }
                    context->packet_queue_maxcounts =
                        (LONGLONG)value * counts_per_ms;
                    context->packet_queue_maxtime = (ULONG)value;
                    break;

                case WINDIVERT_PARAM_QUEUE_SIZE:
                    if (value < WINDIVERT_PARAM_QUEUE_SIZE_MIN ||
                        value > WINDIVERT_PARAM_QUEUE_SIZE_MAX)
                    {
                        KeReleaseInStackQueuedSpinLock(&lock_handle);
                        status = STATUS_INVALID_PARAMETER;
                        DEBUG_ERROR("failed to set queue size; invalid "
                            "value", status);
                        goto windivert_ioctl_exit;
                    }
                    context->packet_queue_maxsize = (ULONG)value;
                    break;

                default:
                    KeReleaseInStackQueuedSpinLock(&lock_handle);
                    status = STATUS_INVALID_PARAMETER;
                    DEBUG_ERROR("failed to set parameter; invalid parameter",
                        status);
                    goto windivert_ioctl_exit;
            }
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            break;

        case IOCTL_WINDIVERT_GET_PARAM:
            ioctl = (windivert_ioctl_t)inbuf;
            if (outbuflen != sizeof(UINT64))
            {
                status = STATUS_INVALID_PARAMETER;
                DEBUG_ERROR("failed to get parameter; invalid output "
                    "buffer size", status);
                goto windivert_ioctl_exit;
            }
            valptr = (UINT64 *)outbuf;
            KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
            if (context->state != WINDIVERT_CONTEXT_STATE_OPEN)
            {
                KeReleaseInStackQueuedSpinLock(&lock_handle);
                status = STATUS_INVALID_DEVICE_STATE;
                goto windivert_ioctl_exit;
            }
            switch ((WINDIVERT_PARAM)ioctl->arg8)
            {
                case WINDIVERT_PARAM_QUEUE_LEN:
                    *valptr = context->packet_queue_maxlength;
                    break;
                case WINDIVERT_PARAM_QUEUE_TIME:
                    *valptr = context->packet_queue_maxtime;
                    break;
                case WINDIVERT_PARAM_QUEUE_SIZE:
                    *valptr = context->packet_queue_maxsize;
                    break;
                default:
                    KeReleaseInStackQueuedSpinLock(&lock_handle);
                    status = STATUS_INVALID_PARAMETER;
                    DEBUG_ERROR("failed to get parameter; invalid parameter",
                        status);
                    goto windivert_ioctl_exit;
            }
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            DEBUG_ERROR("failed to complete I/O control; invalid request",
                status);
            break;
    }

windivert_ioctl_exit:
    WdfRequestComplete(request, status);
}

/*
 * WinDivert notify callout.
 */
static NTSTATUS windivert_notify_callout(IN FWPS_CALLOUT_NOTIFY_TYPE type,
    IN const GUID *filter_key, IN const FWPS_FILTER0 *filter)
{
    UNREFERENCED_PARAMETER(type);
    UNREFERENCED_PARAMETER(filter_key);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

/*
 * WinDivert classify outbound IPv4 callout.
 */
static void windivert_classify_outbound_network_v4_callout(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    windivert_classify_callout((context_t)filter->context,
        WINDIVERT_DIRECTION_OUTBOUND,
        fixed_vals->incomingValue[
            FWPS_FIELD_OUTBOUND_IPPACKET_V4_INTERFACE_INDEX].value.uint32,
        fixed_vals->incomingValue[
            FWPS_FIELD_OUTBOUND_IPPACKET_V4_SUB_INTERFACE_INDEX].value.uint32,
        TRUE,
        (fixed_vals->incomingValue[
            FWPS_FIELD_OUTBOUND_IPPACKET_V4_FLAGS].value.uint32 &
            FWP_CONDITION_FLAG_IS_LOOPBACK) != 0,
        0, data, flow_context, result);
}

/*
 * WinDivert classify outbound IPv6 callout.
 */
static void windivert_classify_outbound_network_v6_callout(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    windivert_classify_callout((context_t)filter->context,
        WINDIVERT_DIRECTION_OUTBOUND,
        fixed_vals->incomingValue[
            FWPS_FIELD_OUTBOUND_IPPACKET_V6_INTERFACE_INDEX].value.uint32,
        fixed_vals->incomingValue[
            FWPS_FIELD_OUTBOUND_IPPACKET_V6_SUB_INTERFACE_INDEX].value.uint32,
        FALSE,
        (fixed_vals->incomingValue[
            FWPS_FIELD_OUTBOUND_IPPACKET_V6_FLAGS].value.uint32 &
            FWP_CONDITION_FLAG_IS_LOOPBACK) != 0,
        0, data, flow_context, result);
}

/*
 * WinDivert classify inbound IPv4 callout.
 */
static void windivert_classify_inbound_network_v4_callout(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    UINT advance = meta_vals->ipHeaderSize;
    windivert_classify_callout((context_t)filter->context,
        WINDIVERT_DIRECTION_INBOUND,
        fixed_vals->incomingValue[
            FWPS_FIELD_INBOUND_IPPACKET_V4_INTERFACE_INDEX].value.uint32,
        fixed_vals->incomingValue[
            FWPS_FIELD_INBOUND_IPPACKET_V4_SUB_INTERFACE_INDEX].value.uint32,
        TRUE,
        (fixed_vals->incomingValue[
            FWPS_FIELD_INBOUND_IPPACKET_V4_FLAGS].value.uint32 &
            FWP_CONDITION_FLAG_IS_LOOPBACK) != 0,
        advance, data, flow_context, result);
}

/*
 * WinDivert classify inbound IPv6 callout.
 */
static void windivert_classify_inbound_network_v6_callout(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    UINT advance = meta_vals->ipHeaderSize;
    windivert_classify_callout((context_t)filter->context,
        WINDIVERT_DIRECTION_INBOUND,
        fixed_vals->incomingValue[
            FWPS_FIELD_INBOUND_IPPACKET_V6_INTERFACE_INDEX].value.uint32,
        fixed_vals->incomingValue[
            FWPS_FIELD_INBOUND_IPPACKET_V6_SUB_INTERFACE_INDEX].value.uint32,
        FALSE,
        (fixed_vals->incomingValue[
            FWPS_FIELD_INBOUND_IPPACKET_V6_FLAGS].value.uint32 &
            FWP_CONDITION_FLAG_IS_LOOPBACK) != 0,
        advance, data, flow_context, result);
}

/*
 * WinDivert classify forward IPv4 callout.
 */
static void windivert_classify_forward_network_v4_callout(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    windivert_classify_callout((context_t)filter->context,
        WINDIVERT_DIRECTION_OUTBOUND,
        fixed_vals->incomingValue[
            FWPS_FIELD_IPFORWARD_V4_DESTINATION_INTERFACE_INDEX].value.uint32,
        0, TRUE, FALSE, 0, data, flow_context, result);
}

/*
 * WinDivert classify forward IPv6 callout.
 */
static void windivert_classify_forward_network_v6_callout(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    windivert_classify_callout((context_t)filter->context,
        WINDIVERT_DIRECTION_OUTBOUND,
        fixed_vals->incomingValue[
            FWPS_FIELD_IPFORWARD_V6_DESTINATION_INTERFACE_INDEX].value.uint32,
        0, FALSE, FALSE, 0, data, flow_context, result);
}

/*
 * WinDivert classify callout.
 */
static void windivert_classify_callout(context_t context, IN UINT8 direction,
    IN UINT32 if_idx, IN UINT32 sub_if_idx, IN BOOL is_ipv4, IN BOOL loopback,
    IN UINT advance, IN OUT void *data, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    FWPS_PACKET_INJECTION_STATE packet_state;
    HANDLE packet_context;
    UINT32 priority, packet_priority;
    PNET_BUFFER_LIST buffers;
    PNET_BUFFER buffer, buffer_fst, buffer_itr;
    BOOL outbound, impostor, sniff_mode, drop_mode, forward, ok;
    WDFOBJECT object;
    PLIST_ENTRY old_entry;
    filter_t filter;
    LONGLONG timestamp;
    NTSTATUS status;

    // Basic checks:
    if (!(result->rights & FWPS_RIGHT_ACTION_WRITE) || data == NULL)
    {
        return;
    }

    result->actionType = FWP_ACTION_CONTINUE;
    buffers = (PNET_BUFFER_LIST)data;
    buffer = NET_BUFFER_LIST_FIRST_NB(buffers);
    if (NET_BUFFER_LIST_NEXT_NBL(buffers) != NULL)
    {
        // This is a fragment group.  This can be ignored since each fragment
        // should have already been indicated.
        return;
    }
    if (is_ipv4)
    {
        packet_state = FwpsQueryPacketInjectionState0(inject_handle, buffers,
            &packet_context);
    }
    else
    {
        packet_state = FwpsQueryPacketInjectionState0(injectv6_handle,
            buffers, &packet_context);
    }

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != WINDIVERT_CONTEXT_STATE_OPEN)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        return;
    }
    sniff_mode = ((context->flags & WINDIVERT_FLAG_SNIFF) != 0);
    drop_mode = ((context->flags & WINDIVERT_FLAG_DROP) != 0);
    forward = (context->layer == WINDIVERT_LAYER_NETWORK_FORWARD);
    priority = context->priority;
    filter = context->filter;
    object = (WDFOBJECT)context->object;
    WdfObjectReference(object);
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    impostor = FALSE;
    if (packet_state == FWPS_PACKET_INJECTED_BY_SELF ||
        packet_state == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF)
    {
        packet_priority = (UINT32)packet_context;
        if (packet_priority >= priority)
        {
            WdfObjectDereference(object);
            return;
        }
    }
    else if (packet_state == FWPS_PACKET_INJECTED_BY_OTHER)
    {
        // This is a packet injected by another driver, possibly an older
        // version of WinDivert.  To prevent block-clone-reinject infinite
        // loops, we mark this packet as an "impostor".
        impostor = TRUE;
    }

    // Loopback packets are considered outbound only.
    if (loopback && direction == WINDIVERT_DIRECTION_INBOUND)
    {
        WdfObjectDereference(object);
        return;
    }

    // Get the timestamp.
    timestamp = KeQueryPerformanceCounter(NULL).QuadPart;

    // Retreat the NET_BUFFER to the IP header, if necessary.
    // If (advance != 0) then this must be in the inbound path, and the
    // NET_BUFFER_LIST must contain exactly one NET_BUFFER.
    if (advance != 0)
    {
        status = NdisRetreatNetBufferDataStart(buffer, advance, 0, NULL);
        if (!NT_SUCCESS(status))
        {
            WdfObjectDereference(object);
            return;
        }
    }

    /*
     * This code is complicated by the fact the a single NET_BUFFER_LIST
     * may contain several NET_BUFFER structures.  Each NET_BUFFER needs to
     * be filtered independently.  To achieve this we do the following:
     * 1) First check if any NET_BUFFER passes the filter.
     * 2) If no, then CONTINUE the entire NET_BUFFER_LIST.
     * 3) Else, split the NET_BUFFER_LIST into individual NET_BUFFERs; and
     *    either queue or re-inject based on the filter.
     */

    // Find the first NET_BUFFER we need to queue:
    buffer_fst = buffer;
    outbound = (direction == WINDIVERT_DIRECTION_OUTBOUND);
    do
    {
        BOOL match = windivert_filter(buffer_fst, if_idx, sub_if_idx,
            outbound, is_ipv4, impostor, loopback, filter);
        if (match)
        {
            break;
        }
        buffer_fst = NET_BUFFER_NEXT_NB(buffer_fst);
    }
    while (buffer_fst != NULL);

    // If no packet matches the filter, CONTINUE the entire NET_BUFFER_LIST.
    if (buffer_fst == NULL)
    {
        WdfObjectDereference(object);
        if (advance != 0)
        {
            NdisAdvanceNetBufferDataStart(buffer, advance, FALSE, NULL);
        }
        return;
    }

    // At least one packet matches the filter.  Queue or re-inject all
    // packets depending on whether they match the filter or not.

    // STEP (1): Queue all non-matching packets up to buffer_fst.
    buffer_itr = buffer;
    while (!sniff_mode && buffer_itr != buffer_fst)
    {
        ok = windivert_queue_work(context, sniff_mode, drop_mode, buffers,
            buffer_itr, direction, if_idx, sub_if_idx, is_ipv4, forward,
            impostor, loopback, FALSE, priority, timestamp);
        if (!ok)
        {
            goto windivert_classify_callout_exit;
        }
        buffer_itr = NET_BUFFER_NEXT_NB(buffer_itr);
    }

    // STEP (2): Queue the first matching packet buffer_fst:
    ok = windivert_queue_work(context, sniff_mode, drop_mode, buffers,
        buffer_fst, direction, if_idx, sub_if_idx, is_ipv4, forward, impostor,
        loopback, TRUE, priority, timestamp);
    if (advance != 0)
    {
        // Advance the NET_BUFFER to its original position.  Note that we can
        // do this here, since if (advance != 0) then there is only one
        // NET_BUFFER in the NET_BUFFER_LIST, meaning that STEPS (1) and (3)
        // will be empty.
        NdisAdvanceNetBufferDataStart(buffer, advance, FALSE, NULL);
    }
    if (!ok)
    {
        goto windivert_classify_callout_exit;
    }

    // STEP (3): Queue all remaining packets:
    buffer_itr = NET_BUFFER_NEXT_NB(buffer_fst);
    while (buffer_itr != NULL)
    {
        BOOL match = windivert_filter(buffer_itr, if_idx, sub_if_idx,
            outbound, is_ipv4, impostor, loopback, filter);
        ok = windivert_queue_work(context, sniff_mode, drop_mode, buffers,
            buffer_itr, direction, if_idx, sub_if_idx, is_ipv4, forward,
            impostor, loopback, match, priority, timestamp);
        if (!ok)
        {
            goto windivert_classify_callout_exit;
        }
        buffer_itr = NET_BUFFER_NEXT_NB(buffer_itr);
    }

windivert_classify_callout_exit:

    WdfObjectDereference(object);
    if (!sniff_mode)
    {
        result->actionType = FWP_ACTION_BLOCK;
        result->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
        result->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}

/*
 * WinDivert work item routine for out-of-band filtering.
 */
VOID windivert_worker(IN WDFWORKITEM item)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    WDFFILEOBJECT object = (WDFFILEOBJECT)WdfWorkItemGetParentObject(item);
    context_t context = windivert_context_get(object);
    PLIST_ENTRY entry;
    packet_t work;

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    while (context->state == WINDIVERT_CONTEXT_STATE_OPEN &&
            !IsListEmpty(&context->work_queue))
    {
        entry = RemoveHeadList(&context->work_queue);
        context->work_queue_length--;
        KeReleaseInStackQueuedSpinLock(&lock_handle);

        work = CONTAINING_RECORD(entry, struct packet_s, entry);
        if (work->match)
        {
            windivert_queue_packet(context, work);
        }
        else
        {
            windivert_reinject_packet(work);
        }

        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    }
    KeReleaseInStackQueuedSpinLock(&lock_handle);
}

/*
 * Queue work.
 */
static BOOL windivert_queue_work(context_t context, BOOL sniff_mode,
    BOOL drop_mode, PNET_BUFFER_LIST buffers, PNET_BUFFER buffer,
    UINT8 direction, UINT32 if_idx, UINT32 sub_if_idx, BOOL is_ipv4,
    BOOL forward, BOOL impostor, BOOL loopback, BOOL match, UINT32 priority,
    LONGLONG timestamp)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    packet_t work;
    UINT data_len;
    PVOID data;
    PLIST_ENTRY old_entry;

    if (!match && sniff_mode)
    {
        return TRUE;
    }
    if (match && drop_mode)
    {
        return TRUE;
    }

    work = (packet_t)windivert_malloc(sizeof(struct packet_s), FALSE);
    if (work == NULL)
    {
        return TRUE;
    }
    data_len = NET_BUFFER_DATA_LENGTH(buffer);
    work->data = windivert_malloc(data_len, FALSE);
    if (work->data == NULL)
    {
        windivert_free_packet(work);
        return TRUE;
    }
    work->data_len = data_len;
    data = NdisGetDataBuffer(buffer, data_len, NULL, 1, 0);
    if (data == NULL)
    {
        NdisGetDataBuffer(buffer, data_len, work->data, 1, 0);
    }
    else
    {
        RtlCopyMemory(work->data, data, data_len);
    }
    work->is_ipv4 = is_ipv4;
    work->forward = forward;
    work->impostor = impostor;
    work->loopback = loopback;
    work->match = match;
    work->direction = direction;
    work->if_idx = if_idx;
    work->sub_if_idx = sub_if_idx;
    work->priority = priority;
    work->timestamp = timestamp;
    work->checksums.Value = NET_BUFFER_LIST_INFO(buffers,
        TcpIpChecksumNetBufferListInfo);
    old_entry = NULL;

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != WINDIVERT_CONTEXT_STATE_OPEN)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        windivert_free_packet(work);
        return FALSE;
    }
    context->work_queue_length++;
    if (context->work_queue_length > WINDIVERT_WORK_QUEUE_LEN_MAX)
    {
        // The work queue is full; as an emergency we drop packets.
        old_entry = RemoveHeadList(&context->work_queue);
        context->work_queue_length--;
    }
    InsertTailList(&context->work_queue, &work->entry);
    WdfWorkItemEnqueue(context->workers[context->worker_curr]);
    context->worker_curr =
        (context->worker_curr + 1) % WINDIVERT_CONTEXT_MAXWORKERS;
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    if (old_entry != NULL)
    {
        work = CONTAINING_RECORD(old_entry, struct packet_s, entry);
        windivert_free_packet(work);
    }

    return TRUE;
}

/*
 * Queue a packet.
 */
static void windivert_queue_packet(context_t context, packet_t packet)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    PLIST_ENTRY entry, old_entry;
    packet_t old_packet;
    LONGLONG timestamp;
    BOOL timeout;

    timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    while (TRUE)
    {
        if (context->state != WINDIVERT_CONTEXT_STATE_OPEN)
        {
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            windivert_free_packet(packet);
            return;
        }
        if (packet->data_len > context->packet_queue_maxsize)
        {
            // (Corner case) the packet is larger than the max queue size:
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            windivert_free_packet(packet);
            return;
        }
        timeout = WINDIVERT_TIMEOUT(context, packet->timestamp, timestamp);
        if (timeout)
        {
            // (Corner case) the packet has already expired:
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            windivert_free_packet(packet);
            return;
        }

        if (context->packet_queue_size + packet->data_len >
                context->packet_queue_maxsize ||
            context->packet_queue_length + 1 > context->packet_queue_maxlength)
        {
            // The queue is full; drop a packet & try again:
            old_entry = RemoveHeadList(&context->packet_queue);
            old_packet = CONTAINING_RECORD(old_entry, struct packet_s, entry);
            context->packet_queue_length--;
            context->packet_queue_size -= old_packet->data_len;
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            DEBUG("DROP: packet queue is full, dropping packet");
            windivert_free_packet(old_packet);
            timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
            KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
            continue;
        }
        else
        {
            // Queue the packet:
            InsertTailList(&context->packet_queue, &packet->entry);
            context->packet_queue_length++;
            context->packet_queue_size += packet->data_len;
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    DEBUG("PACKET: queued packet (packet=%p)", packet);

    // Service any pending I/O request.
    windivert_read_service(context);

    return;
}

/*
 * Re-inject a packet.
 */
static void windivert_reinject_packet(packet_t packet)
{
    PMDL mdl;
    PNET_BUFFER_LIST buffers;
    HANDLE handle;
    UINT32 priority;
    NTSTATUS status;

    mdl = IoAllocateMdl(packet->data, packet->data_len, FALSE, FALSE, NULL);
    if (mdl == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DEBUG_ERROR("failed to allocate MDL for injected packet", status);
        windivert_free_packet(packet);
        return;
    }
    MmBuildMdlForNonPagedPool(mdl);
    status = FwpsAllocateNetBufferAndNetBufferList0(nbl_pool_handle, 0, 0,
        mdl, 0, packet->data_len, &buffers);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create NET_BUFFER_LIST for injected packet",
            status);
        IoFreeMdl(mdl);
        windivert_free_packet(packet);
        return;
    }
    priority = packet->priority;
    NET_BUFFER_LIST_INFO(buffers, TcpIpChecksumNetBufferListInfo) =
        packet->checksums.Value;
    handle = (packet->is_ipv4? inject_handle: injectv6_handle);
    if (packet->forward)
    {
        status = FwpsInjectForwardAsync0(handle, (HANDLE)priority, 0,
            (packet->is_ipv4? AF_INET: AF_INET6), UNSPECIFIED_COMPARTMENT_ID,
            packet->if_idx, buffers, windivert_inject_complete, NULL);
    }
    else if (packet->direction == WINDIVERT_DIRECTION_OUTBOUND)
    {
        status = FwpsInjectNetworkSendAsync0(handle,
            (HANDLE)priority, 0, UNSPECIFIED_COMPARTMENT_ID, buffers,
            windivert_inject_complete, NULL);
    }
    else
    {
        status = FwpsInjectNetworkReceiveAsync0(handle, 
            (HANDLE)priority, 0, UNSPECIFIED_COMPARTMENT_ID, packet->if_idx,
            packet->sub_if_idx, buffers, windivert_inject_complete, NULL);
    }

    if (NT_SUCCESS(status))
    {
        packet->data = NULL;    // Data is now owned by injected NET_BUFFER.
    }
    else
    {
        DEBUG_ERROR("failed to re-inject (packet=%p)", status, packet);
        FwpsFreeNetBufferList0(buffers);
        IoFreeMdl(mdl);
    }
    windivert_free_packet(packet);
}

/*
 * Free a packet.
 */
static void windivert_free_packet(packet_t packet)
{
    windivert_free(packet->data);
    windivert_free(packet);
}

/*
 * Decrement the TTL of a packet.
 */
static BOOL windivert_decrement_ttl(PVOID data, BOOL is_ipv4, BOOL checksum)
{
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_IPV6HDR ipv6_header;

    if (is_ipv4)
    {
        ip_header = (PWINDIVERT_IPHDR)data;
        if (ip_header->TTL <= 1)
        {
            return FALSE;
        }
        ip_header->TTL--;
        if (checksum)
        {
            // Incremental checksum update:
            if (ip_header->Checksum >= 0xFFFE)
            {
                ip_header->Checksum -= 0xFFFE;
            }
            else
            {
                ip_header->Checksum += 1;
            }
        }
    }
    else
    {
        ipv6_header = (PWINDIVERT_IPV6HDR)data;
        if (ipv6_header->HopLimit <= 1)
        {
            return FALSE;
        }
        ipv6_header->HopLimit--;
    }

    return TRUE;
}

/*
 * Skip well-known IPv6 extension headers.
 */
static UINT8 windivert_skip_headers(UINT8 proto, UINT8 **header, size_t *len)
{
    size_t hdrlen;

    while (TRUE)
    {
        if (*len <= 2)
        {
            return IPPROTO_NONE;
        }

        hdrlen = (size_t)*(*header + 1);
        switch (proto)
        {
            case IPPROTO_FRAGMENT:
                hdrlen = 8;
                break;
            case IPPROTO_AH:
                hdrlen += 2;
                hdrlen *= 4;
                break;
            case IPPROTO_HOPOPTS:
            case IPPROTO_DSTOPTS:
            case IPPROTO_ROUTING:
                hdrlen++;
                hdrlen *= 8;
                break;
            case IPPROTO_NONE:
                return proto;
            default:
                return proto;
        }

        if (hdrlen >= *len)
        {
            return IPPROTO_NONE;
        }

        proto = **header;
        *header += hdrlen;
        *len -= hdrlen;
    }
}

/*
 * Big number comparison.
 */
static int windivert_big_num_compare(const UINT32 *a, const UINT32 *b)
{
    if (a[3] < b[3])
    {
        return -1;
    }
    if (a[3] > b[3])
    {
        return 1;
    }
    if (a[2] < b[2])
    {
        return -1;
    }
    if (a[2] > b[2])
    {
        return 1;
    }
    if (a[1] < b[1])
    {
        return -1;
    }
    if (a[1] > b[1])
    {
        return 1;
    }
    if (a[0] < b[0])
    {
        return -1;
    }
    if (a[0] > b[0])
    {
        return 1;
    }
    return 0;
}

/*
 * Checks if the given packet is of interest.
 */
static BOOL windivert_filter(PNET_BUFFER buffer, UINT32 if_idx,
    UINT32 sub_if_idx, BOOL outbound, BOOL is_ipv4, BOOL impostor,
    BOOL loopback, filter_t filter)
{
    size_t tot_len, ip_header_len;
    PWINDIVERT_IPHDR ip_header = NULL;
    PWINDIVERT_IPV6HDR ipv6_header = NULL;
    PWINDIVERT_ICMPHDR icmp_header = NULL;
    PWINDIVERT_ICMPV6HDR icmpv6_header = NULL;
    PWINDIVERT_TCPHDR tcp_header = NULL;
    PWINDIVERT_UDPHDR udp_header = NULL;
    UINT16 ip, ttl;
    UINT8 proto;
    NTSTATUS status;

    // Parse the headers:
    tot_len = NET_BUFFER_DATA_LENGTH(buffer);
    if (tot_len < sizeof(WINDIVERT_IPHDR))
    {
        DEBUG("FILTER: REJECT (packet length too small)");
        return FALSE;
    }

    // Get the IP header.
    if (is_ipv4)
    {
        // IPv4:
        if (tot_len < sizeof(WINDIVERT_IPHDR))
        {
            DEBUG("FILTER: REJECT (packet length too small)");
            return FALSE;
        }
        ip_header = (PWINDIVERT_IPHDR)NdisGetDataBuffer(buffer,
            sizeof(WINDIVERT_IPHDR), NULL, 1, 0);
        if (ip_header == NULL)
        {
            DEBUG("FILTER: REJECT (failed to get IPv4 header)");
            return FALSE;
        }
        ip_header_len = ip_header->HdrLength*sizeof(UINT32);
        if (ip_header->Version != 4 ||
            RtlUshortByteSwap(ip_header->Length) != tot_len ||
            ip_header->HdrLength < 5 ||
            ip_header_len > tot_len)
        {
            DEBUG("FILTER: REJECT (bad IPv4 packet)");
            return FALSE;
        }
        proto = ip_header->Protocol;
        NdisAdvanceNetBufferDataStart(buffer, ip_header_len, FALSE, NULL);
    }
    else
    {
        // IPv6:
        if (tot_len < sizeof(WINDIVERT_IPV6HDR))
        {
            DEBUG("FILTER: REJECT (packet length too small)");
            return FALSE;
        }
        ipv6_header = (PWINDIVERT_IPV6HDR)NdisGetDataBuffer(buffer,
            sizeof(WINDIVERT_IPV6HDR), NULL, 1, 0);
        if (ipv6_header == NULL)
        {
            DEBUG("FILTER: REJECT (failed to get IPv6 header)");
            return FALSE;
        }
        ip_header_len = sizeof(WINDIVERT_IPV6HDR);
        if (ipv6_header->Version != 6 ||
            ip_header_len > tot_len ||
            RtlUshortByteSwap(ipv6_header->Length) +
                sizeof(WINDIVERT_IPV6HDR) != tot_len)
        {
            DEBUG("FILTER: REJECT (bad IPv6 packet)");
            return FALSE;
        }
        proto = ipv6_header->NextHdr;
        NdisAdvanceNetBufferDataStart(buffer, ip_header_len, FALSE, NULL);

        // Skip extension headers:
        while (TRUE)
        {
            UINT8 *ext_header;
            size_t ext_header_len;
            BOOL isexthdr = TRUE;

            ext_header = (UINT8 *)NdisGetDataBuffer(buffer, 2, NULL, 1, 0);
            if (ext_header == NULL)
            {
                break;
            }

            ext_header_len = (size_t)ext_header[1];
            switch (proto)
            {
                case IPPROTO_FRAGMENT:
                    ext_header_len = 8;
                    break;
                case IPPROTO_AH:
                    ext_header_len += 2;
                    ext_header_len *= 4;
                    break;
                case IPPROTO_HOPOPTS:
                case IPPROTO_DSTOPTS:
                case IPPROTO_ROUTING:
                    ext_header_len++;
                    ext_header_len *= 8;
                    break;
                default:
                    isexthdr = FALSE;
                    break;
            }

            if (!isexthdr)
            {
                break;
            }

            proto = ext_header[0];
            ip_header_len += ext_header_len;
            NdisAdvanceNetBufferDataStart(buffer, ext_header_len, FALSE,
                NULL);
        }
    }

    switch (proto)
    {
        case IPPROTO_ICMP:
            icmp_header = (PWINDIVERT_ICMPHDR)NdisGetDataBuffer(buffer,
                sizeof(WINDIVERT_ICMPHDR), NULL, 1, 0);
            break;
        case IPPROTO_ICMPV6:
            icmpv6_header = (PWINDIVERT_ICMPV6HDR)NdisGetDataBuffer(buffer,
                sizeof(WINDIVERT_ICMPV6HDR), NULL, 1, 0);
            break;
        case IPPROTO_TCP:
            tcp_header = (PWINDIVERT_TCPHDR)NdisGetDataBuffer(buffer,
                sizeof(WINDIVERT_TCPHDR), NULL, 1, 0);
            break;
        case IPPROTO_UDP:
            udp_header = (PWINDIVERT_UDPHDR)NdisGetDataBuffer(buffer,
                sizeof(WINDIVERT_UDPHDR), NULL, 1, 0);
            break;
        default:
            break;
    }

    status = NdisRetreatNetBufferDataStart(buffer, ip_header_len, 0, NULL);
    if (!NT_SUCCESS(status))
    {
        // Should never occur.
        DEBUG("FILTER: REJECT (failed to retreat buffer)");
        return FALSE;
    }

    // Execute the filter:
    ip = 0;
    ttl = WINDIVERT_FILTER_MAXLEN+1;       // Additional safety
    while (ttl-- != 0)
    {
        BOOL result;
        int cmp;
        UINT32 field[4];
        field[1] = 0;
        field[2] = 0;
        field[3] = 0;
        switch (filter[ip].protocol)
        {
            case WINDIVERT_FILTER_PROTOCOL_NONE:
                result = TRUE;
                break;
            case WINDIVERT_FILTER_PROTOCOL_IP:
                result = (ip_header != NULL);
                break;
            case WINDIVERT_FILTER_PROTOCOL_IPV6:
                result = (ipv6_header != NULL);
                break;
            case WINDIVERT_FILTER_PROTOCOL_ICMP:
                result = (icmp_header != NULL);
                break;
            case WINDIVERT_FILTER_PROTOCOL_ICMPV6:
                result = (icmpv6_header != NULL);
                break;
            case WINDIVERT_FILTER_PROTOCOL_TCP:
                result = (tcp_header != NULL);
                break;
            case WINDIVERT_FILTER_PROTOCOL_UDP:
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
                case WINDIVERT_FILTER_FIELD_ZERO:
                    field[0] = 0;
                    break;
                case WINDIVERT_FILTER_FIELD_INBOUND:
                    field[0] = (UINT32)(!outbound);
                    break;
                case WINDIVERT_FILTER_FIELD_OUTBOUND:
                    field[0] = (UINT32)outbound;
                    break;
                case WINDIVERT_FILTER_FIELD_IFIDX:
                    field[0] = (UINT32)if_idx;
                    break;
                case WINDIVERT_FILTER_FIELD_SUBIFIDX:
                    field[0] = (UINT32)sub_if_idx;
                    break;
                case WINDIVERT_FILTER_FIELD_LOOPBACK:
                    field[0] = (UINT32)loopback;
                    break;
                case WINDIVERT_FILTER_FIELD_IMPOSTOR:
                    field[0] = (UINT32)impostor;
                    break;
                case WINDIVERT_FILTER_FIELD_IP:
                    field[0] = (UINT32)(ip_header != NULL);
                    break;
                case WINDIVERT_FILTER_FIELD_IPV6:
                    field[0] = (UINT32)(ipv6_header != NULL);
                    break;
                case WINDIVERT_FILTER_FIELD_ICMP:
                    field[0] = (UINT32)(icmp_header != NULL);
                    break;
                case WINDIVERT_FILTER_FIELD_ICMPV6:
                    field[0] = (UINT32)(icmpv6_header != NULL);
                    break;
                case WINDIVERT_FILTER_FIELD_TCP:
                    field[0] = (UINT32)(tcp_header != NULL);
                    break;
                case WINDIVERT_FILTER_FIELD_UDP:
                    field[0] = (UINT32)(udp_header != NULL);
                    break;
                case WINDIVERT_FILTER_FIELD_IP_HDRLENGTH:
                    field[0] = (UINT32)ip_header->HdrLength;
                    break;
                case WINDIVERT_FILTER_FIELD_IP_TOS:
                    field[0] = (UINT32)ip_header->TOS;
                    break;
                case WINDIVERT_FILTER_FIELD_IP_LENGTH:
                    field[0] = (UINT32)RtlUshortByteSwap(ip_header->Length);
                    break;
                case WINDIVERT_FILTER_FIELD_IP_ID:
                    field[0] = (UINT32)RtlUshortByteSwap(ip_header->Id);
                    break;
                case WINDIVERT_FILTER_FIELD_IP_DF:
                    field[0] = (UINT32)WINDIVERT_IPHDR_GET_DF(ip_header);
                    break;
                case WINDIVERT_FILTER_FIELD_IP_MF:
                    field[0] = (UINT32)WINDIVERT_IPHDR_GET_MF(ip_header);
                    break;
                case WINDIVERT_FILTER_FIELD_IP_FRAGOFF:
                    field[0] = (UINT32)RtlUshortByteSwap(
                        WINDIVERT_IPHDR_GET_FRAGOFF(ip_header));
                    break;
                case WINDIVERT_FILTER_FIELD_IP_TTL:
                    field[0] = (UINT32)ip_header->TTL;
                    break;
                case WINDIVERT_FILTER_FIELD_IP_PROTOCOL:
                    field[0] = (UINT32)ip_header->Protocol;
                    break;
                case WINDIVERT_FILTER_FIELD_IP_CHECKSUM:
                    field[0] = (UINT32)RtlUshortByteSwap(ip_header->Checksum);
                    break;
                case WINDIVERT_FILTER_FIELD_IP_SRCADDR:
                    field[0] = (UINT32)RtlUlongByteSwap(ip_header->SrcAddr);
                    break;
                case WINDIVERT_FILTER_FIELD_IP_DSTADDR:
                    field[0] = (UINT32)RtlUlongByteSwap(ip_header->DstAddr);
                    break;
                case WINDIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS:
                    field[0] =
                        (UINT32)WINDIVERT_IPV6HDR_GET_TRAFFICCLASS(ipv6_header);
                    break;
                case WINDIVERT_FILTER_FIELD_IPV6_FLOWLABEL:
                    field[0] = (UINT32)RtlUlongByteSwap(
                        WINDIVERT_IPV6HDR_GET_FLOWLABEL(ipv6_header));
                    break;
                case WINDIVERT_FILTER_FIELD_IPV6_LENGTH:
                    field[0] = (UINT32)RtlUshortByteSwap(ipv6_header->Length);
                    break;
                case WINDIVERT_FILTER_FIELD_IPV6_NEXTHDR:
                    field[0] = (UINT32)ipv6_header->NextHdr;
                    break;
                case WINDIVERT_FILTER_FIELD_IPV6_HOPLIMIT:
                    field[0] = (UINT32)ipv6_header->HopLimit;
                    break;
                case WINDIVERT_FILTER_FIELD_IPV6_SRCADDR:
                    field[3] =
                        (UINT32)RtlUlongByteSwap(ipv6_header->SrcAddr[0]);
                    field[2] =
                        (UINT32)RtlUlongByteSwap(ipv6_header->SrcAddr[1]);
                    field[1] =
                        (UINT32)RtlUlongByteSwap(ipv6_header->SrcAddr[2]);
                    field[0] =
                        (UINT32)RtlUlongByteSwap(ipv6_header->SrcAddr[3]);
                    break;
                case WINDIVERT_FILTER_FIELD_IPV6_DSTADDR:
                    field[3] =
                        (UINT32)RtlUlongByteSwap(ipv6_header->DstAddr[0]);
                    field[2] =
                        (UINT32)RtlUlongByteSwap(ipv6_header->DstAddr[1]);
                    field[1] =
                        (UINT32)RtlUlongByteSwap(ipv6_header->DstAddr[2]);
                    field[0] =
                        (UINT32)RtlUlongByteSwap(ipv6_header->DstAddr[3]);
                    break;
                case WINDIVERT_FILTER_FIELD_ICMP_TYPE:
                    field[0] = (UINT32)icmp_header->Type;
                    break;
                case WINDIVERT_FILTER_FIELD_ICMP_CODE:
                    field[0] = (UINT32)icmp_header->Code;
                    break;
                case WINDIVERT_FILTER_FIELD_ICMP_CHECKSUM:
                    field[0] =
                        (UINT32)RtlUshortByteSwap(icmp_header->Checksum);
                    break;
                case WINDIVERT_FILTER_FIELD_ICMP_BODY:
                    field[0] = (UINT32)RtlUlongByteSwap(icmp_header->Body);
                    break;
                case WINDIVERT_FILTER_FIELD_ICMPV6_TYPE:
                    field[0] = (UINT32)icmpv6_header->Type;
                    break;
                case WINDIVERT_FILTER_FIELD_ICMPV6_CODE:
                    field[0] = (UINT32)icmpv6_header->Code;
                    break;
                case WINDIVERT_FILTER_FIELD_ICMPV6_CHECKSUM:
                    field[0] =
                        (UINT32)RtlUshortByteSwap(icmpv6_header->Checksum);
                    break;
                case WINDIVERT_FILTER_FIELD_ICMPV6_BODY:
                    field[0] =
                        (UINT32)RtlUlongByteSwap(icmpv6_header->Body);
                    break;
                case WINDIVERT_FILTER_FIELD_TCP_SRCPORT:
                    field[0] = (UINT32)RtlUshortByteSwap(tcp_header->SrcPort);
                    break;
                case WINDIVERT_FILTER_FIELD_TCP_DSTPORT:
                    field[0] = (UINT32)RtlUshortByteSwap(tcp_header->DstPort);
                    break;
                case WINDIVERT_FILTER_FIELD_TCP_SEQNUM:
                    field[0] = (UINT32)RtlUlongByteSwap(tcp_header->SeqNum);
                    break;
                case WINDIVERT_FILTER_FIELD_TCP_ACKNUM:
                    field[0] = (UINT32)RtlUlongByteSwap(tcp_header->AckNum);
                    break;
                case WINDIVERT_FILTER_FIELD_TCP_HDRLENGTH:
                    field[0] = (UINT32)tcp_header->HdrLength;
                    break;
                case WINDIVERT_FILTER_FIELD_TCP_URG:
                    field[0] = (UINT32)tcp_header->Urg;
                    break;
                case WINDIVERT_FILTER_FIELD_TCP_ACK:
                    field[0] = (UINT32)tcp_header->Ack;
                    break;
                case WINDIVERT_FILTER_FIELD_TCP_PSH:
                    field[0] = (UINT32)tcp_header->Psh;
                    break;
                case WINDIVERT_FILTER_FIELD_TCP_RST:
                    field[0] = (UINT32)tcp_header->Rst;
                    break;
                case WINDIVERT_FILTER_FIELD_TCP_SYN:
                    field[0] = (UINT32)tcp_header->Syn;
                    break;
                case WINDIVERT_FILTER_FIELD_TCP_FIN:
                    field[0] = (UINT32)tcp_header->Fin;
                    break;
                case WINDIVERT_FILTER_FIELD_TCP_WINDOW:
                    field[0] = (UINT32)RtlUshortByteSwap(tcp_header->Window);
                    break;
                case WINDIVERT_FILTER_FIELD_TCP_CHECKSUM:
                    field[0] = (UINT32)RtlUshortByteSwap(tcp_header->Checksum);
                    break;
                case WINDIVERT_FILTER_FIELD_TCP_URGPTR:
                    field[0] = (UINT32)RtlUshortByteSwap(tcp_header->UrgPtr);
                    break;
                case WINDIVERT_FILTER_FIELD_TCP_PAYLOADLENGTH:
                    field[0] = (UINT32)(tot_len - ip_header_len -
                        tcp_header->HdrLength*sizeof(UINT32));
                    break;
                case WINDIVERT_FILTER_FIELD_UDP_SRCPORT:
                    field[0] = (UINT32)RtlUshortByteSwap(udp_header->SrcPort);
                    break;
                case WINDIVERT_FILTER_FIELD_UDP_DSTPORT:
                    field[0] = (UINT32)RtlUshortByteSwap(udp_header->DstPort);
                    break;
                case WINDIVERT_FILTER_FIELD_UDP_LENGTH:
                    field[0] = (UINT32)RtlUshortByteSwap(udp_header->Length);
                    break;
                case WINDIVERT_FILTER_FIELD_UDP_CHECKSUM:
                    field[0] = (UINT32)RtlUshortByteSwap(udp_header->Checksum);
                    break;
                case WINDIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH:
                    field[0] = (UINT32)(tot_len - ip_header_len -
                        sizeof(WINDIVERT_UDPHDR));
                    break;
                default:
                    field[0] = 0;
                    break;
            }
            cmp = windivert_big_num_compare(field, filter[ip].arg);
            switch (filter[ip].test)
            {
                case WINDIVERT_FILTER_TEST_EQ:
                    result = (cmp == 0);
                    break;
                case WINDIVERT_FILTER_TEST_NEQ:
                    result = (cmp != 0);
                    break;
                case WINDIVERT_FILTER_TEST_LT:
                    result = (cmp < 0);
                    break;
                case WINDIVERT_FILTER_TEST_LEQ:
                    result = (cmp <= 0);
                    break;
                case WINDIVERT_FILTER_TEST_GT:
                    result = (cmp > 0);
                    break;
                case WINDIVERT_FILTER_TEST_GEQ:
                    result = (cmp >= 0);
                    break;
                default:
                    result = FALSE;
                    break;
            }
        }
        ip = (result? filter[ip].success: filter[ip].failure);
        if (ip == WINDIVERT_FILTER_RESULT_ACCEPT)
        {
            return TRUE;
        }
        if (ip == WINDIVERT_FILTER_RESULT_REJECT)
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
static void windivert_filter_analyze(filter_t filter, BOOL *is_inbound,
    BOOL *is_outbound, BOOL *is_ipv4, BOOL *is_ipv6)
{
    BOOL result;

    // False filter?
    result = windivert_filter_test(filter, 0, WINDIVERT_FILTER_PROTOCOL_NONE,
        WINDIVERT_FILTER_FIELD_ZERO, 0);
    if (!result)
    {
        *is_inbound  = FALSE;
        *is_outbound = FALSE;
        *is_ipv4     = FALSE;
        *is_ipv6     = FALSE;
        return;
    }

    // Inbound?
    result = windivert_filter_test(filter, 0, WINDIVERT_FILTER_PROTOCOL_NONE,
        WINDIVERT_FILTER_FIELD_INBOUND, 1);
    if (result)
    {
        result = windivert_filter_test(filter, 0,
            WINDIVERT_FILTER_PROTOCOL_NONE, WINDIVERT_FILTER_FIELD_OUTBOUND,
            0);
    }
    *is_inbound = result;

    // Outbound?
    result = windivert_filter_test(filter, 0, WINDIVERT_FILTER_PROTOCOL_NONE,
        WINDIVERT_FILTER_FIELD_OUTBOUND, 1);
    if (result)
    {
        result = windivert_filter_test(filter, 0,
            WINDIVERT_FILTER_PROTOCOL_NONE, WINDIVERT_FILTER_FIELD_INBOUND, 0);
    }
    *is_outbound = result;

    // IPv4?
    result = windivert_filter_test(filter, 0, WINDIVERT_FILTER_PROTOCOL_NONE,
        WINDIVERT_FILTER_FIELD_IP, 1);
    if (result)
    {
        result = windivert_filter_test(filter, 0,
            WINDIVERT_FILTER_PROTOCOL_NONE, WINDIVERT_FILTER_FIELD_IPV6, 0);
    }
    *is_ipv4 = result;

    // Ipv6?
    result = windivert_filter_test(filter, 0, WINDIVERT_FILTER_PROTOCOL_NONE,
        WINDIVERT_FILTER_FIELD_IPV6, 1);
    if (result)
    {
        result = windivert_filter_test(filter, 0,
            WINDIVERT_FILTER_PROTOCOL_NONE, WINDIVERT_FILTER_FIELD_IP, 0);
    }
    *is_ipv6 = result;
}

/*
 * Test a filter for any packet where field = arg.
 */
static BOOL windivert_filter_test(filter_t filter, UINT16 ip, UINT8 protocol,
    UINT8 field, UINT32 arg)
{
    BOOL known = FALSE;
    BOOL result = FALSE;

    if (ip == WINDIVERT_FILTER_RESULT_ACCEPT)
    {
        return TRUE;
    }
    if (ip == WINDIVERT_FILTER_RESULT_REJECT)
    {
        return FALSE;
    }
    if (ip > WINDIVERT_FILTER_MAXLEN)
    {
        return FALSE;
    }

    if (filter[ip].protocol == protocol &&
        filter[ip].field == field)
    {
        known = TRUE;
        switch (filter[ip].test)
        {
            case WINDIVERT_FILTER_TEST_EQ:
                result = (arg == filter[ip].arg[0]);
                break;
            case WINDIVERT_FILTER_TEST_NEQ:
                result = (arg != filter[ip].arg[0]);
                break;
            case WINDIVERT_FILTER_TEST_LT:
                result = (arg < filter[ip].arg[0]);
                break;
            case WINDIVERT_FILTER_TEST_LEQ:
                result = (arg <= filter[ip].arg[0]);
                break;
            case WINDIVERT_FILTER_TEST_GT:
                result = (arg > filter[ip].arg[0]);
                break;
            case WINDIVERT_FILTER_TEST_GEQ:
                result = (arg >= filter[ip].arg[0]);
                break;
            default:
                result = FALSE;
                break;
        }
    }

    if (!known)
    {
        result = windivert_filter_test(filter, filter[ip].success, protocol,
            field, arg);
        if (result)
        {
            return TRUE;
        }
        return windivert_filter_test(filter, filter[ip].failure, protocol,
            field, arg);
    }
    else
    {
        ip = (result? filter[ip].success: filter[ip].failure);
        return windivert_filter_test(filter, ip, protocol, field, arg);
    }
}

/*
 * Compile a WinDivert filter from an IOCTL.
 */
static filter_t windivert_filter_compile(windivert_ioctl_filter_t ioctl_filter,
    size_t ioctl_filter_len)
{
    filter_t filter0 = NULL, result = NULL;
    UINT16 i;
    size_t length;

    if (ioctl_filter_len % sizeof(struct windivert_ioctl_filter_s) != 0)
    {
        goto windivert_filter_compile_exit;
    }
    length = ioctl_filter_len / sizeof(struct windivert_ioctl_filter_s);
    if (length >= WINDIVERT_FILTER_MAXLEN)
    {
        goto windivert_filter_compile_exit;
    }

    // Do NOT use the stack (size = 12Kb on x86) for filter0.
    filter0 = (filter_t)windivert_malloc(
        WINDIVERT_FILTER_MAXLEN*sizeof(struct filter_s), TRUE);
    if (filter0 == NULL)
    {
        goto windivert_filter_compile_exit;
    }
 
    for (i = 0; i < length; i++)
    {
        if (ioctl_filter[i].field > WINDIVERT_FILTER_FIELD_MAX ||
            ioctl_filter[i].test > WINDIVERT_FILTER_TEST_MAX)
        {
            goto windivert_filter_compile_exit;
        }
        switch (ioctl_filter[i].success)
        {
            case WINDIVERT_FILTER_RESULT_ACCEPT:
            case WINDIVERT_FILTER_RESULT_REJECT:
                break;
            default:
                if (ioctl_filter[i].success <= i ||
                    ioctl_filter[i].success >= length)
                {
                    goto windivert_filter_compile_exit;
                }
                break;
        }
        switch (ioctl_filter[i].failure)
        {
            case WINDIVERT_FILTER_RESULT_ACCEPT:
            case WINDIVERT_FILTER_RESULT_REJECT:
                break;
            default:
                if (ioctl_filter[i].failure <= i ||
                    ioctl_filter[i].failure >= length)
                {
                    goto windivert_filter_compile_exit;
                }
                break;
        }

        // Enforce size limits:
        if (ioctl_filter[i].field != WINDIVERT_FILTER_FIELD_IPV6_SRCADDR &&
            ioctl_filter[i].field != WINDIVERT_FILTER_FIELD_IPV6_DSTADDR)
        {
            if (ioctl_filter[i].arg[1] != 0 ||
                ioctl_filter[i].arg[2] != 0 ||
                ioctl_filter[i].arg[3] != 0)
            {
                goto windivert_filter_compile_exit;
            }
        }
        switch (ioctl_filter[i].field)
        {
            case WINDIVERT_FILTER_FIELD_ZERO:
            case WINDIVERT_FILTER_FIELD_INBOUND:
            case WINDIVERT_FILTER_FIELD_OUTBOUND:
            case WINDIVERT_FILTER_FIELD_IP:
            case WINDIVERT_FILTER_FIELD_IPV6:
            case WINDIVERT_FILTER_FIELD_ICMP:
            case WINDIVERT_FILTER_FIELD_ICMPV6:
            case WINDIVERT_FILTER_FIELD_TCP:
            case WINDIVERT_FILTER_FIELD_UDP:
            case WINDIVERT_FILTER_FIELD_IP_DF:
            case WINDIVERT_FILTER_FIELD_IP_MF:
            case WINDIVERT_FILTER_FIELD_TCP_URG:
            case WINDIVERT_FILTER_FIELD_TCP_ACK:
            case WINDIVERT_FILTER_FIELD_TCP_PSH:
            case WINDIVERT_FILTER_FIELD_TCP_RST:
            case WINDIVERT_FILTER_FIELD_TCP_SYN:
            case WINDIVERT_FILTER_FIELD_TCP_FIN:
                if (ioctl_filter[i].arg[0] > 1)
                {
                    goto windivert_filter_compile_exit;
                }
                break;
            case WINDIVERT_FILTER_FIELD_IP_HDRLENGTH:
            case WINDIVERT_FILTER_FIELD_TCP_HDRLENGTH:
                if (ioctl_filter[i].arg[0] > 0x0F)
                {
                    goto windivert_filter_compile_exit;
                }
                break;
            case WINDIVERT_FILTER_FIELD_IP_TOS:
            case WINDIVERT_FILTER_FIELD_IP_TTL:
            case WINDIVERT_FILTER_FIELD_IP_PROTOCOL:
            case WINDIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS:
            case WINDIVERT_FILTER_FIELD_IPV6_NEXTHDR:
            case WINDIVERT_FILTER_FIELD_IPV6_HOPLIMIT:
            case WINDIVERT_FILTER_FIELD_ICMP_TYPE:
            case WINDIVERT_FILTER_FIELD_ICMP_CODE:
            case WINDIVERT_FILTER_FIELD_ICMPV6_TYPE:
            case WINDIVERT_FILTER_FIELD_ICMPV6_CODE:
                if (ioctl_filter[i].arg[0] > UINT8_MAX)
                {
                    goto windivert_filter_compile_exit;
                }
                break;
            case WINDIVERT_FILTER_FIELD_IP_FRAGOFF:
                if (ioctl_filter[i].arg[0] > 0x1FFF)
                {
                    goto windivert_filter_compile_exit;
                }
                break;
            case WINDIVERT_FILTER_FIELD_IP_LENGTH:
            case WINDIVERT_FILTER_FIELD_IP_ID:
            case WINDIVERT_FILTER_FIELD_IP_CHECKSUM:
            case WINDIVERT_FILTER_FIELD_IPV6_LENGTH:
            case WINDIVERT_FILTER_FIELD_ICMP_CHECKSUM:
            case WINDIVERT_FILTER_FIELD_ICMPV6_CHECKSUM:
            case WINDIVERT_FILTER_FIELD_TCP_SRCPORT:
            case WINDIVERT_FILTER_FIELD_TCP_DSTPORT:
            case WINDIVERT_FILTER_FIELD_TCP_WINDOW:
            case WINDIVERT_FILTER_FIELD_TCP_CHECKSUM:
            case WINDIVERT_FILTER_FIELD_TCP_URGPTR:
            case WINDIVERT_FILTER_FIELD_TCP_PAYLOADLENGTH:
            case WINDIVERT_FILTER_FIELD_UDP_SRCPORT:
            case WINDIVERT_FILTER_FIELD_UDP_DSTPORT:
            case WINDIVERT_FILTER_FIELD_UDP_LENGTH:
            case WINDIVERT_FILTER_FIELD_UDP_CHECKSUM:
            case WINDIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH:
                if (ioctl_filter[i].arg[0] > UINT16_MAX)
                {
                    goto windivert_filter_compile_exit;
                }
                break;
            case WINDIVERT_FILTER_FIELD_IPV6_FLOWLABEL:
                if (ioctl_filter[i].arg[0] > 0x000FFFFF)
                {
                    goto windivert_filter_compile_exit;
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
            case WINDIVERT_FILTER_FIELD_ZERO:
            case WINDIVERT_FILTER_FIELD_INBOUND:
            case WINDIVERT_FILTER_FIELD_OUTBOUND:
            case WINDIVERT_FILTER_FIELD_IFIDX:
            case WINDIVERT_FILTER_FIELD_SUBIFIDX:
            case WINDIVERT_FILTER_FIELD_LOOPBACK:
            case WINDIVERT_FILTER_FIELD_IMPOSTOR:
            case WINDIVERT_FILTER_FIELD_IP:
            case WINDIVERT_FILTER_FIELD_IPV6:
            case WINDIVERT_FILTER_FIELD_ICMP:
            case WINDIVERT_FILTER_FIELD_ICMPV6:
            case WINDIVERT_FILTER_FIELD_TCP:
            case WINDIVERT_FILTER_FIELD_UDP:
                filter0[i].protocol = WINDIVERT_FILTER_PROTOCOL_NONE;
                break;
            case WINDIVERT_FILTER_FIELD_IP_HDRLENGTH:
            case WINDIVERT_FILTER_FIELD_IP_TOS:
            case WINDIVERT_FILTER_FIELD_IP_LENGTH:
            case WINDIVERT_FILTER_FIELD_IP_ID:
            case WINDIVERT_FILTER_FIELD_IP_DF:
            case WINDIVERT_FILTER_FIELD_IP_MF:
            case WINDIVERT_FILTER_FIELD_IP_FRAGOFF:
            case WINDIVERT_FILTER_FIELD_IP_TTL:
            case WINDIVERT_FILTER_FIELD_IP_PROTOCOL:
            case WINDIVERT_FILTER_FIELD_IP_CHECKSUM:
            case WINDIVERT_FILTER_FIELD_IP_SRCADDR:
            case WINDIVERT_FILTER_FIELD_IP_DSTADDR:
                filter0[i].protocol = WINDIVERT_FILTER_PROTOCOL_IP;
                break;
            case WINDIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS:
            case WINDIVERT_FILTER_FIELD_IPV6_FLOWLABEL:
            case WINDIVERT_FILTER_FIELD_IPV6_LENGTH:
            case WINDIVERT_FILTER_FIELD_IPV6_NEXTHDR:
            case WINDIVERT_FILTER_FIELD_IPV6_HOPLIMIT:
            case WINDIVERT_FILTER_FIELD_IPV6_SRCADDR:
            case WINDIVERT_FILTER_FIELD_IPV6_DSTADDR:
                filter0[i].protocol = WINDIVERT_FILTER_PROTOCOL_IPV6;
                break;
            case WINDIVERT_FILTER_FIELD_ICMP_TYPE:
            case WINDIVERT_FILTER_FIELD_ICMP_CODE:
            case WINDIVERT_FILTER_FIELD_ICMP_CHECKSUM:
            case WINDIVERT_FILTER_FIELD_ICMP_BODY:
                filter0[i].protocol = WINDIVERT_FILTER_PROTOCOL_ICMP;
                break;
            case WINDIVERT_FILTER_FIELD_ICMPV6_TYPE:
            case WINDIVERT_FILTER_FIELD_ICMPV6_CODE:
            case WINDIVERT_FILTER_FIELD_ICMPV6_CHECKSUM:
            case WINDIVERT_FILTER_FIELD_ICMPV6_BODY:
                filter0[i].protocol = WINDIVERT_FILTER_PROTOCOL_ICMPV6;
                break;
            case WINDIVERT_FILTER_FIELD_TCP_SRCPORT:
            case WINDIVERT_FILTER_FIELD_TCP_DSTPORT:
            case WINDIVERT_FILTER_FIELD_TCP_SEQNUM:
            case WINDIVERT_FILTER_FIELD_TCP_ACKNUM:
            case WINDIVERT_FILTER_FIELD_TCP_HDRLENGTH:
            case WINDIVERT_FILTER_FIELD_TCP_URG:
            case WINDIVERT_FILTER_FIELD_TCP_ACK:
            case WINDIVERT_FILTER_FIELD_TCP_PSH:
            case WINDIVERT_FILTER_FIELD_TCP_RST:
            case WINDIVERT_FILTER_FIELD_TCP_SYN:
            case WINDIVERT_FILTER_FIELD_TCP_FIN:
            case WINDIVERT_FILTER_FIELD_TCP_WINDOW:
            case WINDIVERT_FILTER_FIELD_TCP_CHECKSUM:
            case WINDIVERT_FILTER_FIELD_TCP_URGPTR:
            case WINDIVERT_FILTER_FIELD_TCP_PAYLOADLENGTH:
                filter0[i].protocol = WINDIVERT_FILTER_PROTOCOL_TCP;
                break;
            case WINDIVERT_FILTER_FIELD_UDP_SRCPORT:
            case WINDIVERT_FILTER_FIELD_UDP_DSTPORT:
            case WINDIVERT_FILTER_FIELD_UDP_LENGTH:
            case WINDIVERT_FILTER_FIELD_UDP_CHECKSUM:
            case WINDIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH:
                filter0[i].protocol = WINDIVERT_FILTER_PROTOCOL_UDP;
                break;
            default:
                goto windivert_filter_compile_exit;
        }
    }
    
    result = (filter_t)windivert_malloc(i*sizeof(struct filter_s), FALSE);
    if (result != NULL)
    {
        RtlMoveMemory(result, filter0, i*sizeof(struct filter_s));
    }

windivert_filter_compile_exit:

    windivert_free(filter0);
    return result;
}

