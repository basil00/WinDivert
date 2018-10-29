/*
 * windivert.c
 * (C) 2018, all rights reserved,
 *
 * This file is part of WinDivert.
 *
 * WinDivert is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * WinDivert is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <ntifs.h>
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
EVT_WDF_WORKITEM windivert_reflect_worker;

/*
 * Debugging macros.
 */
#define DEBUG_ON
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
 * WinDivert reflect event.
 */
typedef struct context_s *context_t;
struct reflect_event_s
{
    LIST_ENTRY entry;                           // Entry.
    context_t context;                          // Context.
    WINDIVERT_EVENT event;                      // Event.
};
typedef struct reflect_event_s *reflect_event_t;

/*
 * WinDivert reflect context information.
 */
struct reflect_context_s
{
    LIST_ENTRY entry;                           // Open handle entry.
    LONGLONG timestamp;                         // Open timestamp.
    WINDIVERT_DATA_REFLECT data;                // Reflect data.
    struct reflect_event_s open_event;          // Open event.
    struct reflect_event_s close_event;         // Close event
    BOOL open;                                  // Seen open event?
};

/*
 * WinDivert context information.
 */
#define WINDIVERT_CONTEXT_SIZE                  (sizeof(struct context_s))
#define WINDIVERT_CONTEXT_MAXLAYERS             8
#define WINDIVERT_CONTEXT_MAXWORKERS            1
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
    LIST_ENTRY flow_set;                        // All active flows.
    UINT32 flow_v4_callout_id;                  // Flow established callout id.
    UINT32 flow_v6_callout_id;                  // Flow established callout id.
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
    UINT32 priority;                            // Context (internal) priority.
    INT16 priority16;                           // Context (user) priority.
    GUID callout_guid[WINDIVERT_CONTEXT_MAXLAYERS];
                                                // Callout GUIDs.
    GUID filter_guid[WINDIVERT_CONTEXT_MAXLAYERS];
                                                // Filter GUIDs.
    BOOL installed[WINDIVERT_CONTEXT_MAXLAYERS];// What is installed?
    HANDLE engine_handle;                       // WFP engine handle.
    PWINDIVERT_FILTER filter;                   // Packet filter.
    UINT8 filter_len;                           // Length of filter.
    struct reflect_context_s reflect;           // Reflection info.
};
typedef struct context_s context_s;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(context_s, windivert_context_get);

#define WINDIVERT_TIMEOUT(context, t0, t1)                                  \
    ((context)->layer == WINDIVERT_LAYER_NETWORK ||                         \
     (context)->layer == WINDIVERT_LAYER_NETWORK_FORWARD?                   \
     ((t1) >= (t0)? (t1) - (t0): (t0) - (t1)) >                             \
        (context)->packet_queue_maxcounts: FALSE)

/*
 * WinDivert Layer information.
 */
typedef void (*windivert_classify_t)(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
typedef void (*windivert_flow_delete_notify_t)(
    IN UINT16 layer_id, IN UINT32 callout_id, IN UINT64 flow_context);
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
    windivert_classify_t classify;          // Classify function.
    windivert_flow_delete_notify_t flow_delete;
                                            // Flow delete function.
    UINT16 sublayer_weight;                 // Sub-layer weight.
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
 * WinDivert packet structure.  Layout is as follows:
 *
 *     +-----------------+------------+-------------+
 *     | struct packet_s | layer data | packet data |
 *     +-----------------+------------+-------------+
 *
 * Note the packet data must be pointer-aligned.
 */
#define WINDIVERT_WORK_QUEUE_LEN_MAX        4096
#ifdef _WIN64
#define WINDIVERT_ALIGN_SIZE                8
#define WINDIVERT_DATA_ALIGN                __declspec(align(8))
#else
#define WINDIVERT_ALIGN_SIZE                4
#define WINDIVERT_DATA_ALIGN                __declspec(align(4))
#endif
struct packet_s
{
    LIST_ENTRY entry;                       // Entry for queue.
    LONGLONG timestamp;                     // Packet timestamp.
    UINT64 layer:8;                         // Layer.
    UINT64 event:24;                        // Event.
    UINT64 outbound:1;                      // Packet is outound?
    UINT64 loopback:1;                      // Packet is loopback?
    UINT64 impostor:1;                      // Packet is impostor?
    UINT64 ipv6:1;                          // Packet is IPv6?
    UINT64 pseudo_ip_checksum:1;            // Packet has pseudo IPv4 check?
    UINT64 pseudo_tcp_checksum:1;           // Packet has pseudo TCP check?
    UINT64 pseudo_udp_checksum:1;           // Packet has pseudo UDP check?
    UINT64 final:1;                         // Packet is final event?
    UINT64 match:1;                         // Packet matches filter?
    UINT32 priority;                        // Packet priority.
    UINT32 packet_len;                      // Length of the packet.
    WINDIVERT_DATA_ALIGN UINT8 data[];      // Packet/layer data.
};
typedef struct packet_s *packet_t;

#define WINDIVERT_DATA_SIZE(size)                                           \
    ((((size) + WINDIVERT_ALIGN_SIZE - 1) / WINDIVERT_ALIGN_SIZE) *         \
        WINDIVERT_ALIGN_SIZE)
#define WINDIVERT_PACKET_SIZE(layer_type, packet_len)                       \
    (sizeof(struct packet_s) + WINDIVERT_DATA_SIZE(sizeof(layer_type)) +    \
        (packet_len))
#define WINDIVERT_LAYER_DATA_PTR(packet)                                    \
    ((packet)->data)
#define WINDIVERT_PACKET_DATA_PTR(layer_type, packet)                       \
    ((packet)->data + WINDIVERT_DATA_SIZE(sizeof(layer_type)))

/*
 * WinDivert flow structure.
 */
struct flow_s
{
    LIST_ENTRY entry;                       // Entry for tracking.
    context_t context;                      // Context.
    UINT64 flow_id;                         // WFP flow ID.
    UINT32 callout_id;                      // WFP callout ID.
    UINT16 layer_id;                        // WFP layout ID.
    BOOL inserted:1;                        // Flow inserted into context?
    BOOL deleted:1;                         // Flow deleted from context?
    BOOL outbound:1;                        // Flow is outound?
    BOOL loopback:1;                        // Flow is loopback?
    BOOL ipv6:1;                            // Flow is ipv6?
    WINDIVERT_DATA_FLOW data;               // Flow data.
};
typedef struct flow_s *flow_t;

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
static MM_PAGE_PRIORITY no_write_flag = 0;
static MM_PAGE_PRIORITY no_exec_flag  = 0;

/*
 * Priorities & weights.
 */
static UINT32 windivert_context_priority(INT64 priority64)
{
    UINT32 priority, increment;
    priority64 += WINDIVERT_PRIORITY_MAX;       // Make positive
    priority = (UINT32)(priority64 << 16);
    increment = (UINT32)InterlockedIncrement(&priority_counter);
    priority |= (increment & 0x0000FFFF);
    return priority;
}

#define WINDIVERT_FILTER_WEIGHT(priority)                                   \
    ((UINT64)((UINT64)UINT32_MAX - (priority)))

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
    UINT64 flags);
static NTSTATUS windivert_install_callout(context_t context, UINT idx,
    layer_t layer, UINT32 *callout_id_ptr);
static void windivert_uninstall_callouts(context_t context,
    context_state_t state);
extern VOID windivert_cleanup(IN WDFFILEOBJECT object);
extern VOID windivert_close(IN WDFFILEOBJECT object);
extern VOID windivert_destroy(IN WDFOBJECT object);
extern NTSTATUS windivert_write(context_t context, WDFREQUEST request,
    PWINDIVERT_ADDRESS addr);
extern void NTAPI windivert_inject_complete(VOID *context,
    NET_BUFFER_LIST *packets, BOOLEAN dispatch_level);
extern void NTAPI windivert_reinject_complete(VOID *context,
    NET_BUFFER_LIST *packets, BOOLEAN dispatch_level);
static NTSTATUS windivert_notify(IN FWPS_CALLOUT_NOTIFY_TYPE type,
    IN const GUID *filter_key, IN const FWPS_FILTER0 *filter);
static void windivert_outbound_network_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_inbound_network_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_outbound_network_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_inbound_network_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_forward_network_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_forward_network_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_flow_established_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_flow_established_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_resource_assignment_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_resource_assignment_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_auth_connect_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_auth_connect_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_auth_listen_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_auth_listen_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_auth_recv_accept_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_auth_recv_accept_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_flow_established_classify(context_t context, 
    IN UINT64 flow_id, IN PWINDIVERT_DATA_FLOW flow_data, IN BOOL ipv4,
    IN BOOL outbound, IN BOOL loopback, OUT FWPS_CLASSIFY_OUT0 *result);
static void windivert_flow_delete_notify(UINT16 layer_id, UINT32 callout_id,
    UINT64 flow_context);
static void windivert_socket_classify(context_t context,
    PWINDIVERT_DATA_SOCKET socket_data, WINDIVERT_EVENT event, BOOL ipv4,
    BOOL outbound, BOOL loopback, FWPS_CLASSIFY_OUT0 *result);
static void windivert_network_classify(context_t context,
    IN PWINDIVERT_DATA_NETWORK network_data, IN BOOL ipv4, IN BOOL outbound,
    IN BOOL loopback, IN UINT advance, IN OUT void *data,
    OUT FWPS_CLASSIFY_OUT0 *result);
static BOOL windivert_queue_work(context_t context, PVOID packet,
    ULONG packet_len, PNET_BUFFER_LIST buffers, WINDIVERT_LAYER layer,
    PVOID layer_data, WINDIVERT_EVENT event, UINT64 flags, UINT32 priority,
    BOOL ipv4, BOOL outbound, BOOL loopback, BOOL impostor, BOOL final,
    BOOL match, LONGLONG timestamp);
static void windivert_queue_packet(context_t context, packet_t packet);
static void windivert_reinject_packet(packet_t packet);
static void windivert_free_packet(packet_t packet);
static BOOL windivert_decrement_ttl(PVOID data, BOOL ipv4);
static int windivert_big_num_compare(const UINT32 *a, const UINT32 *b);
static BOOL windivert_parse_headers(PNET_BUFFER buffer, BOOL ipv4,
    PWINDIVERT_IPHDR *ip_header_ptr, PWINDIVERT_IPV6HDR *ipv6_header_ptr,
    PWINDIVERT_ICMPHDR *icmp_header_ptr,
    PWINDIVERT_ICMPV6HDR *icmpv6_header_ptr,
    PWINDIVERT_TCPHDR *tcp_header_ptr, PWINDIVERT_UDPHDR *udp_header_ptr,
    UINT8 *proto_ptr, UINT *payload_len_ptr);
static BOOL windivert_filter(PNET_BUFFER buffer, WINDIVERT_LAYER layer,
    PVOID layer_data, WINDIVERT_EVENT event, BOOL ipv4, BOOL outbound,
    BOOL loopback, BOOL impostor, PWINDIVERT_FILTER filter);
static PWINDIVERT_FILTER windivert_filter_compile(
    PWINDIVERT_FILTER ioctl_filter, size_t ioctl_filter_len,
    WINDIVERT_LAYER layer);
static NTSTATUS windivert_reflect_init(WDFOBJECT parent);
static void windivert_reflect_close(void);
static void windivert_reflect_open_event(context_t context);
static void windivert_reflect_close_event(context_t context);
static void windivert_reflect_event_notify(context_t context,
    LONGLONG timestamp, WINDIVERT_EVENT event);
static void windivert_reflect_established_notify(context_t context,
    LONGLONG timestamp);
static void windivert_reflect_worker(IN WDFWORKITEM item);

/*
 * WinDivert sublayer GUIDs
 */
DEFINE_GUID(WINDIVERT_SUBLAYER_INBOUND_IPV4_GUID,
    0x82A99281, 0x0389, 0x4DE2,
    0xAE, 0x2D, 0xA4, 0x51, 0x59, 0x16, 0x26, 0x06);
DEFINE_GUID(WINDIVERT_SUBLAYER_OUTBOUND_IPV4_GUID,
    0xB0BB07C6, 0x3B3B, 0x41FE,
    0x83, 0x8B, 0xD8, 0x37, 0xDD, 0xB8, 0x75, 0x41);
DEFINE_GUID(WINDIVERT_SUBLAYER_INBOUND_IPV6_GUID,
    0xD7674846, 0x3AB5, 0x4E93,
    0x82, 0xD0, 0x2F, 0xCC, 0x03, 0xA2, 0x88, 0x7A);
DEFINE_GUID(WINDIVERT_SUBLAYER_OUTBOUND_IPV6_GUID,
    0x6672F761, 0xA0F2, 0x4578,
    0x92, 0x50, 0x09, 0x03, 0x0D, 0x4E, 0x8C, 0x46);
DEFINE_GUID(WINDIVERT_SUBLAYER_FORWARD_IPV4_GUID,
    0x4622DCC6, 0xBD71, 0x48ED,
    0x9D, 0x1A, 0x72, 0xC9, 0x0D, 0xEB, 0xA1, 0x74);
DEFINE_GUID(WINDIVERT_SUBLAYER_FORWARD_IPV6_GUID,
    0x7E5B39EC, 0xB54C, 0x41B3,
    0xA7, 0x99, 0x47, 0x5E, 0x57, 0x41, 0xA4, 0x33);
DEFINE_GUID(WINDIVERT_SUBLAYER_FLOW_ESTABLISHED_IPV4_GUID,
    0x53D6C270, 0xEB79, 0x44CD,
    0x83, 0xCD, 0x14, 0x34, 0xE6, 0x13, 0x91, 0x68);
DEFINE_GUID(WINDIVERT_SUBLAYER_FLOW_ESTABLISHED_IPV6_GUID,
    0x44B0CDED, 0xAA11, 0x4704,
    0x92, 0xA7, 0x99, 0xD2, 0xB7, 0x59, 0x7A, 0x68);
DEFINE_GUID(WINDIVERT_SUBLAYER_RESOURCE_ASSIGNMENT_IPV4_GUID,
    0x736848B6, 0xBE0D, 0x4A8D,
    0xA0, 0xC2, 0xE2, 0x02, 0xDC, 0x29, 0x32, 0xBC);
DEFINE_GUID(WINDIVERT_SUBLAYER_RESOURCE_ASSIGNMENT_IPV6_GUID,
    0xF3458E58, 0xD123, 0x439B,
    0xB6, 0x40, 0x74, 0x3C, 0xC7, 0x53, 0x9E, 0x36);
DEFINE_GUID(WINDIVERT_SUBLAYER_AUTH_CONNECT_IPV4_GUID,
    0x2F97411F, 0x6350, 0x450A,
    0xBF, 0x45, 0x4C, 0x0B, 0xC1, 0xDB, 0x3F, 0x7E);
DEFINE_GUID(WINDIVERT_SUBLAYER_AUTH_CONNECT_IPV6_GUID,
    0x7BAFEEEB, 0x84F0, 0x4BB0,
    0x91, 0x1F, 0x7E, 0x62, 0x2D, 0x73, 0x24, 0x2C);
DEFINE_GUID(WINDIVERT_SUBLAYER_AUTH_LISTEN_IPV4_GUID,
    0x49F2A9AD, 0x805E, 0x4328,
    0xBB, 0xDA, 0x92, 0x57, 0xB5, 0x18, 0x3A, 0x40);
DEFINE_GUID(WINDIVERT_SUBLAYER_AUTH_LISTEN_IPV6_GUID,
    0xC1BB250E, 0xDE07, 0x41AB,
    0x82, 0xEE, 0xAD, 0x7B, 0xFF, 0x13, 0xCE, 0x35);
DEFINE_GUID(WINDIVERT_SUBLAYER_AUTH_RECV_ACCEPT_IPV4_GUID,
    0x7A012579, 0xC75A, 0x4D29,
    0xB7, 0x47, 0x04, 0xAD, 0x3C, 0x7B, 0x32, 0x69);
DEFINE_GUID(WINDIVERT_SUBLAYER_AUTH_RECV_ACCEPT_IPV6_GUID,
    0x1C51DD53, 0x6BA4, 0x4149,
    0x89, 0x97, 0x1C, 0xD4, 0x8B, 0x51, 0x1B, 0x7D);

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
    windivert_inbound_network_v4_classify,
    NULL,
    UINT16_MAX
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
    windivert_outbound_network_v4_classify,
    NULL,
    UINT16_MAX
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
    windivert_inbound_network_v6_classify,
    NULL,
    UINT16_MAX
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
    windivert_outbound_network_v6_classify,
    NULL,
    UINT16_MAX
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
    windivert_forward_network_v4_classify,
    NULL,
    UINT16_MAX
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
    windivert_forward_network_v6_classify,
    NULL,
    UINT16_MAX
};
static layer_t layer_forward_network_ipv6 = &layer_forward_network_ipv6_0;

static struct layer_s layer_resource_assignment_ipv4_0 =
{
    L"" WINDIVERT_DEVICE_NAME L"_SubLayerResourceAssignmentIPv4",
    L"" WINDIVERT_DEVICE_NAME L" sublayer flow established (IPv4)",
    L"" WINDIVERT_DEVICE_NAME L"_CalloutResourceAssignmentIPv4",
    L"" WINDIVERT_DEVICE_NAME L" callout flow established (IPv4)",
    L"" WINDIVERT_DEVICE_NAME L"_FilterResourceAssignmentIPv4",
    L"" WINDIVERT_DEVICE_NAME L" filter flow established (IPv4)",
    {0},
    {0},
    windivert_resource_assignment_v4_classify,
    NULL,
    0
};
static layer_t layer_resource_assignment_ipv4 =
    &layer_resource_assignment_ipv4_0;

static struct layer_s layer_resource_assignment_ipv6_0 =
{
    L"" WINDIVERT_DEVICE_NAME L"_SubLayerResourceAssignmentIPv6",
    L"" WINDIVERT_DEVICE_NAME L" sublayer flow established (IPv6)",
    L"" WINDIVERT_DEVICE_NAME L"_CalloutResourceAssignmentIPv6",
    L"" WINDIVERT_DEVICE_NAME L" callout flow established (IPv6)",
    L"" WINDIVERT_DEVICE_NAME L"_FilterResourceAssignmentIPv6",
    L"" WINDIVERT_DEVICE_NAME L" filter flow established (IPv6)",
    {0},
    {0},
    windivert_resource_assignment_v6_classify,
    NULL,
    0
};
static layer_t layer_resource_assignment_ipv6 =
    &layer_resource_assignment_ipv6_0;

static struct layer_s layer_auth_connect_ipv4_0 =
{
    L"" WINDIVERT_DEVICE_NAME L"_SubLayerAuthConnectIPv4",
    L"" WINDIVERT_DEVICE_NAME L" sublayer flow established (IPv4)",
    L"" WINDIVERT_DEVICE_NAME L"_CalloutAuthConnectIPv4",
    L"" WINDIVERT_DEVICE_NAME L" callout flow established (IPv4)",
    L"" WINDIVERT_DEVICE_NAME L"_FilterAuthConnectIPv4",
    L"" WINDIVERT_DEVICE_NAME L" filter flow established (IPv4)",
    {0},
    {0},
    windivert_auth_connect_v4_classify,
    NULL,
    0
};
static layer_t layer_auth_connect_ipv4 = &layer_auth_connect_ipv4_0;

static struct layer_s layer_auth_connect_ipv6_0 =
{
    L"" WINDIVERT_DEVICE_NAME L"_SubLayerAuthConnectIPv6",
    L"" WINDIVERT_DEVICE_NAME L" sublayer flow established (IPv6)",
    L"" WINDIVERT_DEVICE_NAME L"_CalloutAuthConnectIPv6",
    L"" WINDIVERT_DEVICE_NAME L" callout flow established (IPv6)",
    L"" WINDIVERT_DEVICE_NAME L"_FilterAuthConnectIPv6",
    L"" WINDIVERT_DEVICE_NAME L" filter flow established (IPv6)",
    {0},
    {0},
    windivert_auth_connect_v6_classify,
    NULL,
    0
};
static layer_t layer_auth_connect_ipv6 = &layer_auth_connect_ipv6_0;

static struct layer_s layer_auth_listen_ipv4_0 =
{
    L"" WINDIVERT_DEVICE_NAME L"_SubLayerAuthListenIPv4",
    L"" WINDIVERT_DEVICE_NAME L" sublayer flow established (IPv4)",
    L"" WINDIVERT_DEVICE_NAME L"_CalloutAuthListenIPv4",
    L"" WINDIVERT_DEVICE_NAME L" callout flow established (IPv4)",
    L"" WINDIVERT_DEVICE_NAME L"_FilterAuthListenIPv4",
    L"" WINDIVERT_DEVICE_NAME L" filter flow established (IPv4)",
    {0},
    {0},
    windivert_auth_listen_v4_classify,
    NULL,
    0
};
static layer_t layer_auth_listen_ipv4 = &layer_auth_listen_ipv4_0;

static struct layer_s layer_auth_listen_ipv6_0 =
{
    L"" WINDIVERT_DEVICE_NAME L"_SubLayerAuthListenIPv6",
    L"" WINDIVERT_DEVICE_NAME L" sublayer flow established (IPv6)",
    L"" WINDIVERT_DEVICE_NAME L"_CalloutAuthListenIPv6",
    L"" WINDIVERT_DEVICE_NAME L" callout flow established (IPv6)",
    L"" WINDIVERT_DEVICE_NAME L"_FilterAuthListenIPv6",
    L"" WINDIVERT_DEVICE_NAME L" filter flow established (IPv6)",
    {0},
    {0},
    windivert_auth_listen_v6_classify,
    NULL,
    0
};
static layer_t layer_auth_listen_ipv6 = &layer_auth_listen_ipv6_0;

static struct layer_s layer_auth_recv_accept_ipv4_0 =
{
    L"" WINDIVERT_DEVICE_NAME L"_SubLayerAuthRecvAcceptIPv4",
    L"" WINDIVERT_DEVICE_NAME L" sublayer flow established (IPv4)",
    L"" WINDIVERT_DEVICE_NAME L"_CalloutAuthRecvAcceptIPv4",
    L"" WINDIVERT_DEVICE_NAME L" callout flow established (IPv4)",
    L"" WINDIVERT_DEVICE_NAME L"_FilterAuthRecvAcceptIPv4",
    L"" WINDIVERT_DEVICE_NAME L" filter flow established (IPv4)",
    {0},
    {0},
    windivert_auth_recv_accept_v4_classify,
    NULL,
    0
};
static layer_t layer_auth_recv_accept_ipv4 = &layer_auth_recv_accept_ipv4_0;

static struct layer_s layer_auth_recv_accept_ipv6_0 =
{
    L"" WINDIVERT_DEVICE_NAME L"_SubLayerAuthRecvAcceptIPv6",
    L"" WINDIVERT_DEVICE_NAME L" sublayer flow established (IPv6)",
    L"" WINDIVERT_DEVICE_NAME L"_CalloutAuthRecvAcceptIPv6",
    L"" WINDIVERT_DEVICE_NAME L" callout flow established (IPv6)",
    L"" WINDIVERT_DEVICE_NAME L"_FilterAuthRecvAcceptIPv6",
    L"" WINDIVERT_DEVICE_NAME L" filter flow established (IPv6)",
    {0},
    {0},
    windivert_auth_recv_accept_v6_classify,
    NULL,
    0
};
static layer_t layer_auth_recv_accept_ipv6 = &layer_auth_recv_accept_ipv6_0;

static struct layer_s layer_flow_established_ipv4_0 =
{
    L"" WINDIVERT_DEVICE_NAME L"_SubLayerFlowEstablishedIPv4",
    L"" WINDIVERT_DEVICE_NAME L" sublayer flow established (IPv4)",
    L"" WINDIVERT_DEVICE_NAME L"_CalloutFlowEstablishedIPv4",
    L"" WINDIVERT_DEVICE_NAME L" callout flow established (IPv4)",
    L"" WINDIVERT_DEVICE_NAME L"_FilterFlowEstablishedIPv4",
    L"" WINDIVERT_DEVICE_NAME L" filter flow established (IPv4)",
    {0},
    {0},
    windivert_flow_established_v4_classify,
    windivert_flow_delete_notify,
    0
};
static layer_t layer_flow_established_ipv4 = &layer_flow_established_ipv4_0;

static struct layer_s layer_flow_established_ipv6_0 =
{
    L"" WINDIVERT_DEVICE_NAME L"_SubLayerFlowEstablishedIPv6",
    L"" WINDIVERT_DEVICE_NAME L" sublayer flow established (IPv6)",
    L"" WINDIVERT_DEVICE_NAME L"_CalloutFlowEstablishedIPv6",
    L"" WINDIVERT_DEVICE_NAME L" callout flow established (IPv6)",
    L"" WINDIVERT_DEVICE_NAME L"_FilterFlowEstablishedIPv6",
    L"" WINDIVERT_DEVICE_NAME L" filter flow established (IPv6)",
    {0},
    {0},
    windivert_flow_established_v6_classify,
    windivert_flow_delete_notify,
    0
};
static layer_t layer_flow_established_ipv6 = &layer_flow_established_ipv6_0;

/*
 * Shared functions.
 */
#include "windivert_shared.c"

/*
 * WinDivert malloc/free.
 */
static PVOID windivert_malloc(SIZE_T size, BOOL paged)
{
    POOL_TYPE pool = (paged? PagedPool: non_paged_pool);
    if (size == 0)
    {
        return NULL;
    }
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
            no_exec_flag   = (MM_PAGE_PRIORITY)0x40000000;
                                                // MdlMappingNoExecute
            no_write_flag  = (MM_PAGE_PRIORITY)0x80000000;
                                                // MdlMappingNoWrite
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
    layer_flow_established_ipv4->layer_guid =
        FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;
    layer_flow_established_ipv6->layer_guid =
        FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6;
    layer_resource_assignment_ipv4->layer_guid =
        FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4;
    layer_resource_assignment_ipv6->layer_guid =
        FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6;
    layer_auth_connect_ipv4->layer_guid = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    layer_auth_connect_ipv6->layer_guid = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    layer_auth_listen_ipv4->layer_guid = FWPM_LAYER_ALE_AUTH_LISTEN_V4;
    layer_auth_listen_ipv6->layer_guid = FWPM_LAYER_ALE_AUTH_LISTEN_V6;
    layer_auth_recv_accept_ipv4->layer_guid =
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
    layer_auth_recv_accept_ipv6->layer_guid =
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
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
    layer_flow_established_ipv4->sublayer_guid =
        WINDIVERT_SUBLAYER_FLOW_ESTABLISHED_IPV4_GUID;
    layer_flow_established_ipv6->sublayer_guid =
        WINDIVERT_SUBLAYER_FLOW_ESTABLISHED_IPV6_GUID;
    layer_resource_assignment_ipv4->sublayer_guid =
        WINDIVERT_SUBLAYER_RESOURCE_ASSIGNMENT_IPV4_GUID;
    layer_resource_assignment_ipv6->sublayer_guid =
        WINDIVERT_SUBLAYER_RESOURCE_ASSIGNMENT_IPV6_GUID;
    layer_auth_connect_ipv4->sublayer_guid =
        WINDIVERT_SUBLAYER_AUTH_CONNECT_IPV4_GUID;
    layer_auth_connect_ipv6->sublayer_guid =
        WINDIVERT_SUBLAYER_AUTH_CONNECT_IPV6_GUID;
    layer_auth_listen_ipv4->sublayer_guid =
        WINDIVERT_SUBLAYER_AUTH_LISTEN_IPV4_GUID;
    layer_auth_listen_ipv6->sublayer_guid =
        WINDIVERT_SUBLAYER_AUTH_LISTEN_IPV6_GUID;
    layer_auth_recv_accept_ipv4->sublayer_guid =
        WINDIVERT_SUBLAYER_AUTH_RECV_ACCEPT_IPV4_GUID;
    layer_auth_recv_accept_ipv6->sublayer_guid =
        WINDIVERT_SUBLAYER_AUTH_RECV_ACCEPT_IPV6_GUID;

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
    status = windivert_install_sublayer(layer_flow_established_ipv4);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = windivert_install_sublayer(layer_flow_established_ipv6);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = windivert_install_sublayer(layer_resource_assignment_ipv4);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = windivert_install_sublayer(layer_resource_assignment_ipv6);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = windivert_install_sublayer(layer_auth_connect_ipv4);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = windivert_install_sublayer(layer_auth_connect_ipv6);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = windivert_install_sublayer(layer_auth_listen_ipv4);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = windivert_install_sublayer(layer_auth_listen_ipv6);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = windivert_install_sublayer(layer_auth_recv_accept_ipv4);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = windivert_install_sublayer(layer_auth_recv_accept_ipv6);
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

    status = windivert_reflect_init((WDFOBJECT)device);
    if (!NT_SUCCESS(status))
    {
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
        FwpmSubLayerDeleteByKey0(engine_handle,
            &layer_flow_established_ipv4->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            &layer_flow_established_ipv6->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            &layer_resource_assignment_ipv4->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            &layer_resource_assignment_ipv6->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            &layer_auth_connect_ipv4->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            &layer_auth_connect_ipv6->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            &layer_auth_listen_ipv4->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            &layer_auth_listen_ipv6->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            &layer_auth_recv_accept_ipv4->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            &layer_auth_recv_accept_ipv6->sublayer_guid);
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
    sublayer.subLayerKey             = layer->sublayer_guid;
    sublayer.displayData.name        = layer->sublayer_name;
    sublayer.displayData.description = layer->sublayer_desc;
    sublayer.weight                  = layer->sublayer_weight;

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
    context->priority = windivert_context_priority(WINDIVERT_PRIORITY_DEFAULT);
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
    KeInitializeSpinLock(&context->lock);
    InitializeListHead(&context->flow_set);
    context->flow_v4_callout_id = 0;
    context->flow_v6_callout_id = 0;
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
    RtlZeroMemory(&context->reflect, sizeof(context->reflect));

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
    UINT64 flags)
{
    UINT8 i, j;
    layer_t layers[WINDIVERT_CONTEXT_MAXLAYERS];
    UINT32 *callout_ids[WINDIVERT_CONTEXT_MAXLAYERS] = {NULL};
    BOOL inbound, outbound, ipv4, ipv6;
    NTSTATUS status = STATUS_SUCCESS;

    inbound  = ((flags & WINDIVERT_FILTER_FLAG_INBOUND) != 0);
    outbound = ((flags & WINDIVERT_FILTER_FLAG_OUTBOUND) != 0);
    ipv4     = ((flags & WINDIVERT_FILTER_FLAG_IP) != 0);
    ipv6     = ((flags & WINDIVERT_FILTER_FLAG_IPV6) != 0);

    i = 0;
    switch (layer)
    {
        case WINDIVERT_LAYER_NETWORK:
            if (inbound && ipv4)
            {
                layers[i++] = layer_inbound_network_ipv4;
            }
            if (outbound && ipv4)
            {
                layers[i++] = layer_outbound_network_ipv4;
            }
            if (inbound && ipv6)
            {
                layers[i++] = layer_inbound_network_ipv6;
            }
            if (outbound && ipv6)
            {
                layers[i++] = layer_outbound_network_ipv6;
            }
            break;

        case WINDIVERT_LAYER_NETWORK_FORWARD:
            if (ipv4)
            {
                layers[i++] = layer_forward_network_ipv4;
            }
            if (ipv6)
            {
                layers[i++] = layer_forward_network_ipv6;
            }
            break;
        
        case WINDIVERT_LAYER_FLOW:
            if (ipv4)
            {
                callout_ids[i] = &context->flow_v4_callout_id;
                layers[i++] = layer_flow_established_ipv4;
            }
            if (ipv6)
            {
                callout_ids[i] = &context->flow_v6_callout_id;
                layers[i++] = layer_flow_established_ipv6;
            }
            break;

        case WINDIVERT_LAYER_SOCKET:
            if (ipv4)
            {
                layers[i++] = layer_resource_assignment_ipv4;
                layers[i++] = layer_auth_connect_ipv4;
                layers[i++] = layer_auth_listen_ipv4;
                layers[i++] = layer_auth_recv_accept_ipv4;
            }
            if (ipv6)
            {
                layers[i++] = layer_resource_assignment_ipv6;
                layers[i++] = layer_auth_connect_ipv6;
                layers[i++] = layer_auth_listen_ipv6;
                layers[i++] = layer_auth_recv_accept_ipv6;
            }
            break;

        case WINDIVERT_LAYER_REFLECT:
            break;

        default:
            return STATUS_INVALID_PARAMETER;
    }

    for (j = 0; j < i; j++)
    {
        status = windivert_install_callout(context, j, layers[j],
            callout_ids[j]);
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
    layer_t layer, UINT32 *callout_id_ptr)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    FWPS_CALLOUT0 scallout;
    FWPM_CALLOUT0 mcallout;
    FWPM_FILTER0 filter;
    UINT64 weight;
    UINT32 priority;
    GUID callout_guid, filter_guid;
    UINT32 callout_id;
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
    scallout.classifyFn              = layer->classify;
    scallout.notifyFn                = windivert_notify;
    scallout.flowDeleteFn            = layer->flow_delete;
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
        &scallout, &callout_id);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to install WFP callout", status);
        return status;
    }
    if (callout_id_ptr != NULL)
    {
        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
        *callout_id_ptr = callout_id;
        KeReleaseInStackQueuedSpinLock(&lock_handle);
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
        goto windivert_uninstall_callouts_unregister;
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
        goto windivert_uninstall_callouts_unregister;
    }
    status = FwpmTransactionCommit0(engine_handle);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to commit WFP transaction", status);
        // continue
    }

windivert_uninstall_callouts_unregister:
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
        status = FwpsCalloutUnregisterByKey0(&callout_guid);
        if (!NT_SUCCESS(status))
        {
            DEBUG_ERROR("failed to delete callout", status);
            continue;
        }
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
    flow_t flow;
    packet_t work, packet;
    WDFQUEUE read_queue;
    WDFWORKITEM worker;
    LONGLONG timestamp;
    BOOL sniff_mode, timeout, forward;
    UINT priority;
    NTSTATUS status;
    
    DEBUG("CLEANUP: cleaning up WinDivert context (context=%p)", context);

    windivert_reflect_close_event(context);
    timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
    
    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != WINDIVERT_CONTEXT_STATE_OPENING &&
            context->state != WINDIVERT_CONTEXT_STATE_OPEN)
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
    while (!IsListEmpty(&context->flow_set))
    {
        entry = RemoveHeadList(&context->flow_set);
        flow = CONTAINING_RECORD(entry, struct flow_s, entry);
        flow->deleted = TRUE;
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        status = FwpsFlowRemoveContext0(flow->flow_id, flow->layer_id,
            flow->callout_id);
        if (!NT_SUCCESS(status))
        {
            windivert_free(flow);
        }
        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    }
    while (!IsListEmpty(&context->packet_queue))
    {
        entry = RemoveHeadList(&context->packet_queue);
        packet = CONTAINING_RECORD(entry, struct packet_s, entry);
        context->packet_queue_length--;
        context->packet_queue_size -= packet->packet_len;
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        timeout = WINDIVERT_TIMEOUT(context, packet->timestamp, timestamp);
        if (!sniff_mode && !timeout)
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
        if (!sniff_mode && !timeout)
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
    PWINDIVERT_FILTER filter;
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
    windivert_uninstall_callouts(context, WINDIVERT_CONTEXT_STATE_CLOSED);
    FwpmEngineClose0(context->engine_handle);
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
    if ((context->flags & WINDIVERT_FLAG_SEND_ONLY) != 0)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        status = STATUS_INVALID_PARAMETER;
        DEBUG_ERROR("failed to inject; send-only flag is set", status);
        return status;
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
    UINT8 *layer_data, *src, *dst;
    ULONG dst_len, src_len;
    req_context_t req_context;
    PWINDIVERT_ADDRESS addr;
    NTSTATUS status;

    DEBUG("SERVICE: servicing read request (request=%p, packet=%p)", request,
        packet);
        
    layer_data = (PVOID)packet->data;
    switch (packet->layer)
    {
        case WINDIVERT_LAYER_NETWORK:
        case WINDIVERT_LAYER_NETWORK_FORWARD:
        case WINDIVERT_LAYER_REFLECT:

            status = WdfRequestRetrieveOutputWdmMdl(request, &dst_mdl);
            if (!NT_SUCCESS(status))
            {
                DEBUG_ERROR("failed to retrieve output MDL", status);
                goto windivert_read_service_request_exit;
            }
            dst = MmGetSystemAddressForMdlSafe(dst_mdl,
                NormalPagePriority | no_exec_flag);
            if (dst == NULL)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                DEBUG_ERROR("failed to get address of output MDL", status);
                goto windivert_read_service_request_exit;
            }

            if (packet->layer != WINDIVERT_LAYER_REFLECT)
            {
                src = WINDIVERT_PACKET_DATA_PTR(WINDIVERT_DATA_NETWORK, packet);
            }
            else
            {
                src = WINDIVERT_PACKET_DATA_PTR(WINDIVERT_DATA_REFLECT, packet);
            }
            src_len = packet->packet_len;
            dst_len = MmGetMdlByteCount(dst_mdl);
            dst_len = (src_len < dst_len? src_len: dst_len);
            RtlCopyMemory(dst, src, dst_len);
            break;

        case WINDIVERT_LAYER_FLOW:
        case WINDIVERT_LAYER_SOCKET:

            status = STATUS_SUCCESS;
            dst_len = 0;
            break;

        default:
            status = STATUS_INVALID_DEVICE_STATE;
            DEBUG_ERROR("invalid packet layer", status);
            goto windivert_read_service_request_exit;
    }

    // Write the address information.
    req_context = windivert_req_context_get(request);
    addr = req_context->addr;
    if (addr != NULL)
    {
        addr->Timestamp         = (INT64)packet->timestamp;
        addr->Layer             = packet->layer;
        addr->Event             = packet->event;
        addr->Outbound          = packet->outbound;
        addr->Loopback          = packet->loopback;
        addr->Impostor          = packet->impostor;
        addr->IPv6              = packet->ipv6;
        addr->PseudoIPChecksum  = packet->pseudo_ip_checksum;
        addr->PseudoTCPChecksum = packet->pseudo_tcp_checksum;
        addr->PseudoUDPChecksum = packet->pseudo_udp_checksum;
        addr->Final             = packet->final;
        addr->Reserved          = 0;
        switch (packet->layer)
        {
            case WINDIVERT_LAYER_NETWORK:
            case WINDIVERT_LAYER_NETWORK_FORWARD:
                RtlCopyMemory(&addr->Network, layer_data,
                    sizeof(WINDIVERT_DATA_NETWORK));
                break;

            case WINDIVERT_LAYER_FLOW:
                RtlCopyMemory(&addr->Flow, layer_data,
                    sizeof(WINDIVERT_DATA_FLOW));
                break;

            case WINDIVERT_LAYER_SOCKET:
                RtlCopyMemory(&addr->Socket, layer_data,
                    sizeof(WINDIVERT_DATA_SOCKET));
                break;

            case WINDIVERT_LAYER_REFLECT:
                RtlCopyMemory(&addr->Reflect, layer_data,
                    sizeof(WINDIVERT_DATA_REFLECT));
                break;

            default:
                break;
        }
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
        context->packet_queue_size -= packet->packet_len;
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
    BOOL ipv4;
    UINT8 layer;
    UINT32 priority;
    UINT64 flags, checksums;
    HANDLE handle, compl_handle;
    PNET_BUFFER_LIST buffers = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    DEBUG("WRITE: writing/injecting a packet (context=%p, request=%p)",
        context, request);
    
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

    if ((flags & WINDIVERT_FLAG_RECV_ONLY) != 0)
    {
        status = STATUS_INVALID_PARAMETER;
        DEBUG_ERROR("failed to inject; recv-only flag is set", status);
        goto windivert_write_exit;
    }

    switch (layer)
    {
        case WINDIVERT_LAYER_FLOW:
        case WINDIVERT_LAYER_SOCKET:
        case WINDIVERT_LAYER_REFLECT:
            status = STATUS_INVALID_PARAMETER;
            DEBUG_ERROR("failed to inject at layer", status);
            goto windivert_write_exit;
        default:
            break;
    }

    status = WdfRequestRetrieveOutputWdmMdl(request, &mdl);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to retrieve input MDL", status);
        goto windivert_write_exit;
    }

    data = MmGetSystemAddressForMdlSafe(mdl,
        NormalPagePriority | no_write_flag | no_exec_flag);
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

    // Copy packet data:
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
            ipv4 = TRUE;
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
            ipv4 = FALSE;
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

    // Fix checksums:
    if (addr->PseudoIPChecksum != 0 || addr->PseudoTCPChecksum != 0 ||
        addr->PseudoUDPChecksum != 0)
    {
        checksums = 
            (addr->PseudoIPChecksum?  0: WINDIVERT_HELPER_NO_IP_CHECKSUM) |
            (addr->PseudoTCPChecksum? 0: WINDIVERT_HELPER_NO_TCP_CHECKSUM) |
            (addr->PseudoUDPChecksum? 0: WINDIVERT_HELPER_NO_UDP_CHECKSUM);
        WinDivertHelperCalcChecksums(data_copy, data_len, NULL, checksums);
    }

    // Decrement TTL for impostor packets:
    if (addr->Impostor && !windivert_decrement_ttl(data_copy, ipv4))
    {
        status = STATUS_HOPLIMIT_EXCEEDED;
        goto windivert_write_exit;
    }

    // Allocate packet:
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

    // Inject packet:
    handle = (ipv4? inject_handle: injectv6_handle);
    compl_handle = ((flags & WINDIVERT_FLAG_DEBUG) != 0? (HANDLE)request: NULL);
    if (layer == WINDIVERT_LAYER_NETWORK_FORWARD)
    {
        status = FwpsInjectForwardAsync0(handle, (HANDLE)priority, 0,
            (ipv4? AF_INET: AF_INET6), UNSPECIFIED_COMPARTMENT_ID,
            addr->Network.IfIdx, buffers, windivert_inject_complete,
            compl_handle);
    }
    else if (addr->Outbound != 0)
    {
        status = FwpsInjectNetworkSendAsync0(handle, (HANDLE)priority, 0,
            UNSPECIFIED_COMPARTMENT_ID, buffers, windivert_inject_complete,
            compl_handle);
    }
    else
    {
        status = FwpsInjectNetworkReceiveAsync0(handle, (HANDLE)priority, 0,
            UNSPECIFIED_COMPARTMENT_ID, addr->Network.IfIdx,
            addr->Network.SubIfIdx, buffers, windivert_inject_complete,
            compl_handle);
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
        // Request completed in windivert_ioctl()
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
    data = MmGetSystemAddressForMdlSafe(mdl,
        NormalPagePriority | no_exec_flag);
    windivert_free(data);
    IoFreeMdl(mdl);
    FwpsFreeNetBufferList0(buffers);
}

/*
 * WinDivert reinject complete routine.
 */
static void NTAPI windivert_reinject_complete(VOID *context,
    NET_BUFFER_LIST *buffers, BOOLEAN dispatch_level)
{
    PMDL mdl;
    PNET_BUFFER buffer;
    size_t length;
    packet_t packet;
    UNREFERENCED_PARAMETER(dispatch_level);

    buffer = NET_BUFFER_LIST_FIRST_NB(buffers);
    packet = (packet_t)context;
    mdl = NET_BUFFER_FIRST_MDL(buffer);
    windivert_free_packet(packet);
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
    PWINDIVERT_IOCTL ioctl;
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

    if (inbuflen != sizeof(WINDIVERT_IOCTL))
    {
        status = STATUS_INVALID_PARAMETER;
        DEBUG_ERROR("input buffer not an ioctl message header", status);
        goto windivert_caller_context_error;
    }

    ioctl = (PWINDIVERT_IOCTL)inbuf;
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
    PWINDIVERT_IOCTL ioctl;
    PWINDIVERT_FILTER filter0;
    PWINDIVERT_FILTER filter;
    UINT8 layer;
    INT16 priority;
    UINT32 priority32;
    INT64 priority64;
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
            BOOL inbound, outbound, ipv4, ipv6;
            PIRP irp;
            LONGLONG timestamp;
            UINT32 process_id;
            UINT8 filter_len;

            ioctl = (PWINDIVERT_IOCTL)inbuf;
            if ((ioctl->arg & ~WINDIVERT_FILTER_FLAGS_ALL) != 0)
            {
                status = STATUS_INVALID_PARAMETER;
                DEBUG_ERROR("failed to start filter; invalid flags", status);
                goto windivert_ioctl_exit;
            }
 
            filter = NULL;
            KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
            if (context->state != WINDIVERT_CONTEXT_STATE_OPENING)
            {
windivert_ioctl_bad_start_state:
                KeReleaseInStackQueuedSpinLock(&lock_handle);
                windivert_free(filter);
                status = STATUS_INVALID_DEVICE_STATE;
                goto windivert_ioctl_exit;
            }
            context->state = WINDIVERT_CONTEXT_STATE_OPEN;
            layer = context->layer;
            KeReleaseInStackQueuedSpinLock(&lock_handle);

            filter0 = (PWINDIVERT_FILTER)outbuf;
            filter0_len = outbuflen;
            filter = windivert_filter_compile(filter0, filter0_len, layer);
            if (filter == NULL)
            {
                status = STATUS_INVALID_PARAMETER;
                DEBUG_ERROR("failed to compile filter", status);
                goto windivert_ioctl_exit;
            }
            filter_len = filter0_len / sizeof(WINDIVERT_FILTER);
            irp = WdfRequestWdmGetIrp(request);
            process_id = (UINT32)IoGetRequestorProcessId(irp);
            timestamp = KeQueryPerformanceCounter(NULL).QuadPart;

            KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
            if (context->state != WINDIVERT_CONTEXT_STATE_OPEN)
            {
                goto windivert_ioctl_bad_start_state;
            }
            flags = context->flags;
            switch (layer)
            {
                case WINDIVERT_LAYER_FLOW:
                case WINDIVERT_LAYER_REFLECT:
                    if ((flags & WINDIVERT_FLAG_SNIFF) == 0 ||
                        (flags & WINDIVERT_FLAG_RECV_ONLY) == 0)
                    {
                        goto windivert_ioctl_bad_start_state;
                    }
                    break;

                case WINDIVERT_LAYER_SOCKET:
                    if ((flags & WINDIVERT_FLAG_RECV_ONLY) == 0)
                    {
                        goto windivert_ioctl_bad_start_state;
                    }
                    break;

                default:
                    break;
            }
            context->filter                 = filter;
            context->filter_len             = filter_len;
            context->reflect.data.Timestamp = timestamp;
            context->reflect.data.ProcessId = process_id;
            context->reflect.data.Layer     = context->layer;
            context->reflect.data.Flags     = context->flags;
            context->reflect.data.Priority  = context->priority16;
            context->reflect.open           = FALSE;
            KeReleaseInStackQueuedSpinLock(&lock_handle);

            windivert_reflect_open_event(context);

            flags = ioctl->arg;
            status = windivert_install_callouts(context, layer, flags);

            break;
        }

        case IOCTL_WINDIVERT_SET_LAYER:
            ioctl = (PWINDIVERT_IOCTL)inbuf;
            switch (ioctl->arg)
            {
                case WINDIVERT_LAYER_NETWORK:
                case WINDIVERT_LAYER_NETWORK_FORWARD:
                case WINDIVERT_LAYER_FLOW:
                case WINDIVERT_LAYER_SOCKET:
                case WINDIVERT_LAYER_REFLECT:
                    break;
                default:
                    status = STATUS_INVALID_PARAMETER;
                    DEBUG_ERROR("failed to set layer; invalid value", status);
                    goto windivert_ioctl_exit;
            }
            layer = (UINT8)ioctl->arg;
            KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
            if (context->state != WINDIVERT_CONTEXT_STATE_OPENING)
            {
                KeReleaseInStackQueuedSpinLock(&lock_handle);
                status = STATUS_INVALID_DEVICE_STATE;
                goto windivert_ioctl_exit;
            }
            context->layer = layer;
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            break;

        case IOCTL_WINDIVERT_SET_PRIORITY:
            ioctl = (PWINDIVERT_IOCTL)inbuf;
            priority64 = (INT64)ioctl->arg - WINDIVERT_PRIORITY_MAX;
            if (priority64 < WINDIVERT_PRIORITY_MIN ||
                priority64 > WINDIVERT_PRIORITY_MAX)
            {
                status = STATUS_INVALID_PARAMETER;
                DEBUG_ERROR("failed to set priority; value out of range",
                    status);
                goto windivert_ioctl_exit;
            }
            priority32 = windivert_context_priority(priority64);
            KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
            if (context->state != WINDIVERT_CONTEXT_STATE_OPENING)
            {
                KeReleaseInStackQueuedSpinLock(&lock_handle);
                status = STATUS_INVALID_DEVICE_STATE;
                goto windivert_ioctl_exit;
            }
            context->priority16 = (INT16)priority64;
            context->priority = priority32;
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            break;

        case IOCTL_WINDIVERT_SET_FLAGS:
            ioctl = (PWINDIVERT_IOCTL)inbuf;
            if (!WINDIVERT_FLAGS_VALID(ioctl->arg))
            {
                status = STATUS_INVALID_PARAMETER;
                DEBUG_ERROR("failed to set flags; invalid flags value",
                    status);
                goto windivert_ioctl_exit;
            }
            flags = ioctl->arg;
            KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
            if (context->state != WINDIVERT_CONTEXT_STATE_OPENING)
            {
                KeReleaseInStackQueuedSpinLock(&lock_handle);
                status = STATUS_INVALID_DEVICE_STATE;
                goto windivert_ioctl_exit;
            }
            context->flags = flags;
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            break;

        case IOCTL_WINDIVERT_SET_PARAM:
            ioctl = (PWINDIVERT_IOCTL)inbuf;
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
            ioctl = (PWINDIVERT_IOCTL)inbuf;
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
 * WinDivert notify function.
 */
static NTSTATUS windivert_notify(IN FWPS_CALLOUT_NOTIFY_TYPE type,
    IN const GUID *filter_key, IN const FWPS_FILTER0 *filter)
{
    UNREFERENCED_PARAMETER(type);
    UNREFERENCED_PARAMETER(filter_key);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

/*
 * WinDivert get fixed values.
 */
static UINT8 windivert_get_val8(const FWPS_INCOMING_VALUES0 *fixed_vals,
    int idx)
{
    FWP_VALUE0 value = fixed_vals->incomingValue[idx].value;
    return (value.type != FWP_UINT8? 0: value.uint8);
}
static UINT16 windivert_get_val16(const FWPS_INCOMING_VALUES0 *fixed_vals,
    int idx)
{
    FWP_VALUE0 value = fixed_vals->incomingValue[idx].value;
    return (value.type != FWP_UINT16? 0: value.uint16);
}
static UINT32 windivert_get_val32(const FWPS_INCOMING_VALUES0 *fixed_vals,
    int idx)
{
    FWP_VALUE0 value = fixed_vals->incomingValue[idx].value;
    return (value.type != FWP_UINT32? 0: value.uint32);
}
static void windivert_get_ipv4_addr(const FWPS_INCOMING_VALUES0 *fixed_vals,
    int idx, UINT32 *addr)
{
    FWP_VALUE0 value = fixed_vals->incomingValue[idx].value;
    addr[2] = addr[3] = 0;
    if (value.type != FWP_UINT32)
    {
        addr[0] = addr[1] = 0;
    }
    else
    {
        addr[0] = value.uint32;
        addr[1] = 0x0000FFFF;
    }
}
static void windivert_get_ipv6_addr(const FWPS_INCOMING_VALUES0 *fixed_vals,
    int idx, UINT32 *addr)
{
    UINT8 *addr8 = (UINT8 *)addr;
    INT i;
    FWP_VALUE0 value = fixed_vals->incomingValue[idx].value;
	if (value.type != FWP_BYTE_ARRAY16_TYPE)
    {
        RtlZeroMemory(&addr, 16);
        return;
    }
    for (i = 16-1; i >= 0; i--)
    {
        addr8[16-i-1] = value.byteArray16->byteArray16[i];
    }
}

/*
 * WinDivert classify outbound IPv4 function.
 */
static void windivert_outbound_network_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    WINDIVERT_DATA_NETWORK network_data;
    BOOL loopback;

    if ((result->rights & FWPS_RIGHT_ACTION_WRITE) == 0 || data == NULL)
    {
        return;
    }

    network_data.IfIdx = windivert_get_val32(fixed_vals,
        FWPS_FIELD_OUTBOUND_IPPACKET_V4_INTERFACE_INDEX);
    network_data.SubIfIdx = windivert_get_val32(fixed_vals,
        FWPS_FIELD_OUTBOUND_IPPACKET_V4_SUB_INTERFACE_INDEX);
    loopback = ((windivert_get_val32(fixed_vals,
        FWPS_FIELD_OUTBOUND_IPPACKET_V4_FLAGS) &
            FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    windivert_network_classify((context_t)filter->context, &network_data,
        /*ipv4=*/TRUE, /*outbound=*/TRUE, loopback, /*advance=*/0, data,
        result);
}

/*
 * WinDivert classify outbound IPv6 function.
 */
static void windivert_outbound_network_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    WINDIVERT_DATA_NETWORK network_data;
    BOOL loopback;
 
    if ((result->rights & FWPS_RIGHT_ACTION_WRITE) == 0 || data == NULL)
    {
        return;
    }

    network_data.IfIdx = windivert_get_val32(fixed_vals,
        FWPS_FIELD_OUTBOUND_IPPACKET_V6_INTERFACE_INDEX);
    network_data.SubIfIdx = windivert_get_val32(fixed_vals,
        FWPS_FIELD_OUTBOUND_IPPACKET_V6_SUB_INTERFACE_INDEX);
    loopback = ((windivert_get_val32(fixed_vals,
        FWPS_FIELD_OUTBOUND_IPPACKET_V6_FLAGS) &
            FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    windivert_network_classify((context_t)filter->context, &network_data,
        /*ipv4=*/FALSE, /*outbound=*/TRUE, loopback, /*advance=*/0,
        data, result);
}

/*
 * WinDivert classify inbound IPv4 function.
 */
static void windivert_inbound_network_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    WINDIVERT_DATA_NETWORK network_data;
    UINT advance;
    BOOL loopback;
 
    if ((result->rights & FWPS_RIGHT_ACTION_WRITE) == 0 || data == NULL)
    {
        return;
    }

    loopback = ((windivert_get_val32(fixed_vals,
        FWPS_FIELD_INBOUND_IPPACKET_V4_FLAGS) &
            FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);
    if (loopback)
    {
        result->actionType = FWP_ACTION_CONTINUE;
        return;
    }

    network_data.IfIdx = windivert_get_val32(fixed_vals,
        FWPS_FIELD_INBOUND_IPPACKET_V4_INTERFACE_INDEX);
    network_data.SubIfIdx = windivert_get_val32(fixed_vals,
        FWPS_FIELD_INBOUND_IPPACKET_V4_SUB_INTERFACE_INDEX);
    advance = meta_vals->ipHeaderSize;
    
    windivert_network_classify((context_t)filter->context, &network_data,
        /*ipv4=*/TRUE, /*outbound=*/FALSE, loopback, advance, data, result);
}

/*
 * WinDivert classify inbound IPv6 function.
 */
static void windivert_inbound_network_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    WINDIVERT_DATA_NETWORK network_data;
    UINT advance;
    BOOL loopback;
 
    if ((result->rights & FWPS_RIGHT_ACTION_WRITE) == 0 || data == NULL)
    {
        return;
    }

    loopback = ((windivert_get_val32(fixed_vals,
        FWPS_FIELD_INBOUND_IPPACKET_V6_FLAGS) &
            FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);
    if (loopback)
    {
        result->actionType = FWP_ACTION_CONTINUE;
        return;
    }

    network_data.IfIdx = windivert_get_val32(fixed_vals,
        FWPS_FIELD_INBOUND_IPPACKET_V6_INTERFACE_INDEX);
    network_data.SubIfIdx = windivert_get_val32(fixed_vals,
        FWPS_FIELD_INBOUND_IPPACKET_V6_SUB_INTERFACE_INDEX);
    advance = meta_vals->ipHeaderSize;
    
    windivert_network_classify((context_t)filter->context, &network_data,
        /*ipv4=*/FALSE, /*outbound=*/FALSE, loopback, advance, data, result);
}

/*
 * WinDivert classify forward IPv4 function.
 */
static void windivert_forward_network_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    WINDIVERT_DATA_NETWORK network_data;
 
    if ((result->rights & FWPS_RIGHT_ACTION_WRITE) == 0 || data == NULL)
    {
        return;
    }
 
    network_data.IfIdx = windivert_get_val32(fixed_vals,
        FWPS_FIELD_IPFORWARD_V4_DESTINATION_INTERFACE_INDEX);
    network_data.SubIfIdx = 0;

    windivert_network_classify((context_t)filter->context, &network_data,
        /*ipv4=*/TRUE, /*outbound=*/TRUE, /*loopback=*/FALSE, /*advance=*/0,
        data, result);
}

/*
 * WinDivert classify forward IPv6 function.
 */
static void windivert_forward_network_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    WINDIVERT_DATA_NETWORK network_data;
 
    if ((result->rights & FWPS_RIGHT_ACTION_WRITE) == 0 || data == NULL)
    {
        return;
    }

    network_data.IfIdx = windivert_get_val32(fixed_vals,
        FWPS_FIELD_IPFORWARD_V6_DESTINATION_INTERFACE_INDEX);
    network_data.SubIfIdx = 0;

    windivert_network_classify((context_t)filter->context, &network_data,
        /*ipv4=*/FALSE, /*outbound=*/TRUE, /*loopback=*/FALSE, /*advance=*/0,
        data, result);
}

/*
 * WinDivert network classify function.
 */
static void windivert_network_classify(context_t context,
    IN PWINDIVERT_DATA_NETWORK network_data, IN BOOL ipv4, IN BOOL outbound,
    IN BOOL loopback, IN UINT advance, IN OUT void *data,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    FWPS_PACKET_INJECTION_STATE packet_state;
    HANDLE packet_context;
    UINT32 priority, packet_priority;
    UINT64 flags;
    WINDIVERT_LAYER layer;
    PNET_BUFFER_LIST buffers;
    PNET_BUFFER buffer, buffer_fst, buffer_itr;
    BOOL impostor, sniff_mode, ok;
    WDFOBJECT object;
    PLIST_ENTRY old_entry;
    PWINDIVERT_FILTER filter;
    LONGLONG timestamp;
    NTSTATUS status;

    result->actionType = FWP_ACTION_CONTINUE;
    buffers = (PNET_BUFFER_LIST)data;
    buffer = NET_BUFFER_LIST_FIRST_NB(buffers);
    if (NET_BUFFER_LIST_NEXT_NBL(buffers) != NULL)
    {
        // This is a fragment group.  This can be ignored since each fragment
        // should have already been indicated.
        return;
    }
    if (ipv4)
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
    flags = context->flags;
    priority = context->priority;
    filter = context->filter;
    layer = context->layer;
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
    do
    {
        BOOL match = windivert_filter(buffer_fst, layer, (PVOID)network_data,
            /*event=*/WINDIVERT_EVENT_NETWORK_PACKET, ipv4, outbound, loopback,
            impostor, filter);
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
    sniff_mode = ((flags & WINDIVERT_FLAG_SNIFF) != 0);
    while (!sniff_mode && buffer_itr != buffer_fst)
    {
        ok = windivert_queue_work(context, (PVOID)buffer_itr,
            NET_BUFFER_DATA_LENGTH(buffer_itr), buffers, layer,
            (PVOID)network_data, /*event=*/WINDIVERT_EVENT_NETWORK_PACKET,
            flags, priority, ipv4, outbound, loopback, impostor,
            /*final=*/FALSE, /*match=*/FALSE, timestamp);
        if (!ok)
        {
            goto windivert_network_classify_exit;
        }
        buffer_itr = NET_BUFFER_NEXT_NB(buffer_itr);
    }

    // STEP (2): Queue the first matching packet buffer_fst:
    ok = windivert_queue_work(context, (PVOID)buffer_itr,
        NET_BUFFER_DATA_LENGTH(buffer_itr), buffers, layer,
        (PVOID)network_data, /*event=*/WINDIVERT_EVENT_NETWORK_PACKET,
        flags, priority, ipv4, outbound, loopback, impostor, /*final=*/FALSE,
        /*match=*/TRUE, timestamp);
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
        goto windivert_network_classify_exit;
    }

    // STEP (3): Queue all remaining packets:
    buffer_itr = NET_BUFFER_NEXT_NB(buffer_fst);
    while (buffer_itr != NULL)
    {
        BOOL match = windivert_filter(buffer_itr, layer, (PVOID)network_data,
            /*event=*/WINDIVERT_EVENT_NETWORK_PACKET, ipv4, outbound,
            loopback, impostor, filter);
        ok = windivert_queue_work(context, (PVOID)buffer_itr,
            NET_BUFFER_DATA_LENGTH(buffer_itr), buffers, layer,
            (PVOID)network_data, /*event=*/WINDIVERT_EVENT_NETWORK_PACKET,
            flags, priority, ipv4, outbound, loopback, impostor, 
            /*FINAL=*/FALSE, match, timestamp);
        if (!ok)
        {
            goto windivert_network_classify_exit;
        }
        buffer_itr = NET_BUFFER_NEXT_NB(buffer_itr);
    }

windivert_network_classify_exit:

    WdfObjectDereference(object);
    if (!sniff_mode)
    {
        result->actionType = FWP_ACTION_BLOCK;
        result->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
        result->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}

/*
 * WinDivert classify flow established IPv4 function.
 */
static void windivert_flow_established_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    WINDIVERT_DATA_FLOW flow_data;
    BOOL outbound, loopback;
    UINT64 flow_id;

    flow_data.ProcessId = (UINT32)meta_vals->processId;
    windivert_get_ipv4_addr(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS,
        flow_data.LocalAddr);
    windivert_get_ipv4_addr(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS,
        flow_data.RemoteAddr);
    flow_data.LocalPort = windivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT);
    flow_data.RemotePort = windivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT);
    flow_data.Protocol = windivert_get_val8(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL);

    outbound = (windivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION) ==
        FWP_DIRECTION_OUTBOUND);
    loopback = ((windivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_FLAGS) &
        FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);
    flow_id = meta_vals->flowHandle;

    windivert_flow_established_classify((context_t)filter->context,
        flow_id, &flow_data, /*ipv4=*/TRUE, outbound, loopback, result);
}

/*
 * WinDivert classify flow established IPv6 function.
 */
static void windivert_flow_established_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    WINDIVERT_DATA_FLOW flow_data;
    BOOL outbound, loopback;
    UINT64 flow_id;

    flow_data.ProcessId = (UINT32)meta_vals->processId;
    windivert_get_ipv6_addr(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS,
        flow_data.LocalAddr);
    windivert_get_ipv6_addr(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS,
        flow_data.RemoteAddr);
    flow_data.LocalPort = windivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT);
    flow_data.RemotePort = windivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT);
    flow_data.Protocol = windivert_get_val8(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL);
    
    outbound = (windivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_DIRECTION) ==
        FWP_DIRECTION_OUTBOUND);
    loopback = ((windivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_FLAGS) &
        FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);
    flow_id = meta_vals->flowHandle;
    
    windivert_flow_established_classify((context_t)filter->context,
        flow_id, &flow_data, /*ipv4=*/FALSE, outbound, loopback, result);
}

/*
 * WinDivert flow established classify function.
 */
static void windivert_flow_established_classify(context_t context,
    IN UINT64 flow_id, IN PWINDIVERT_DATA_FLOW flow_data, IN BOOL ipv4,
    IN BOOL outbound, IN BOOL loopback, OUT FWPS_CLASSIFY_OUT0 *result)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    UINT64 flags;
    UINT32 callout_id;
    UINT16 layer_id;
    BOOL match, ok;
    WDFOBJECT object;
    PWINDIVERT_FILTER filter;
    LONGLONG timestamp;
    flow_t flow;
    NTSTATUS status;

    // Basic checks:
    if (!(result->rights & FWPS_RIGHT_ACTION_WRITE))
    {
        return;
    }

    // Get the timestamp.
    timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
    
    result->actionType = FWP_ACTION_CONTINUE;

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != WINDIVERT_CONTEXT_STATE_OPEN)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        return;
    }
    filter = context->filter;
    flags = context->flags;
    callout_id = (ipv4? context->flow_v4_callout_id:
        context->flow_v6_callout_id);
    object = (WDFOBJECT)context->object;

    // Reference only released once the flow has been deleted.  This is to
    // prevent the callout being unregistered while flow deletions are still
    // pending, causing the operation to fail with STATUS_DEVICE_BUSY.
    WdfObjectReference(object);
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    match = windivert_filter(/*buffer=*/NULL, /*layer=*/WINDIVERT_LAYER_FLOW,
        (PVOID)flow_data, /*event=*/WINDIVERT_EVENT_FLOW_ESTABLISHED, ipv4,
        outbound, loopback, /*impostor=*/FALSE, filter);
    if (match)
    {
        ok = windivert_queue_work(context, /*packet=*/NULL, /*packet_len=*/0,
            /*buffers=*/NULL, /*layer=*/WINDIVERT_LAYER_FLOW, (PVOID)flow_data,
            /*event=*/WINDIVERT_EVENT_FLOW_ESTABLISHED, flags, /*priority=*/0,
            ipv4, outbound, loopback, /*impostor=*/FALSE, /*final=*/FALSE,
            match, timestamp);
        if (!ok)
        {
            WdfObjectDereference(object);
            return;
        }
    }

    // Associate a context with the flow.  This is so we can detect when
    // the flow is deleted.
    flow = windivert_malloc(sizeof(struct flow_s), FALSE);
    if (flow == NULL)
    {
        WdfObjectDereference(object);
        return;
    }
    layer_id = (ipv4? FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4:
                      FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6);
    flow->context = context;
    flow->flow_id = flow_id;
    flow->callout_id = callout_id;
    flow->layer_id = layer_id;
    flow->inserted = FALSE;
    flow->deleted = FALSE;
    flow->outbound = outbound;
    flow->loopback = loopback;
    flow->ipv6 = !ipv4;
    RtlCopyMemory(&flow->data, flow_data, sizeof(flow->data));

    status = FwpsFlowAssociateContext0(flow_id, layer_id, callout_id,
        (UINT64)flow);
    if (!NT_SUCCESS(status))
    {
        windivert_free(flow);
        WdfObjectDereference(object);
        return;
    }

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != WINDIVERT_CONTEXT_STATE_OPEN)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        windivert_free(flow);
        WdfObjectDereference(object);
        return;
    }
    if (!flow->deleted)
    {
        InsertTailList(&context->flow_set, &flow->entry);
        flow->inserted = TRUE;
    }
    else
    {
        // Flow was deleted before insertion; we are responsible for cleanup.
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        windivert_free(flow);
        WdfObjectDereference(object);
        return;
    }
    KeReleaseInStackQueuedSpinLock(&lock_handle);
}

/*
 * WinDivert flow delete notify function.
 */
static void windivert_flow_delete_notify(UINT16 layer_id, UINT32 callout_id,
    UINT64 flow_context)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    UINT64 flags;
    BOOL match, cleanup;
    WDFOBJECT object;
    context_t context;
    PWINDIVERT_FILTER filter;
    LONGLONG timestamp;
    flow_t flow;
 
    flow = (flow_t)flow_context;
    if (flow == NULL)
    {
        return;
    }

    timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
    context = flow->context;

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    object = (WDFOBJECT)context->object; // referenced in flow_established.
    if (flow->inserted && !flow->deleted)
    {
        RemoveEntryList(&flow->entry);
    }
    flow->deleted = TRUE;
    cleanup = flow->inserted;
    if (context->state != WINDIVERT_CONTEXT_STATE_OPEN)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        goto windivert_flow_delete_notify_exit;
    }
    filter = context->filter;
    flags = context->flags;
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    match = windivert_filter(/*buffer=*/NULL, /*layer=*/WINDIVERT_LAYER_FLOW,
        (PVOID)&flow->data, /*event=*/WINDIVERT_EVENT_FLOW_DELETED,
        !flow->ipv6, flow->outbound, flow->loopback, /*impostor=*/FALSE,
        filter);
    if (match)
    {
        (VOID)windivert_queue_work(context, /*packet=*/NULL, /*packet_len=*/0,
            /*buffers=*/NULL, /*layer=*/WINDIVERT_LAYER_FLOW,
            (PVOID)&flow->data, /*event=*/WINDIVERT_EVENT_FLOW_DELETED, flags,
            /*priority=*/0, !flow->ipv6, flow->outbound, flow->loopback,
            /*impostor=*/FALSE, /*final=*/FALSE, match, timestamp);
    }

windivert_flow_delete_notify_exit:

    if (cleanup)
    {
        windivert_free(flow);
        WdfObjectDereference(object);
    }
}

/*
 * WinDivert classify resource assignment IPv4 function.
 */
static void windivert_resource_assignment_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    WINDIVERT_DATA_SOCKET socket_data;
    BOOL loopback;

    socket_data.ProcessId = (UINT32)meta_vals->processId;
    windivert_get_ipv4_addr(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_ADDRESS,
        socket_data.LocalAddr);
    RtlZeroMemory(&socket_data.RemoteAddr, sizeof(socket_data.RemoteAddr));
    socket_data.LocalPort = windivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_PORT);
    socket_data.RemotePort = 0;
    socket_data.Protocol = windivert_get_val8(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_PROTOCOL);

    loopback = ((windivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_FLAGS) &
        FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    windivert_socket_classify((context_t)filter->context,
        &socket_data, /*event=*/WINDIVERT_EVENT_SOCKET_BIND, /*ipv4=*/TRUE,
        /*outbound=*/FALSE, loopback, result);
}

/*
 * WinDivert classify resource assignment IPv6 function.
 */
static void windivert_resource_assignment_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    WINDIVERT_DATA_SOCKET socket_data;
    BOOL loopback;

    socket_data.ProcessId = (UINT32)meta_vals->processId;
    windivert_get_ipv6_addr(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_IP_LOCAL_ADDRESS,
        socket_data.LocalAddr);
    RtlZeroMemory(&socket_data.RemoteAddr, sizeof(socket_data.RemoteAddr));
    socket_data.LocalPort = windivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_IP_LOCAL_PORT);
    socket_data.RemotePort = 0;
    socket_data.Protocol = windivert_get_val8(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_IP_PROTOCOL);

    loopback = ((windivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_FLAGS) &
        FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    windivert_socket_classify((context_t)filter->context,
        &socket_data, /*event=*/WINDIVERT_EVENT_SOCKET_BIND, /*ipv4=*/FALSE,
        /*outbound=*/FALSE, loopback, result);
}

/*
 * WinDivert classify auth connect IPv4 function.
 */
static void windivert_auth_connect_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    WINDIVERT_DATA_SOCKET socket_data;
    BOOL loopback;

    socket_data.ProcessId = (UINT32)meta_vals->processId;
    windivert_get_ipv4_addr(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS,
        socket_data.LocalAddr);
    windivert_get_ipv4_addr(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS,
        socket_data.RemoteAddr);
    socket_data.LocalPort = windivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT);
    socket_data.RemotePort = windivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT);
    socket_data.Protocol = windivert_get_val8(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL);

    loopback = ((windivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS) &
        FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    windivert_socket_classify((context_t)filter->context,
        &socket_data, /*event=*/WINDIVERT_EVENT_SOCKET_CONNECT, /*ipv4=*/TRUE,
        /*outbound=*/TRUE, loopback, result);
}

/*
 * WinDivert classify auth connect IPv6 function.
 */
static void windivert_auth_connect_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    WINDIVERT_DATA_SOCKET socket_data;
    BOOL loopback;

    socket_data.ProcessId = (UINT32)meta_vals->processId;
    windivert_get_ipv6_addr(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS,
        socket_data.LocalAddr);
    windivert_get_ipv6_addr(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS,
        socket_data.RemoteAddr);
    socket_data.LocalPort = windivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT);
    socket_data.RemotePort = windivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT);
    socket_data.Protocol = windivert_get_val8(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL);

    loopback = ((windivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS) &
        FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    windivert_socket_classify((context_t)filter->context,
        &socket_data, /*event=*/WINDIVERT_EVENT_SOCKET_CONNECT, /*ipv4=*/FALSE,
        /*outbound=*/TRUE, loopback, result);
}

/*
 * WinDivert classify auth listen IPv4 function.
 */
static void windivert_auth_listen_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    WINDIVERT_DATA_SOCKET socket_data;
    BOOL loopback;

    socket_data.ProcessId = (UINT32)meta_vals->processId;
    windivert_get_ipv4_addr(fixed_vals,
        FWPS_FIELD_ALE_AUTH_LISTEN_V4_IP_LOCAL_ADDRESS,
        socket_data.LocalAddr);
    RtlZeroMemory(&socket_data.RemoteAddr, sizeof(socket_data.RemoteAddr));
    socket_data.LocalPort = windivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_AUTH_LISTEN_V4_IP_LOCAL_PORT);
    socket_data.RemotePort = 0;
    socket_data.Protocol = IPPROTO_TCP;

    loopback = ((windivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_AUTH_LISTEN_V4_FLAGS) &
        FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    windivert_socket_classify((context_t)filter->context,
        &socket_data, /*event=*/WINDIVERT_EVENT_SOCKET_LISTEN, /*ipv4=*/TRUE,
        /*outbound=*/FALSE, loopback, result);
}

/*
 * WinDivert classify auth listen IPv6 function.
 */
static void windivert_auth_listen_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    WINDIVERT_DATA_SOCKET socket_data;
    BOOL loopback;

    socket_data.ProcessId = (UINT32)meta_vals->processId;
    windivert_get_ipv6_addr(fixed_vals,
        FWPS_FIELD_ALE_AUTH_LISTEN_V6_IP_LOCAL_ADDRESS,
        socket_data.LocalAddr);
    RtlZeroMemory(&socket_data.RemoteAddr, sizeof(socket_data.RemoteAddr));
    socket_data.LocalPort = windivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_AUTH_LISTEN_V6_IP_LOCAL_PORT);
    socket_data.RemotePort = 0;
    socket_data.Protocol = IPPROTO_TCP;

    loopback = ((windivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_AUTH_LISTEN_V6_FLAGS) &
        FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    windivert_socket_classify((context_t)filter->context,
        &socket_data, /*event=*/WINDIVERT_EVENT_SOCKET_LISTEN, /*ipv4=*/FALSE,
        /*outbound=*/FALSE, loopback, result);
}

/*
 * WinDivert classify auth recv accept IPv4 function.
 */
static void windivert_auth_recv_accept_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    WINDIVERT_DATA_SOCKET socket_data;
    BOOL loopback;

    socket_data.ProcessId = (UINT32)meta_vals->processId;
    windivert_get_ipv4_addr(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS,
        socket_data.LocalAddr);
    windivert_get_ipv4_addr(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS,
        socket_data.RemoteAddr);
    socket_data.LocalPort = windivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT);
    socket_data.RemotePort = windivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT);
    socket_data.Protocol = windivert_get_val8(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL);

    loopback = ((windivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_FLAGS) &
        FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    windivert_socket_classify((context_t)filter->context,
        &socket_data, /*event=*/WINDIVERT_EVENT_SOCKET_ACCEPT, /*ipv4=*/TRUE,
        /*outbound=*/FALSE, loopback, result);
}

/*
 * WinDivert classify auth recv accept IPv6 function.
 */
static void windivert_auth_recv_accept_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    WINDIVERT_DATA_SOCKET socket_data;
    BOOL loopback;

    socket_data.ProcessId = (UINT32)meta_vals->processId;
    windivert_get_ipv6_addr(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS,
        socket_data.LocalAddr);
    windivert_get_ipv6_addr(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS,
        socket_data.RemoteAddr);
    socket_data.LocalPort = windivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT);
    socket_data.RemotePort = windivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT);
    socket_data.Protocol = windivert_get_val8(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL);

    loopback = ((windivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_FLAGS) &
        FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    windivert_socket_classify((context_t)filter->context,
        &socket_data, /*event=*/WINDIVERT_EVENT_SOCKET_ACCEPT, /*ipv4=*/FALSE,
        /*outbound=*/FALSE, loopback, result);
}

/*
 * WinDivert socket classify function.
 */
static void windivert_socket_classify(context_t context,
    PWINDIVERT_DATA_SOCKET socket_data, WINDIVERT_EVENT event, BOOL ipv4,
    BOOL outbound, BOOL loopback, FWPS_CLASSIFY_OUT0 *result)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    UINT64 flags;
    BOOL match, ok;
    WDFOBJECT object;
    PWINDIVERT_FILTER filter;
    LONGLONG timestamp;
    NTSTATUS status;

    // Basic checks:
    if (!(result->rights & FWPS_RIGHT_ACTION_WRITE))
    {
        return;
    }

    // Get the timestamp.
    timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
    
    result->actionType = FWP_ACTION_CONTINUE;

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != WINDIVERT_CONTEXT_STATE_OPEN)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        return;
    }
    filter = context->filter;
    flags = context->flags;
    object = (WDFOBJECT)context->object;
    WdfObjectReference(object);
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    match = windivert_filter(/*buffer=*/NULL, /*layer=*/WINDIVERT_LAYER_SOCKET,
        (PVOID)socket_data, event, ipv4, outbound, loopback,
        /*impostor=*/FALSE, filter);
    if (match)
    {
        ok = windivert_queue_work(context, /*packet=*/NULL, /*packet_len=*/0,
            /*buffers=*/NULL, /*layer=*/WINDIVERT_LAYER_SOCKET,
            (PVOID)socket_data, event, flags, /*priority=*/0, ipv4, outbound,
            loopback, /*impostor=*/FALSE, /*final=*/FALSE, match, timestamp);
        if (!ok)
        {
            WdfObjectDereference(object);
            return;
        }
    }

    WdfObjectDereference(object);
    if ((flags & WINDIVERT_FLAG_SNIFF) == 0)
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
static BOOL windivert_queue_work(context_t context, PVOID packet,
    ULONG packet_len, PNET_BUFFER_LIST buffers, WINDIVERT_LAYER layer,
    PVOID layer_data, WINDIVERT_EVENT event, UINT64 flags, UINT32 priority,
    BOOL ipv4, BOOL outbound, BOOL loopback, BOOL impostor, BOOL final,
    BOOL match, LONGLONG timestamp)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    PNET_BUFFER buffer;
    packet_t work;
    PVOID packet_data;
    UINT8 *data;
    PLIST_ENTRY old_entry;
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO checksums;
    PWINDIVERT_DATA_NETWORK network_data;
    PWINDIVERT_DATA_FLOW flow_data;
    PWINDIVERT_DATA_SOCKET socket_data;
    PWINDIVERT_DATA_REFLECT reflect_data;
    BOOL pseudo_ip_checksum, pseudo_tcp_checksum, pseudo_udp_checksum;

    if (!match && (flags & WINDIVERT_FLAG_SNIFF) != 0)
    {
        return TRUE;
    }
    if (match && (flags & WINDIVERT_FLAG_DROP) != 0)
    {
        return TRUE;
    }

    // Copy the packet & layer data.
    switch (layer)
    {
        case WINDIVERT_LAYER_NETWORK:
        case WINDIVERT_LAYER_NETWORK_FORWARD:
            buffer = (PNET_BUFFER)packet;
            network_data = (PWINDIVERT_DATA_NETWORK)layer_data;
            if (packet_len > UINT16_MAX)
            {
                // Cannot handle oversized packet
                return TRUE;
            }
            work = (packet_t)windivert_malloc(
                WINDIVERT_PACKET_SIZE(WINDIVERT_DATA_NETWORK, packet_len),
                FALSE);
            if (work == NULL)
            {
                return TRUE;
            }
            work->packet_len = (UINT32)packet_len;
            data = WINDIVERT_LAYER_DATA_PTR(work);
            RtlCopyMemory(data, network_data, sizeof(WINDIVERT_DATA_NETWORK));
            data = WINDIVERT_PACKET_DATA_PTR(WINDIVERT_DATA_NETWORK, work);
            packet_data = NdisGetDataBuffer(buffer, packet_len, NULL, 1, 0);
            if (packet_data == NULL)
            {
                NdisGetDataBuffer(buffer, packet_len, data, 1, 0);
            }
            else
            {
                RtlCopyMemory(data, packet_data, packet_len);
            }
            checksums.Value = NET_BUFFER_LIST_INFO(buffers,
                TcpIpChecksumNetBufferListInfo);
            if (outbound)
            {
                pseudo_ip_checksum = (checksums.Transmit.IpHeaderChecksum != 0);
                pseudo_tcp_checksum = (checksums.Transmit.TcpChecksum != 0);
                pseudo_udp_checksum = (checksums.Transmit.UdpChecksum != 0);
            }
            else
            {
                pseudo_ip_checksum =
                    (checksums.Receive.IpChecksumSucceeded != 0);
                pseudo_tcp_checksum =
                    (checksums.Receive.TcpChecksumSucceeded != 0);
                pseudo_udp_checksum =
                    (checksums.Receive.UdpChecksumSucceeded != 0);
            }
            break;

        case WINDIVERT_LAYER_FLOW:
            flow_data = (PWINDIVERT_DATA_FLOW)layer_data;
            work = (packet_t)windivert_malloc(
                WINDIVERT_PACKET_SIZE(WINDIVERT_DATA_FLOW, 0), FALSE);
            if (work == NULL)
            {
                return TRUE;
            }
            work->packet_len = 0;
            data = WINDIVERT_LAYER_DATA_PTR(work);
            RtlCopyMemory(data, flow_data, sizeof(WINDIVERT_DATA_FLOW));
            pseudo_ip_checksum = pseudo_tcp_checksum = pseudo_udp_checksum =
                FALSE;
            break;
 
        case WINDIVERT_LAYER_SOCKET:
            socket_data = (PWINDIVERT_DATA_SOCKET)layer_data;
            work = (packet_t)windivert_malloc(
                WINDIVERT_PACKET_SIZE(WINDIVERT_DATA_SOCKET, 0), FALSE);
            if (work == NULL)
            {
                return TRUE;
            }
            work->packet_len = 0;
            data = WINDIVERT_LAYER_DATA_PTR(work);
            RtlCopyMemory(data, socket_data, sizeof(WINDIVERT_DATA_SOCKET));
            pseudo_ip_checksum = pseudo_tcp_checksum = pseudo_udp_checksum =
                FALSE;
            break;

        case WINDIVERT_LAYER_REFLECT:
            reflect_data = (PWINDIVERT_DATA_REFLECT)layer_data;
            work = (packet_t)windivert_malloc(
                WINDIVERT_PACKET_SIZE(WINDIVERT_DATA_REFLECT, packet_len),
                FALSE);
            if (work == NULL)
            {
                return TRUE;
            }
            work->packet_len = packet_len;
            data = WINDIVERT_LAYER_DATA_PTR(work);
            RtlCopyMemory(data, reflect_data, sizeof(WINDIVERT_DATA_REFLECT));
            data = WINDIVERT_PACKET_DATA_PTR(WINDIVERT_DATA_REFLECT, work);
            RtlCopyMemory(data, packet, packet_len);
            pseudo_ip_checksum  = TRUE;
            pseudo_tcp_checksum = pseudo_udp_checksum = FALSE;
            break;

        default:
            return TRUE;
    }

    work->layer               = layer;
    work->event               = event;
    work->outbound            = (outbound? 1: 0);
    work->loopback            = (loopback? 1: 0);
    work->impostor            = (impostor? 1: 0);
    work->ipv6                = (!ipv4? 1: 0);
    work->pseudo_ip_checksum  = (pseudo_ip_checksum? 1: 0);
    work->pseudo_tcp_checksum = (pseudo_tcp_checksum? 1: 0);
    work->pseudo_udp_checksum = (pseudo_udp_checksum? 1: 0);
    work->final               = (final? 1: 0);
    work->match               = match;
    work->priority            = priority;
    work->timestamp           = timestamp;

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
            windivert_reinject_packet(packet);
            return;
        }
        if (packet->packet_len > context->packet_queue_maxsize)
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

        if (context->packet_queue_size + packet->packet_len >
                context->packet_queue_maxsize ||
            context->packet_queue_length + 1 > context->packet_queue_maxlength)
        {
            // The queue is full; drop a packet & try again:
            old_entry = RemoveHeadList(&context->packet_queue);
            old_packet = CONTAINING_RECORD(old_entry, struct packet_s, entry);
            context->packet_queue_length--;
            context->packet_queue_size -= old_packet->packet_len;
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
            context->packet_queue_size += packet->packet_len;
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
    UINT8 *packet_data;
    UINT32 packet_len;
    PWINDIVERT_DATA_NETWORK network_data;
    PMDL mdl;
    PNET_BUFFER_LIST buffers;
    HANDLE handle;
    UINT32 priority;
    NTSTATUS status;

    if (packet->layer != WINDIVERT_LAYER_NETWORK &&
        packet->layer != WINDIVERT_LAYER_NETWORK_FORWARD)
    {
        windivert_free_packet(packet);
        return;
    }

    network_data = (PWINDIVERT_DATA_NETWORK)WINDIVERT_LAYER_DATA_PTR(packet);
    packet_data = WINDIVERT_PACKET_DATA_PTR(WINDIVERT_DATA_NETWORK, packet);
    packet_len = packet->packet_len;
    mdl = IoAllocateMdl(packet_data, packet_len, FALSE, FALSE, NULL);
    if (mdl == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DEBUG_ERROR("failed to allocate MDL for injected packet", status);
        windivert_free_packet(packet);
        return;
    }
    MmBuildMdlForNonPagedPool(mdl);
    status = FwpsAllocateNetBufferAndNetBufferList0(nbl_pool_handle, 0, 0,
        mdl, 0, packet_len, &buffers);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create NET_BUFFER_LIST for injected packet",
            status);
        IoFreeMdl(mdl);
        windivert_free_packet(packet);
        return;
    }
    priority = packet->priority;
    handle = (packet->ipv6? injectv6_handle: inject_handle);
    if (packet->layer == WINDIVERT_LAYER_NETWORK_FORWARD)
    {
        status = FwpsInjectForwardAsync0(handle, (HANDLE)priority, 0,
            (packet->ipv6? AF_INET6: AF_INET), UNSPECIFIED_COMPARTMENT_ID,
            network_data->IfIdx, buffers, windivert_reinject_complete, 
            (HANDLE)packet);
    }
    else if (packet->outbound)
    {
        status = FwpsInjectNetworkSendAsync0(handle, (HANDLE)priority, 0,
            UNSPECIFIED_COMPARTMENT_ID, buffers, windivert_reinject_complete,
            (HANDLE)packet);
    }
    else
    {
        status = FwpsInjectNetworkReceiveAsync0(handle, (HANDLE)priority, 0,
            UNSPECIFIED_COMPARTMENT_ID, network_data->IfIdx,
            network_data->SubIfIdx, buffers, windivert_reinject_complete,
            (HANDLE)packet);
    }

    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to re-inject (packet=%p)", status, packet);
        FwpsFreeNetBufferList0(buffers);
        IoFreeMdl(mdl);
        windivert_free_packet(packet);
    }
}

/*
 * Free a packet.
 */
static void windivert_free_packet(packet_t packet)
{
    windivert_free(packet);
}

/*
 * Decrement the TTL of a packet.
 */
static BOOL windivert_decrement_ttl(PVOID data, BOOL ipv4)
{
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_IPV6HDR ipv6_header;

    if (ipv4)
    {
        ip_header = (PWINDIVERT_IPHDR)data;
        if (ip_header->TTL <= 1)
        {
            return FALSE;
        }
        ip_header->TTL--;

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
 * Parse packet headers.
 */
static BOOL windivert_parse_headers(PNET_BUFFER buffer, BOOL ipv4,
    PWINDIVERT_IPHDR *ip_header_ptr, PWINDIVERT_IPV6HDR *ipv6_header_ptr,
    PWINDIVERT_ICMPHDR *icmp_header_ptr,
    PWINDIVERT_ICMPV6HDR *icmpv6_header_ptr,
    PWINDIVERT_TCPHDR *tcp_header_ptr, PWINDIVERT_UDPHDR *udp_header_ptr,
    UINT8 *proto_ptr, UINT *payload_len_ptr)
{
    UINT tot_len, ip_header_len;
    PWINDIVERT_IPHDR ip_header = NULL;
    PWINDIVERT_IPV6HDR ipv6_header = NULL;
    PWINDIVERT_ICMPHDR icmp_header = NULL;
    PWINDIVERT_ICMPV6HDR icmpv6_header = NULL;
    PWINDIVERT_TCPHDR tcp_header = NULL;
    PWINDIVERT_UDPHDR udp_header = NULL;
    UINT16 ip, ttl;
    UINT8 proto = 0;
    UINT payload_len = 0;
    NTSTATUS status;

    // Parse the headers:
    if (buffer == NULL)
    {
        DEBUG("FILTER: REJECT (packet is NULL)");
        return FALSE;
    }
    tot_len = NET_BUFFER_DATA_LENGTH(buffer);
    if (tot_len < sizeof(WINDIVERT_IPHDR))
    {
        DEBUG("FILTER: REJECT (packet length too small)");
        return FALSE;
    }

    // Get the IP header.
    if (ipv4)
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
            UINT ext_header_len;
            BOOL isexthdr = TRUE;

            ext_header = (UINT8 *)NdisGetDataBuffer(buffer, 2, NULL, 1, 0);
            if (ext_header == NULL)
            {
                break;
            }

            ext_header_len = (UINT)ext_header[1];
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
            payload_len = tot_len - ip_header_len -
                tcp_header->HdrLength*sizeof(UINT32);
            break;
        case IPPROTO_UDP:
            udp_header = (PWINDIVERT_UDPHDR)NdisGetDataBuffer(buffer,
                sizeof(WINDIVERT_UDPHDR), NULL, 1, 0);
            payload_len = tot_len - ip_header_len - sizeof(WINDIVERT_UDPHDR);
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

    *ip_header_ptr     = ip_header;
    *ipv6_header_ptr   = ipv6_header;
    *icmp_header_ptr   = icmp_header;
    *icmpv6_header_ptr = icmpv6_header;
    *tcp_header_ptr    = tcp_header;
    *udp_header_ptr    = udp_header;
    *proto_ptr         = proto;
    *payload_len_ptr   = payload_len;

    return TRUE;
}

/*
 * Checks if the given network packet is of interest.
 */
static BOOL windivert_filter(PNET_BUFFER buffer, WINDIVERT_LAYER layer,
    PVOID layer_data, WINDIVERT_EVENT event, BOOL ipv4, BOOL outbound,
    BOOL loopback, BOOL impostor, PWINDIVERT_FILTER filter)
{
    PWINDIVERT_IPHDR ip_header = NULL;
    PWINDIVERT_IPV6HDR ipv6_header = NULL;
    PWINDIVERT_ICMPHDR icmp_header = NULL;
    PWINDIVERT_ICMPV6HDR icmpv6_header = NULL;
    PWINDIVERT_TCPHDR tcp_header = NULL;
    PWINDIVERT_UDPHDR udp_header = NULL;
    UINT8 protocol = 0;
    UINT payload_len = 0;
    UINT16 ip, ttl;
    PWINDIVERT_DATA_NETWORK network_data = NULL;
    PWINDIVERT_DATA_FLOW flow_data = NULL;
    PWINDIVERT_DATA_SOCKET socket_data = NULL;
    PWINDIVERT_DATA_REFLECT reflect_data = NULL;
    NTSTATUS status;

    switch (layer)
    {
        case WINDIVERT_LAYER_NETWORK:
        case WINDIVERT_LAYER_NETWORK_FORWARD:
            if (!windivert_parse_headers(buffer, ipv4, &ip_header, &ipv6_header,
                    &icmp_header, &icmpv6_header, &tcp_header, &udp_header,
                    &protocol, &payload_len))
            {
                return FALSE;
            }
            network_data = (PWINDIVERT_DATA_NETWORK)layer_data;
            break;
        case WINDIVERT_LAYER_FLOW:
            flow_data = (PWINDIVERT_DATA_FLOW)layer_data;
            break;
        case WINDIVERT_LAYER_SOCKET:
            socket_data = (PWINDIVERT_DATA_SOCKET)layer_data;
            break;
        case WINDIVERT_LAYER_REFLECT:
            reflect_data = (PWINDIVERT_DATA_REFLECT)layer_data;
            break;
        default:
            DEBUG("FILTER: REJECT (invalid parameter)");
            return FALSE;
    }

    // Execute the filter:
    ip = 0;
    ttl = WINDIVERT_FILTER_MAXLEN+1;       // Additional safety
    while (ttl-- != 0)
    {
        BOOL result = FALSE;
        BOOL error  = FALSE;
        int cmp;
        UINT32 field[4];
        field[1] = 0;
        field[2] = 0;
        field[3] = 0;

        switch (filter[ip].field)
        {
            case WINDIVERT_FILTER_FIELD_ZERO:
            case WINDIVERT_FILTER_FIELD_EVENT:
                result = TRUE;
                break;
            case WINDIVERT_FILTER_FIELD_INBOUND:
            case WINDIVERT_FILTER_FIELD_OUTBOUND:
                result = (layer != WINDIVERT_LAYER_NETWORK_FORWARD &&
                          layer != WINDIVERT_LAYER_REFLECT);
                break;
            case WINDIVERT_FILTER_FIELD_LOOPBACK:
            case WINDIVERT_FILTER_FIELD_IMPOSTOR:
            case WINDIVERT_FILTER_FIELD_IP:
            case WINDIVERT_FILTER_FIELD_IPV6:
            case WINDIVERT_FILTER_FIELD_ICMP:
            case WINDIVERT_FILTER_FIELD_ICMPV6:
            case WINDIVERT_FILTER_FIELD_TCP:
            case WINDIVERT_FILTER_FIELD_UDP:
                result = (layer != WINDIVERT_LAYER_REFLECT);
                break;
            case WINDIVERT_FILTER_FIELD_IFIDX:
            case WINDIVERT_FILTER_FIELD_SUBIFIDX:
                result = (layer == WINDIVERT_LAYER_NETWORK ||
                          layer == WINDIVERT_LAYER_NETWORK_FORWARD);
                break;
            case WINDIVERT_FILTER_FIELD_LOCALADDR:
            case WINDIVERT_FILTER_FIELD_REMOTEADDR:
            case WINDIVERT_FILTER_FIELD_LOCALPORT:
            case WINDIVERT_FILTER_FIELD_REMOTEPORT:
            case WINDIVERT_FILTER_FIELD_PROTOCOL:
                result = (layer == WINDIVERT_LAYER_NETWORK ||
                          layer == WINDIVERT_LAYER_FLOW ||
                          layer == WINDIVERT_LAYER_SOCKET);
                break;
            case WINDIVERT_FILTER_FIELD_PROCESSID:
                result = (layer == WINDIVERT_LAYER_FLOW ||
                          layer == WINDIVERT_LAYER_SOCKET ||
                          layer == WINDIVERT_LAYER_REFLECT);
                break;
            case WINDIVERT_FILTER_FIELD_LAYER:
                result = (layer == WINDIVERT_LAYER_REFLECT);
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
                result = (layer == WINDIVERT_LAYER_NETWORK ||
                          layer == WINDIVERT_LAYER_NETWORK_FORWARD);
                result = result && (ip_header != NULL);
                break;
            case WINDIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS:
            case WINDIVERT_FILTER_FIELD_IPV6_FLOWLABEL:
            case WINDIVERT_FILTER_FIELD_IPV6_LENGTH:
            case WINDIVERT_FILTER_FIELD_IPV6_NEXTHDR:
            case WINDIVERT_FILTER_FIELD_IPV6_HOPLIMIT:
            case WINDIVERT_FILTER_FIELD_IPV6_SRCADDR:
            case WINDIVERT_FILTER_FIELD_IPV6_DSTADDR:
                result = (layer == WINDIVERT_LAYER_NETWORK ||
                          layer == WINDIVERT_LAYER_NETWORK_FORWARD);
                result = result && (ipv6_header != NULL);
                break;
            case WINDIVERT_FILTER_FIELD_ICMP_TYPE:
            case WINDIVERT_FILTER_FIELD_ICMP_CODE:
            case WINDIVERT_FILTER_FIELD_ICMP_CHECKSUM:
            case WINDIVERT_FILTER_FIELD_ICMP_BODY:
                result = (layer == WINDIVERT_LAYER_NETWORK ||
                          layer == WINDIVERT_LAYER_NETWORK_FORWARD);
                result = result && (icmp_header != NULL);
                break;
            case WINDIVERT_FILTER_FIELD_ICMPV6_TYPE:
            case WINDIVERT_FILTER_FIELD_ICMPV6_CODE:
            case WINDIVERT_FILTER_FIELD_ICMPV6_CHECKSUM:
            case WINDIVERT_FILTER_FIELD_ICMPV6_BODY:
                result = (layer == WINDIVERT_LAYER_NETWORK ||
                          layer == WINDIVERT_LAYER_NETWORK_FORWARD);
                result = result && (icmpv6_header != NULL);
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
                result = (layer == WINDIVERT_LAYER_NETWORK ||
                          layer == WINDIVERT_LAYER_NETWORK_FORWARD);
                result = result && (tcp_header != NULL);
                break;
            case WINDIVERT_FILTER_FIELD_UDP_SRCPORT:
            case WINDIVERT_FILTER_FIELD_UDP_DSTPORT:
            case WINDIVERT_FILTER_FIELD_UDP_LENGTH:
            case WINDIVERT_FILTER_FIELD_UDP_CHECKSUM:
            case WINDIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH:
                result = (layer == WINDIVERT_LAYER_NETWORK ||
                          layer == WINDIVERT_LAYER_NETWORK_FORWARD);
                result = result && (udp_header != NULL);
                break;
            default:
                result = FALSE;
                error  = TRUE;
                break;
        }
        if (result)
        {
            switch (filter[ip].field)
            {
                case WINDIVERT_FILTER_FIELD_ZERO:
                    field[0] = 0;
                    break;
                case WINDIVERT_FILTER_FIELD_EVENT:
                    field[0] = (UINT32)event;
                    break;
                case WINDIVERT_FILTER_FIELD_INBOUND:
                    field[0] = (UINT32)!outbound;
                    break;
                case WINDIVERT_FILTER_FIELD_OUTBOUND:
                    field[0] = (UINT32)outbound;
                    break;
                case WINDIVERT_FILTER_FIELD_IFIDX:
                    field[0] = network_data->IfIdx;
                    break;
                case WINDIVERT_FILTER_FIELD_SUBIFIDX:
                    field[0] = network_data->SubIfIdx;
                    break;
                case WINDIVERT_FILTER_FIELD_LOOPBACK:
                    field[0] = (UINT32)loopback;
                    break;
                case WINDIVERT_FILTER_FIELD_IMPOSTOR:
                    field[0] = (UINT32)impostor;
                    break;
                case WINDIVERT_FILTER_FIELD_IP:
                    field[0] = (UINT32)ipv4;
                    break;
                case WINDIVERT_FILTER_FIELD_IPV6:
                    field[0] = (UINT32)!ipv4;
                    break;
                case WINDIVERT_FILTER_FIELD_ICMP:
                    switch (layer)
                    {
                        case WINDIVERT_LAYER_NETWORK:
                        case WINDIVERT_LAYER_NETWORK_FORWARD:
                            field[0] = (UINT32)(icmp_header != NULL);
                            break;
                        case WINDIVERT_LAYER_SOCKET:
                            field[0] = (UINT32)(ipv4 &&
                                socket_data->Protocol == IPPROTO_ICMP);
                            break;
                        case WINDIVERT_LAYER_FLOW:
                            field[0] = (UINT32)(ipv4 &&
                                flow_data->Protocol == IPPROTO_ICMP);
                            break;
                        default:
                            error = TRUE;
                            result = FALSE;
                            break;
                    }
                    break;
                case WINDIVERT_FILTER_FIELD_ICMPV6:
                    switch (layer)
                    {
                        case WINDIVERT_LAYER_NETWORK:
                        case WINDIVERT_LAYER_NETWORK_FORWARD:
                            field[0] = (UINT32)(icmpv6_header != NULL);
                            break;
                        case WINDIVERT_LAYER_SOCKET:
                            field[0] = (UINT32)(!ipv4 &&
                                socket_data->Protocol == IPPROTO_ICMPV6);
                            break;
                        case WINDIVERT_LAYER_FLOW:
                            field[0] = (UINT32)(!ipv4 &&
                                flow_data->Protocol == IPPROTO_ICMPV6);
                            break;
                        default:
                            error = TRUE;
                            result = FALSE;
                            break;
                    }
                    break;
                case WINDIVERT_FILTER_FIELD_TCP:
                    switch (layer)
                    {
                        case WINDIVERT_LAYER_NETWORK:
                        case WINDIVERT_LAYER_NETWORK_FORWARD:
                            field[0] = (UINT32)(tcp_header != NULL);
                            break;
                        case WINDIVERT_LAYER_SOCKET:
                            field[0] =
                                (UINT32)(socket_data->Protocol == IPPROTO_TCP);
                            break;
                        case WINDIVERT_LAYER_FLOW:
                            field[0] =
                                (UINT32)(flow_data->Protocol == IPPROTO_TCP);
                            break;
                        default:
                            error = TRUE;
                            result = FALSE;
                            break;
                    }
                    break;
                case WINDIVERT_FILTER_FIELD_UDP:
                    switch (layer)
                    {
                        case WINDIVERT_LAYER_NETWORK:
                        case WINDIVERT_LAYER_NETWORK_FORWARD:
                            field[0] = (UINT32)(udp_header != NULL);
                            break;
                        case WINDIVERT_LAYER_SOCKET:
                            field[0] =
                                (UINT32)(socket_data->Protocol == IPPROTO_UDP);
                            break;
                        case WINDIVERT_LAYER_FLOW:
                            field[0] =
                                (UINT32)(flow_data->Protocol == IPPROTO_UDP);
                            break;
                        default:
                            error = TRUE;
                            result = FALSE;
                            break;
                    }
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
                    field[1] = 0x0000FFFF;
                    field[0] = (UINT32)RtlUlongByteSwap(ip_header->SrcAddr);
                    break;
                case WINDIVERT_FILTER_FIELD_IP_DSTADDR:
                    field[1] = 0x0000FFFF;
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
                    field[0] = (UINT32)payload_len;
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
                    field[0] = (UINT32)payload_len;
                    break;
                case WINDIVERT_FILTER_FIELD_LOCALADDR:
                    switch (layer)
                    {
                        case WINDIVERT_LAYER_NETWORK:
                            if (ipv4)
                            {
                                field[1] = 0x0000FFFF;
                                field[0] = (UINT32)RtlUlongByteSwap(
                                    (outbound? ip_header->SrcAddr:
                                               ip_header->DstAddr));
                            }
                            else if (outbound)
                            {
                                field[3] = (UINT32)RtlUlongByteSwap(
                                    ipv6_header->SrcAddr[0]);
                                field[2] = (UINT32)RtlUlongByteSwap(
                                    ipv6_header->SrcAddr[1]);
                                field[1] = (UINT32)RtlUlongByteSwap(
                                    ipv6_header->SrcAddr[2]);
                                field[0] = (UINT32)RtlUlongByteSwap(
                                    ipv6_header->SrcAddr[3]);
                            }
                            else
                            {
                                field[3] = (UINT32)RtlUlongByteSwap(
                                    ipv6_header->DstAddr[0]);
                                field[2] = (UINT32)RtlUlongByteSwap(
                                    ipv6_header->DstAddr[1]);
                                field[1] = (UINT32)RtlUlongByteSwap(
                                    ipv6_header->DstAddr[2]);
                                field[0] = (UINT32)RtlUlongByteSwap(
                                    ipv6_header->DstAddr[3]);
                            }
                            break;
                        case WINDIVERT_LAYER_FLOW:
                            field[0] = flow_data->LocalAddr[0];
                            field[1] = flow_data->LocalAddr[1];
                            field[2] = flow_data->LocalAddr[2];
                            field[3] = flow_data->LocalAddr[3];
                            break;
                        case WINDIVERT_LAYER_SOCKET:
                            field[0] = socket_data->LocalAddr[0];
                            field[1] = socket_data->LocalAddr[1];
                            field[2] = socket_data->LocalAddr[2];
                            field[3] = socket_data->LocalAddr[3];
                            break;
                        default:
                            error  = TRUE;
                            result = FALSE;
                            break;
                    }
                    break;
                case WINDIVERT_FILTER_FIELD_REMOTEADDR:
                    switch (layer)
                    {
                        case WINDIVERT_LAYER_NETWORK:
                            if (ipv4)
                            {
                                field[1] = 0x0000FFFF;
                                field[0] = (UINT32)RtlUlongByteSwap(
                                    (!outbound? ip_header->SrcAddr:
                                                ip_header->DstAddr));
                            }
                            else if (!outbound)
                            {
                                field[3] = (UINT32)RtlUlongByteSwap(
                                    ipv6_header->SrcAddr[0]);
                                field[2] = (UINT32)RtlUlongByteSwap(
                                    ipv6_header->SrcAddr[1]);
                                field[1] = (UINT32)RtlUlongByteSwap(
                                    ipv6_header->SrcAddr[2]);
                                field[0] = (UINT32)RtlUlongByteSwap(
                                    ipv6_header->SrcAddr[3]);
                            }
                            else
                            {
                                field[3] = (UINT32)RtlUlongByteSwap(
                                    ipv6_header->DstAddr[0]);
                                field[2] = (UINT32)RtlUlongByteSwap(
                                    ipv6_header->DstAddr[1]);
                                field[1] = (UINT32)RtlUlongByteSwap(
                                    ipv6_header->DstAddr[2]);
                                field[0] = (UINT32)RtlUlongByteSwap(
                                    ipv6_header->DstAddr[3]);
                            }
                            break;
                        case WINDIVERT_LAYER_FLOW:
                            field[0] = flow_data->RemoteAddr[0];
                            field[1] = flow_data->RemoteAddr[1];
                            field[2] = flow_data->RemoteAddr[2];
                            field[3] = flow_data->RemoteAddr[3];
                            break;
                        case WINDIVERT_LAYER_SOCKET:
                            field[0] = socket_data->RemoteAddr[0];
                            field[1] = socket_data->RemoteAddr[1];
                            field[2] = socket_data->RemoteAddr[2];
                            field[3] = socket_data->RemoteAddr[3];
                            break;
                        default:
                            error  = TRUE;
                            result = FALSE;
                            break;
                    }
                    break;
                case WINDIVERT_FILTER_FIELD_LOCALPORT:
                    switch (layer)
                    {
                        case WINDIVERT_LAYER_NETWORK:
                            if (tcp_header != NULL)
                            {
                                field[0] = (UINT32)RtlUshortByteSwap(
                                    (outbound? tcp_header->SrcPort:
                                               tcp_header->DstPort));
                            }
                            else if (udp_header != NULL)
                            {
                                field[0] = (UINT32)RtlUshortByteSwap(
                                    (outbound? udp_header->SrcPort:
                                               udp_header->DstPort));
                            }
                            else
                            {
                                field[0] = 0;
                            }
                            break;
                        case WINDIVERT_LAYER_FLOW:
                            field[0] = (UINT32)flow_data->LocalPort;
                            break;
                        case WINDIVERT_LAYER_SOCKET:
                            field[0] = (UINT32)socket_data->LocalPort;
                            break;
                        default:
                            error  = TRUE;
                            result = FALSE;
                            break;
                    }
                    break;
                case WINDIVERT_FILTER_FIELD_REMOTEPORT:
                    switch (layer)
                    {
                        case WINDIVERT_LAYER_NETWORK:
                            if (tcp_header != NULL)
                            {
                                field[0] = (UINT32)RtlUshortByteSwap(
                                    (!outbound? tcp_header->SrcPort:
                                                tcp_header->DstPort));
                            }
                            else if (udp_header != NULL)
                            {
                                field[0] = (UINT32)RtlUshortByteSwap(
                                    (!outbound? udp_header->SrcPort:
                                                udp_header->DstPort));
                            }
                            else
                            {
                                field[0] = 0;
                            }
                            break;
                        case WINDIVERT_LAYER_FLOW:
                            field[0] = (UINT32)flow_data->RemotePort;
                            break;
                        case WINDIVERT_LAYER_SOCKET:
                            field[0] = (UINT32)socket_data->RemotePort;
                            break;
                        default:
                            error  = TRUE;
                            result = FALSE;
                            break;
                    }
                    break;
                case WINDIVERT_FILTER_FIELD_PROTOCOL:
                    switch (layer)
                    {
                        case WINDIVERT_LAYER_NETWORK:
                            field[0] = (UINT32)protocol;
                            break;
                        case WINDIVERT_LAYER_FLOW:
                            field[0] = (UINT32)flow_data->Protocol;
                            break;
                        case WINDIVERT_LAYER_SOCKET:
                            field[0] = (UINT32)socket_data->Protocol;
                            break;
                        default:
                            error  = TRUE;
                            result = FALSE;
                            break;
                    }
                    break;
                case WINDIVERT_FILTER_FIELD_PROCESSID:
                    switch (layer)
                    {
                        case WINDIVERT_LAYER_FLOW:
                            field[0] = flow_data->ProcessId;
                            break;
                        case WINDIVERT_LAYER_SOCKET:
                            field[0] = socket_data->ProcessId;
                            break;
                        case WINDIVERT_LAYER_REFLECT:
                            field[0] = reflect_data->ProcessId;
                            break;
                        default:
                            error  = TRUE;
                            result = FALSE;
                    }
                    break;
                case WINDIVERT_FILTER_FIELD_LAYER:
                    field[0] = reflect_data->Layer;
                    break;
                default:
                    error  = TRUE;
                    result = FALSE;
                    break;
            }
        }
        if (result)
        {
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
                    error  = TRUE;
                    result = FALSE;
                    break;
            }
        }
        if (error)
        {
            DEBUG("FILTER: REJECT (bad filter)");
            return FALSE;
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
 * Compile a WinDivert filter from an IOCTL.
 */
static PWINDIVERT_FILTER windivert_filter_compile(
    PWINDIVERT_FILTER ioctl_filter, size_t ioctl_filter_len,
    WINDIVERT_LAYER layer)
{
    PWINDIVERT_FILTER filter = NULL;
    WINDIVERT_EVENT event;
    UINT16 i;
    size_t length;

    if (ioctl_filter_len % sizeof(WINDIVERT_FILTER) != 0)
    {
        goto windivert_filter_compile_error;
    }
    length = ioctl_filter_len / sizeof(WINDIVERT_FILTER);
    if (length >= WINDIVERT_FILTER_MAXLEN || length == 0)
    {
        goto windivert_filter_compile_error;
    }

    filter = (PWINDIVERT_FILTER)windivert_malloc(
        length * sizeof(WINDIVERT_FILTER), FALSE);
    if (filter == NULL)
    {
        goto windivert_filter_compile_error;
    }
 
    for (i = 0; i < length; i++)
    {
        if (ioctl_filter[i].field > WINDIVERT_FILTER_FIELD_MAX ||
            ioctl_filter[i].test > WINDIVERT_FILTER_TEST_MAX)
        {
            goto windivert_filter_compile_error;
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
                    goto windivert_filter_compile_error;
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
                    goto windivert_filter_compile_error;
                }
                break;
        }

        // Enforce ranges:
        if (ioctl_filter[i].field != WINDIVERT_FILTER_FIELD_IPV6_SRCADDR &&
            ioctl_filter[i].field != WINDIVERT_FILTER_FIELD_IPV6_DSTADDR &&
            ioctl_filter[i].field != WINDIVERT_FILTER_FIELD_LOCALADDR &&
            ioctl_filter[i].field != WINDIVERT_FILTER_FIELD_REMOTEADDR)
        {
            if (ioctl_filter[i].arg[2] != 0 ||
                ioctl_filter[i].arg[3] != 0)
            {
                goto windivert_filter_compile_error;
            }
            if ((ioctl_filter[i].field == WINDIVERT_FILTER_FIELD_IP_SRCADDR ||
                 ioctl_filter[i].field == WINDIVERT_FILTER_FIELD_IP_DSTADDR))
            {
                if (ioctl_filter[i].arg[1] != 0x0000FFFF)
                {
                    goto windivert_filter_compile_error;
                }
            }
            else if (ioctl_filter[i].arg[1] != 0)
            {
                goto windivert_filter_compile_error;
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
                    goto windivert_filter_compile_error;
                }
                break;
            case WINDIVERT_FILTER_FIELD_LAYER:
                if (ioctl_filter[i].arg[0] > WINDIVERT_LAYER_MAX)
                {
                    goto windivert_filter_compile_error;
                }
                break;
            case WINDIVERT_FILTER_FIELD_EVENT:
                event = (WINDIVERT_EVENT)ioctl_filter[i].arg[0];
                switch (layer)
                {
                    case WINDIVERT_LAYER_NETWORK:
                    case WINDIVERT_LAYER_NETWORK_FORWARD:
                        if (event != WINDIVERT_EVENT_NETWORK_PACKET)
                        {
                            goto windivert_filter_compile_error;
                        }
                        break;
                    case WINDIVERT_LAYER_FLOW:
                        if (event != WINDIVERT_EVENT_FLOW_ESTABLISHED &&
                            event != WINDIVERT_EVENT_FLOW_DELETED)
                        {
                            goto windivert_filter_compile_error;
                        }
                        break;
                    case WINDIVERT_LAYER_SOCKET:
                        if (event != WINDIVERT_EVENT_SOCKET_BIND &&
                            event != WINDIVERT_EVENT_SOCKET_CONNECT &&
                            event != WINDIVERT_EVENT_SOCKET_LISTEN &&
                            event != WINDIVERT_EVENT_SOCKET_ACCEPT)
                        {
                            goto windivert_filter_compile_error;
                        }
                        break;
                    case WINDIVERT_LAYER_REFLECT:
                        if (event != WINDIVERT_EVENT_REFLECT_ESTABLISHED &&
                            event != WINDIVERT_EVENT_REFLECT_OPEN &&
                            event != WINDIVERT_EVENT_REFLECT_CLOSE)
                        {
                            goto windivert_filter_compile_error;
                        }
                        break;
                    default:
                        goto windivert_filter_compile_error;
                }
                break;
            case WINDIVERT_FILTER_FIELD_IP_HDRLENGTH:
            case WINDIVERT_FILTER_FIELD_TCP_HDRLENGTH:
                if (ioctl_filter[i].arg[0] > 0x0F)
                {
                    goto windivert_filter_compile_error;
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
            case WINDIVERT_FILTER_FIELD_PROTOCOL:
                if (ioctl_filter[i].arg[0] > UINT8_MAX)
                {
                    goto windivert_filter_compile_error;
                }
                break;
            case WINDIVERT_FILTER_FIELD_IP_FRAGOFF:
                if (ioctl_filter[i].arg[0] > 0x1FFF)
                {
                    goto windivert_filter_compile_error;
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
            case WINDIVERT_FILTER_FIELD_LOCALPORT:
            case WINDIVERT_FILTER_FIELD_REMOTEPORT:
                if (ioctl_filter[i].arg[0] > UINT16_MAX)
                {
                    goto windivert_filter_compile_error;
                }
                break;
            case WINDIVERT_FILTER_FIELD_IPV6_FLOWLABEL:
                if (ioctl_filter[i].arg[0] > 0x000FFFFF)
                {
                    goto windivert_filter_compile_error;
                }
                break;
            default:
                break;
        }
        filter[i].field   = ioctl_filter[i].field;
        filter[i].test    = ioctl_filter[i].test;
        filter[i].success = ioctl_filter[i].success;
        filter[i].failure = ioctl_filter[i].failure;
        filter[i].arg[0]  = ioctl_filter[i].arg[0];
        filter[i].arg[1]  = ioctl_filter[i].arg[1];
        filter[i].arg[2]  = ioctl_filter[i].arg[2];
        filter[i].arg[3]  = ioctl_filter[i].arg[3];
    }
    
    return filter;

windivert_filter_compile_error:

    windivert_free(filter);
    return NULL;
}

/****************************************************************************/
/* WINDIVERT REFLECT MANAGER IMPLEMENTATION                                 */
/****************************************************************************/

#define WINDIVERT_REFLECT_PSEUDO_PACKET_MAX     12288

/*
 * WinDivert reflect state.
 */
static BOOL reflect_inited = FALSE;         // Reflection initialized?
static BOOL reflect_worker_queued = FALSE;  // Reflect worker queued?
static KSPIN_LOCK reflect_lock;             // Reflect lock.
static LIST_ENTRY reflect_event_queue;      // Reflect event queue.
static LIST_ENTRY reflect_contexts;         // All open (non-REFLECT) contexts.
static LIST_ENTRY reflect_waiters;          // All open REFLECT contexts.
static WDFWORKITEM reflect_worker;          // Reflect work item.
#pragma data_seg(push, stack, "PAGE")
static UINT8 reflect_pseudo_packet[WINDIVERT_REFLECT_PSEUDO_PACKET_MAX];
#pragma data_seg(pop, stack)

/*
 * Initialize the reflection layer implementation.
 */
static NTSTATUS windivert_reflect_init(WDFOBJECT parent)
{
    WDF_WORKITEM_CONFIG item_config;
    WDF_OBJECT_ATTRIBUTES obj_attrs;
    NTSTATUS status;

    KeInitializeSpinLock(&reflect_lock);
    InitializeListHead(&reflect_event_queue);
    InitializeListHead(&reflect_contexts);
    InitializeListHead(&reflect_waiters);
    WDF_WORKITEM_CONFIG_INIT(&item_config, windivert_reflect_worker);
    item_config.AutomaticSerialization = FALSE;
    WDF_OBJECT_ATTRIBUTES_INIT(&obj_attrs);
    obj_attrs.ParentObject = parent;
    status = WdfWorkItemCreate(&item_config, &obj_attrs, &reflect_worker);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create reflection work item", status);
        return status;
    }
    reflect_inited = TRUE;
    return STATUS_SUCCESS;
}

/*
 * Cleanup the reflection layer implementation.
 */
static void windivert_reflect_close(void)
{
    if (!reflect_inited)
    {
        return;
    }
    WdfWorkItemFlush(reflect_worker);
    WdfObjectDelete(reflect_worker);
}

/*
 * WinDivert handle reflect open event.
 */
static void windivert_reflect_open_event(context_t context)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    WDFOBJECT object;
    reflect_event_t reflect_event;

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    object = (WDFOBJECT)context->object;
    // To be released on the close event.  This ensures the context object
    // remains valid until the close event has been handled.
    WdfObjectReference(object);
    context->reflect.open = TRUE;
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    // Queue the event:
    reflect_event = &context->reflect.open_event;
    reflect_event->context = context;
    reflect_event->event   = WINDIVERT_EVENT_REFLECT_OPEN;
    KeAcquireInStackQueuedSpinLock(&reflect_lock, &lock_handle);
    InsertTailList(&reflect_event_queue, &reflect_event->entry);
    if (!reflect_worker_queued)
    {
        WdfWorkItemEnqueue(reflect_worker);
        reflect_worker_queued = TRUE;
    }
    KeReleaseInStackQueuedSpinLock(&lock_handle);
}

/*
 * WinDivert handle reflect close event.
 */
static void windivert_reflect_close_event(context_t context)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    reflect_event_t reflect_event;
    BOOL open;

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    open = context->reflect.open;
    KeReleaseInStackQueuedSpinLock(&lock_handle);
    if (!open)
    {
        return;
    }

    // Queue the event:
    reflect_event = &context->reflect.close_event;
    reflect_event->context = context;
    reflect_event->event   = WINDIVERT_EVENT_REFLECT_CLOSE;
    KeAcquireInStackQueuedSpinLock(&reflect_lock, &lock_handle);
    InsertTailList(&reflect_event_queue, &reflect_event->entry);
    if (!reflect_worker_queued)
    {
        WdfWorkItemEnqueue(reflect_worker);
        reflect_worker_queued = TRUE;
    }
    KeReleaseInStackQueuedSpinLock(&lock_handle);
}

/*
 * Create REFLECT layer "pseudo" packet to pass the filter.
 */
static PWINDIVERT_IPHDR windivert_reflect_pseudo_packet(context_t context,
    ULONG *len_ptr)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    UINT16 total_len;
    UINT8 *packet;
    char *object;
    PWINDIVERT_FILTER filter;
    UINT8 filter_len;
    PWINDIVERT_IPHDR iphdr;
    WINDIVERT_STREAM stream;

    // The filter is returned in a pseudo-IP packet.  This is just to make
    // the interface consistent, i.e., WinDivertRecv() always receives IP
    // packets.

    packet = reflect_pseudo_packet;
    iphdr = (PWINDIVERT_IPHDR)packet;
    object = (char *)(iphdr + 1);

    stream.data     = object;
    stream.pos      = 0;
    stream.max      = sizeof(reflect_pseudo_packet) - sizeof(WINDIVERT_IPHDR);
    stream.overflow = FALSE;

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    filter = context->filter;
    filter_len = context->filter_len;
    KeReleaseInStackQueuedSpinLock(&lock_handle);
    
    WinDivertSerializeFilter(&stream, filter, filter_len);

    total_len = sizeof(WINDIVERT_IPHDR) + (UINT16)stream.pos;
    RtlZeroMemory(iphdr, sizeof(WINDIVERT_IPHDR));
    iphdr->Version   = 4;
    iphdr->HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);
    iphdr->Length    = RtlUshortByteSwap(total_len);
    iphdr->TTL       = 1;
    iphdr->Protocol  = 254;                         // "experimental"

    *len_ptr = total_len;

    return iphdr;
}

/*
 * Notify all REFLECT layer contexts a new event.
 */
static void windivert_reflect_event_notify(context_t context,
    LONGLONG timestamp, WINDIVERT_EVENT event)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    PLIST_ENTRY entry;
    context_t waiter;
    PWINDIVERT_FILTER filter;
    PWINDIVERT_IPHDR packet = NULL;
    ULONG packet_len;
    BOOL match;

    entry = reflect_waiters.Flink;
    while (entry != &reflect_waiters)
    {
        waiter = CONTAINING_RECORD(entry, struct context_s, reflect.entry);
        entry = entry->Flink;
        KeAcquireInStackQueuedSpinLock(&waiter->lock, &lock_handle);
        filter = waiter->filter;
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        match = windivert_filter(/*buffer=*/NULL,
            /*layer=*/WINDIVERT_LAYER_REFLECT, (PVOID)&context->reflect.data,
            event, /*ipv4=*/TRUE, /*outbound=*/FALSE, /*loopback=*/FALSE,
            /*impostor=*/FALSE, filter);
        if (!match)
        {
            continue;
        }
        if (packet == NULL)
        {
            packet = windivert_reflect_pseudo_packet(context, &packet_len);
        }
        (VOID)windivert_queue_work(waiter, (PVOID)packet, packet_len,
            /*buffers=*/NULL, /*layer=*/WINDIVERT_LAYER_REFLECT,
            (PVOID)&context->reflect.data, event, /*flags=*/0, /*priority=*/0,
            /*ipv4=*/TRUE, /*outbound=*/FALSE, /*loopback=*/FALSE,
            /*impostor=*/FALSE, /*final=*/FALSE, /*match=*/TRUE, timestamp);
    }
}

/*
 * Notify a new REFLECT layer context of all existing open handles.
 */
static void windivert_reflect_established_notify(context_t context,
    LONGLONG timestamp)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    PLIST_ENTRY entry;
    BOOL match, ok, final;
    context_t waiter;
    PWINDIVERT_FILTER filter;
    PWINDIVERT_IPHDR packet;
    ULONG packet_len;

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    filter = context->filter;
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    entry = reflect_contexts.Flink;
    while (entry != &reflect_contexts)
    {
        waiter = CONTAINING_RECORD(entry, struct context_s, reflect.entry);
        entry = entry->Flink;
        match = windivert_filter(/*buffer=*/NULL,
            /*layer=*/WINDIVERT_LAYER_REFLECT, (PVOID)&waiter->reflect.data,
            /*event=*/WINDIVERT_EVENT_REFLECT_ESTABLISHED, /*ipv4=*/TRUE,
            /*outbound=*/FALSE, /*loopback=*/FALSE, /*impostor=*/FALSE, filter);
        if (!match)
        {
            continue;
        }
        packet = windivert_reflect_pseudo_packet(waiter, &packet_len);
        final = (entry == &reflect_contexts);
        ok = windivert_queue_work(context, (PVOID)packet, packet_len,
            /*buffers=*/NULL, /*layer=*/WINDIVERT_LAYER_REFLECT,
            (PVOID)&waiter->reflect.data,
            /*event=*/WINDIVERT_EVENT_REFLECT_ESTABLISHED, /*flags=*/0,
            /*priority=*/0, /*ipv4=*/TRUE, /*outbound=*/FALSE,
            /*loopback=*/FALSE, /*impostor=*/FALSE, final, /*match=*/TRUE,
            timestamp);
        if (!ok)
        {
            break;
        }
    }
}

/*
 * WinDivert REFLECT worker.
 */
static void windivert_reflect_worker(IN WDFWORKITEM item)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    PLIST_ENTRY entry;
    context_t context;
    LONGLONG timestamp;
    WINDIVERT_EVENT event;
    reflect_event_t reflect_event;
    WDFOBJECT object;
    WINDIVERT_LAYER layer;

    // All reflection events are serialized and handled by this worker.
    // This ensures that we are always operating on a consistent "snapshot"
    // of the WinDivert handle state.  This worker also has exclusive control 
    // over reflect_contexts/reflect_waiters, so locking is not required.

    KeAcquireInStackQueuedSpinLock(&reflect_lock, &lock_handle);
    while (!IsListEmpty(&reflect_event_queue))
    {
        entry = RemoveHeadList(&reflect_event_queue);
        KeReleaseInStackQueuedSpinLock(&lock_handle);

        reflect_event = CONTAINING_RECORD(entry, struct reflect_event_s, entry);
        context       = reflect_event->context;
        event         = reflect_event->event;

        DEBUG("REFLECT: %s event for WinDivert context (context=%p)",
            (event == WINDIVERT_EVENT_REFLECT_OPEN? "open": "close"), context);

        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
        object = (WDFOBJECT)context->object;
        layer = context->layer;
        KeReleaseInStackQueuedSpinLock(&lock_handle);

        timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
        switch (event)
        {
            case WINDIVERT_EVENT_REFLECT_OPEN:
                if (layer != WINDIVERT_LAYER_REFLECT)
                {
                    InsertTailList(&reflect_contexts, &context->reflect.entry);
                }
                else
                {
                    InsertTailList(&reflect_waiters, &context->reflect.entry);
                    windivert_reflect_established_notify(context, timestamp);
                }
                break;

            case WINDIVERT_EVENT_REFLECT_CLOSE:
                RemoveEntryList(&context->reflect.entry);
                break;
        }

        if (layer != WINDIVERT_LAYER_REFLECT)
        {
            windivert_reflect_event_notify(context, timestamp, event);
        }
        if (event == WINDIVERT_EVENT_REFLECT_CLOSE)
        {
            WdfObjectDereference(object);
        }

        KeAcquireInStackQueuedSpinLock(&reflect_lock, &lock_handle);
    }
    reflect_worker_queued = FALSE;
    KeReleaseInStackQueuedSpinLock(&lock_handle);
}

