#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>
#include <string.h>
#include "common.h"

#define SCAN_WINDOW_NS 90ULL * 1000000000ULL
#define PORT_THRESHOLD 90

// this da map twin
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 28); // 256 MiB
} Network_RB SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 2048);
} Blocked_Ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct scan_entry);
    __uint(max_entries, 1024);
} Port_Scan_Tracker SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct in_addr);
    __type(value, __u8);
    __uint(max_entries, 100);
} Blocked_IPs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct in_addr);
    __type(value, __u8);
    __uint(max_entries, 100);
} Whitelist SEC(".maps");

struct {
    __uint (type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct scan_entry);
    __uint(max_entries, 1);
} Scratch_Space SEC(".maps");


// func to check if port is blocked
// be a doll and dont forget to convert port from network order to host order when passing arg
static __always_inline int is_blocked(__u16 port){
    __u32 idx = port / 32;
    __u32 bit = port % 32;

    __u32 *entry = bpf_map_lookup_elem(&Blocked_Ports, &idx);
    if (!entry) return 0;

    return (*entry & (1 << bit));
}

static __always_inline int track_ip(__u32 src_ip, __u16 port){
    int err;
    struct scan_entry *entry;
    const static struct scan_entry empty = {0};
    entry = bpf_map_lookup_elem(&Port_Scan_Tracker, &src_ip);
    if (!entry){
        __u32 key = 0;
        struct scan_entry *new_entry = bpf_map_lookup_elem(&Scratch_Space, &key);
        if (!new_entry) return 1;

        // AIR OUT THAT MAP PEW PEW
        err = bpf_map_update_elem(&Port_Scan_Tracker, &src_ip, &empty, BPF_NOEXIST);
        if (err != 0) return 1;

        new_entry->window_start_time = bpf_ktime_get_ns();
        err = bpf_map_update_elem(&Port_Scan_Tracker, &src_ip, new_entry, BPF_EXIST);
        if (err != 0) return 1;
        
        entry = bpf_map_lookup_elem(&Port_Scan_Tracker, &src_ip);
        if (!entry) return 1;
    }
    
    if (bitmap_test(entry->port_bitmap, port) == 0){
        bitmap_set(entry->port_bitmap, port);
        entry->port_count++;
    }
    
    return 0;    
}

static __always_inline int check_port_scan(__u32 src_ip){
    struct scan_entry *entry;
    entry = bpf_map_lookup_elem(&Port_Scan_Tracker, &src_ip);
    if (!entry) return 0;

    __u64 current_time = bpf_ktime_get_ns();
    __u64 duration = current_time - entry->window_start_time;

    if (duration <= SCAN_WINDOW_NS && entry->port_count >= PORT_THRESHOLD) {
        return 1;
    }

    return 0;
}

SEC("xdp")
int reconguard(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    enum xdp_action operation;
    struct hdr_cursor nh;

    nh.pos = data;

    int eth_type = parse_ethhdr(&nh, data_end, &eth);
    // only deal with ipv4 addresses
    if (eth_type != bpf_htons(ETH_P_IP)) {
        operation = XDP_PASS;
        goto done;
    }
    
    struct iphdr *ip_hdr;
    int proto_type = parse_iphdr(&nh, data_end, &ip_hdr);
    if (proto_type < 0) {
        operation = XDP_PASS;
        goto done;
    }    
   
    struct NetworkEvent *ev;
    ev = bpf_ringbuf_reserve(&Network_RB, sizeof(struct NetworkEvent), 0);
    if (!ev) {
        operation = XDP_PASS;
        goto done;
    }

    ev->src_ip = (__u32)ip_hdr->saddr;
    ev->isScanner = false;

    __u8 *is_offender = bpf_map_lookup_elem(&Blocked_IPs, &ev->src_ip);

    // disregard noise traffic
    if (is_offender != NULL){
        bpf_ringbuf_discard(ev, 0);
        operation = XDP_DROP;
        goto done;
    }
    __u8 *is_whitelisted = bpf_map_lookup_elem(&Whitelist, &ev->src_ip);

    if (proto_type == IPPROTO_TCP){
        struct tcphdr *tcp_hdr;
        int tcp_ret = parse_tcphdr(&nh, data_end, &tcp_hdr);
        // ensure the length is valid
        if (tcp_ret < 0) {
            bpf_ringbuf_discard(ev, 0);
            operation = XDP_PASS;
            goto done;
        }

        ev->src_port = (__u16)tcp_hdr->source;
        ev->dst_port = (__u16)tcp_hdr->dest;
        strcpy(ev->protocol, "TCP");
        
        int ret = track_ip(ev->src_ip, ev->dst_port);
        if (ret != 0){
            bpf_ringbuf_discard(ev, 0);
            operation = XDP_PASS;
            goto done;
        }

        int is_scanning = check_port_scan(ev->src_ip);

        int to_block = is_blocked(bpf_ntohs((__u16)tcp_hdr->dest));

        bool not_whitelisted = is_scanning && !is_whitelisted;
        
        if (to_block != 0 || is_offender != NULL || not_whitelisted){
            if (not_whitelisted)
            {
                // only update it if it doesnt exist
                bpf_map_update_elem(&Blocked_IPs, &ev->src_ip, &val, BPF_NOEXIST);
                ev->isScanner = true;
            }
            
            ev->action = 1;
            operation = XDP_DROP;
        } else {
            ev->action = 0;
            operation = XDP_PASS;
        }


    } else if (proto_type == IPPROTO_UDP){
        struct udphdr *udp_hdr;
        int udp_ret = parse_udphdr(&nh, data_end, &udp_hdr);
        if (udp_ret < 0) {
            bpf_ringbuf_discard(ev, 0);
            operation = XDP_PASS;
            goto done;
        }
        ev->src_port = (__u16)udp_hdr->source;
        ev->dst_port = (__u16)udp_hdr->dest;
        strcpy(ev->protocol, "UDP");

        int ret = track_ip(ev->src_ip, ev->dst_port);
        if (ret != 0){
            bpf_ringbuf_discard(ev, 0);
            operation = XDP_PASS;
            goto done;
        }

        int is_scanning = check_port_scan(ev->src_ip);
        
        int to_block = is_blocked(bpf_ntohs((__u16)udp_hdr->dest));
        
        bool not_whitelisted = is_scanning && !is_whitelisted;

        if (to_block != 0 || is_offender != NULL || not_whitelisted){
            if (not_whitelisted)
            {
                bpf_map_update_elem(&Blocked_IPs, &ev->src_ip, &val, BPF_NOEXIST);
                ev->isScanner = true;
            }

            ev->action = 1;
            operation = XDP_DROP; 
        } else {
            ev->action = 0;
            operation = XDP_PASS;
        }
        
    } else {
        bpf_ringbuf_discard(ev, 0);
        operation = XDP_PASS;
        goto done;
    }

    bpf_ringbuf_submit(ev, 0);

done:
    return operation;
}

char _license[] SEC("license") = "GPL";