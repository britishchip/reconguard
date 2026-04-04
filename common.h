#ifndef __COMMON_H
#define __COMMON_H

#include <linux/bpf.h>
#include <stdbool.h>

struct NetworkEvent {
    __u32 src_ip;
    __u16 dst_port;
    __u16 src_port;
    char protocol[4];
    __u8 action;
    bool isScanner;
};

struct scan_entry {
    __u64 window_start_time;
    __u32 port_bitmap[2048];
    __u16 port_count;

};

__u8 val = 1;

#define SetBit(A,k)     ( A[(k/32)] |= (1 << (k%32)) )
#define ClearBit(A,k)   ( A[(k/32)] &= ~(1 << (k%32)) )
#define TestBit(A,k)    ( A[(k/32)] & (1 << (k%32)) )

static __always_inline void bitmap_set(__u32 *bitmap, __u16 bit) {
    bitmap[bit / 32] |= (__u32)1 << (bit % 32);
}

static __always_inline int bitmap_test(__u32 *bitmap, __u16 bit) {
    return (bitmap[bit / 32] >> (bit % 32)) & 1;
}

#endif /*__COMMON_H*/