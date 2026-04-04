#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <signal.h>
#include <net/if.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include "common.h"
#include "reconguard.skel.h"

#define ARRAY_SIZE 2048
#define BLOCKLIST_SIZE 100

int blocked_ports[ARRAY_SIZE];
struct in_addr *blocklist_array[BLOCKLIST_SIZE];
struct in_addr *whitelist_array[BLOCKLIST_SIZE];

char *ports_file = "blocked_ports.txt";
char *blocklist = "blocklist.txt";
char *whitelist = "whitelist.txt";

static volatile sig_atomic_t exiting = 0;

static void sig_handler(){
    printf("\nShutting down...\n");
    printf("ReconGuard stopped\n");
    exiting = 1;
}

static int handle_packet(void *ctx, void *data, size_t size)
{

    struct NetworkEvent *e = (struct NetworkEvent *)data;
    char action[17];
    if (e->action == 1){
        strcpy(action, "\x1b[31mBLOCKED\x1b[0m");
    } else {
        strcpy(action, "\x1b[32mALLOWED\x1b[0m");
    }
    
    // designated initializer syntax, pretty cool
    struct in_addr addr = {.s_addr = e->src_ip};
    if (e->isScanner && check_existing(blocklist, addr) == 0) {
        //update blocklist file on disk 
        int err = write_to_blocklist(blocklist, addr);
        if(err != 0)
        {
            fprintf(stderr, "Error updating blocklist\n");
            return 1;
        }
    }
    printf("[%s] %s:%d -> Port %d (%s)\n", action, inet_ntoa(addr), ntohs(e->src_port), ntohs(e->dst_port), e->protocol);
    return 0;
}

int load_blocked_ports(char *filename){
    int port;
    memset(blocked_ports, 0, sizeof(blocked_ports));

    FILE *f = fopen(filename, "r");
    if(f == NULL){
        fprintf(stderr, "Could not open %s: %s.\n", filename, strerror(errno));
        return 1;
    }
    
    while (fscanf(f, "%d", &port) == 1)
    {
        if(port >= 0 && port <= 65535){
            SetBit(blocked_ports, port);
        }
    }
    fclose(f);
    return 0;
}

int check_existing (char *filename, struct in_addr addr) {
    
    char ip[INET_ADDRSTRLEN+1];

    FILE *f =fopen(filename, "r");
    if (f == NULL){
        fprintf(stderr, "Could not load blocklist: %s\n", strerror(errno));
        return -1;
    }

    while (fscanf(f, "%s", ip) == 1){
        if (strcmp(ip, inet_ntoa(addr)) == 0){
            fclose(f);
            return 1;
        }
    }

    fclose(f);
    return 0;
}

int load_blocklist(char *filename){
    char ip[INET_ADDRSTRLEN+1];
    FILE *f = fopen(filename, "a+");
    
    if (f == NULL){
        fprintf(stderr, "Could not load blocklist: %s\n", strerror(errno));
        return -1;
    }

    // update r+w permissions (is this smart? should it be rd_only by root/)
    // if (chmod(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) == -1){
    //     fprintf(stderr, "Error setting file permissions\n");
    //     return 1;
    // };
    
    int i = 0;
    while (fscanf(f, "%s", ip) == 1)
    {
        /* load ip into blocklist array*/
        if (i >= BLOCKLIST_SIZE)
        {
            fprintf(stderr, "Blocklist full.\n");
            break;
        }
        // converts each ip to network byte order before storing
        int s = inet_pton(AF_INET, ip, &blocklist_array[i]);
        if (s == 1){
            i++;
        } else{
            fprintf(stderr, "Error: %s\n", strerror(errno));
            return -1;
        }

    }
    fclose(f);
    return i;
}

int load_whitelist(char *filename){
    char ip[INET_ADDRSTRLEN+1];
    FILE *f = fopen(filename, "a+");
    
    if (f == NULL){
        fprintf(stderr, "Could not load whitelist: %s\n", strerror(errno));
        return -1;
    }

    int i = 0;
    while (fscanf(f, "%s", ip) == 1)
    {
        /* load ip into whitelist array*/
        if (i >= BLOCKLIST_SIZE)
        {
            fprintf(stderr, "Whitelist full.\n");
            break;
        }
        // converts each ip to network byte order before storing
        int s = inet_pton(AF_INET, ip, &whitelist_array[i]);
        if (s == 1){
            i++;
        } else{
            fprintf(stderr, "Error: %s\n", strerror(errno));
            return -1;
        }

    }
    fclose(f);
    return i;
}

int write_to_blocklist(char *filename, struct in_addr addr){

    FILE *f = fopen(filename, "a+");
    if (f == NULL){
        fprintf(stderr, "Could not load blocklist: %s\n", strerror(errno));
        return 1;
    }

    fprintf(f, "%s\n", inet_ntoa(addr));
    fclose(f);
    return 0;
}

int main(int argc, char *argv[]) {

    struct reconguard *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, sig_handler);

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    int ifindex = if_nametoindex(ifname);
    
    if (ifindex == 0)
    {
        fprintf(stderr, "Invalid interface name %s\n", ifname);
        return 1;
    }

    // load ports 
    err = load_blocked_ports(ports_file);
    if (err != 0) {
        fprintf(stderr, "Error loading blocked ports list\n");
        goto cleanup;
    }

    // load blocklist
    int ip_count = load_blocklist(blocklist);
    if (ip_count < 0) {
        fprintf(stderr, "Error loading blocklist\n");
        goto cleanup;
    }

    // load whitelist
    int angel_count = load_whitelist(whitelist);
    if (angel_count < 0) {
        fprintf(stderr, "Error loading whitelist\n");
        goto cleanup;
    }

    // open and load BPF application
    skel = reconguard__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // load and verify BPF programs
    err = reconguard__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // attach XDP program 
    err = reconguard__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // attach the XDP program to the specified interface
    skel->links.reconguard = bpf_program__attach_xdp(skel->progs.reconguard, ifindex);
    if (!skel->links.reconguard)
    {
        err = -errno;
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(errno));
        goto cleanup;
    }
    
    // set up ring buffer polling
    rb = ring_buffer__new(bpf_map__fd(skel->maps.Network_RB), handle_packet, NULL, NULL);
    if (!rb)
    {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    // update bit array in bpf program
    for (int i = 0; i < ARRAY_SIZE; i++){
        err = bpf_map_update_elem(bpf_map__fd(skel->maps.Blocked_Ports), &i, &blocked_ports[i], BPF_ANY);
        if(err != 0){
            fprintf(stderr, "Error updating map\n");
            goto cleanup;
        }
    }

    //__u8 val = 1; 
     /* the IPs are stored as keys for that 
     sweet O(1) lookup time, but they need a
     value, so every key is lazily set to our 
     sweet val over here */
    
    // update blocklist hashmap    
    for (int i = 0; i < ip_count; i++){
        err = bpf_map_update_elem(bpf_map__fd(skel->maps.Blocked_IPs), &blocklist_array[i], &val, BPF_NOEXIST);
        if (err != 0)
        {
            fprintf(stderr, "Error updating blocklist\n");
            goto cleanup;
        }
    }

    // update whitelist hashmap 
    for (int i = 0; i < angel_count; i++){
        err = bpf_map_update_elem(bpf_map__fd(skel->maps.Whitelist), &whitelist_array[i], &val, BPF_NOEXIST);
        if (err != 0)
        {
            fprintf(stderr, "Error updating whitelist\n");
            goto cleanup;
        }
    }
    printf("\t\x1b[1;32mReconGuard\x1b[0m\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("Successfully attached ReconGuard to interface %s\n", ifname);
     
    printf("\x1b[32mProtecting your server...:)\x1b[0m\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("Press \x1b[31mCtrl + C\x1b[0m to stop\n\n");

    // poll the ring buffer
    while (!exiting)
    {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR)
        {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    
cleanup:
    if (rb){
        ring_buffer__free(rb);
    }
    if (skel){
        reconguard__destroy(skel);
    }
    return -err;
}