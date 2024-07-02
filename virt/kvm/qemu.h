#ifndef __QEMU_H_
#define __QEMU_H_

#include <linux/uio.h>
typedef struct VirtQueueElement VirtQueueElement;
typedef struct EventNotifier EventNotifier;
struct VRingMemoryRegionCaches;
typedef long unsigned int hwaddr;
struct VirtIODevice;
struct VirtQueue;
typedef unsigned long size_t;

#define QLIST_ENTRY(type)                                               \
struct {                                                                \
        struct type *le_next;   /* next element */                      \
        struct type **le_prev;  /* address of previous next element */  \
}

typedef struct VRing
{
    unsigned int num;
    unsigned int num_default;
    unsigned int align;
    hwaddr desc;
    hwaddr avail;
    hwaddr used;
    struct VRingMemoryRegionCaches *caches;
} VRing;
struct VirtIOHandleOutput;
typedef void (*VirtIOHandleOutput)(struct VirtIODevice *, struct VirtQueue *);

struct EventNotifier {
    int rfd;
    int wfd;
    bool initialized;
};


struct VirtQueue
{
    VRing vring;
    VirtQueueElement *used_elems;

    /* Next head to pop */
    unsigned short int  last_avail_idx;
    bool last_avail_wrap_counter;

    /* Last avail_idx read from VQ. */
    unsigned short int  shadow_avail_idx;
    bool shadow_avail_wrap_counter;

    unsigned short int  used_idx;
    bool used_wrap_counter;

    /* Last used index value we have signalled on */
    unsigned short int  signalled_used;

    /* Last used index value we have signalled on */
    bool signalled_used_valid;

    /* Notification enabled? */
    bool notification;

    unsigned short int  queue_index;

    unsigned int inuse;

    unsigned short int  vector;
    VirtIOHandleOutput handle_output;
    struct VirtIODevice *vdev;
    EventNotifier guest_notifier;
    EventNotifier host_notifier;
    bool host_notifier_enabled;
    QLIST_ENTRY(VirtQueue) node;
};

struct fast_map {
    struct iovec iovec[3];
    hwaddr addr[3];
    bool fast;
    unsigned int wfd;
    unsigned int fd;
    unsigned short head;
};

typedef unsigned char val__t[64];

struct ReValue {
    char found;
    val__t value;
};


struct virtio_blk_inhdr {
    unsigned char status;
    struct ReValue query;
};


struct extent_status {
	unsigned int  es_lblk;	/* first logical block extent covers */
	unsigned int  es_len;	/* length of extent in block */
	unsigned long int  es_pblk;	/* first physical block */
};

struct virtio_blk_outhdr {
	// unsigned int 	ib_enable;
	// struct extent_status ib_es[15];
	// unsigned int 	ib_es_num;
	/* VIRTIO_BLK_T* */
	unsigned int type;
	/* io priority. */
	unsigned int ioprio;
	/* Sector (ie. 512 byte offset) */
	unsigned long int sector;
};

struct VirtIOBlockReq {
    size_t in_len;
    struct virtio_blk_inhdr *in;
    struct iovec qiov;
    struct iovec undo;
    struct virtio_blk_outhdr out;
};


#endif
