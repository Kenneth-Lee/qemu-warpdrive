/*
 * WarpDrive dummyv2 device
 *
 * Copyright (c) 2019 Kenneth Lee
 *
 * This code is licensed under the GPL.
 */

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "qemu/log.h"
#include "sysemu/dma.h"
#include "trace.h"

#define TYPE_WD_DUMMY_V2 "wd_dummy_v2"
#define TYPE_WD_DUMMY_V2_IOMMU "wd_dummy_v2_iommu"
#define DUMMY_TAG 0x3333444455556666
#define PAGE_SHIF 12
#define DMA_PAGESIZE    (1<<PAGE_SHIF)
#define MAX_PT_ENTRIES  64

/* every entry refer to a dma page (size=DMA_PAGESIZE) */
struct pt_entry {
    uint64_t asid; /* -1 means entry invalid, 0 means kernel, others are valide pasid */
    uint64_t iova; /* -1 means entry invalid */
    uint64_t pa;
};

struct ring_bd {
	char *src_addr;
	char *tgt_addr;
	size_t size;
	void *ptr;
	uint32_t ret;
};
#define Q_BDS 16
#define DUMMY_HW_TAG_SZ 	8
#define DUMMY_Q_TAG "WDDUMMY\0"
struct dummy_hw_queue_reg {
	char hw_tag[DUMMY_HW_TAG_SZ];	/* should be "WDDUMMY\0" */
	struct ring_bd ring[Q_BDS];	/* in real hardware, this is good to be
					   in memory space, and will be fast
					   for communication. here we keep it
					   in io space just to make it simple
					   */
	uint32_t ring_bd_num;		/* ring_bd_num, now it is Q_BDS until
					   we use a memory ring */
	uint32_t head; 			/* assume int is atomical. it should be
					   fine as a dummy and test function.
					   head is for the writer(user) while
					   tail is for the reader(kernel).
					   head==tail means the queue is empty
					   */
	uint32_t tail;
};

#define RING_NUM 3
#define HEADER_WORDS 12 /* reseved words in page 0 */
#define MAX_COPY_SIZE 1024

/* IO space defintion
 *
 * page0:
 * 64bit word:
 * w0(ro): tag: TYPE_WD_DUMMY_V2
 * w1(rw): pa to page table
 * w2(rw): page table size (write to this for pt validation)
 * w3(rw): flags
 * w4(ro): max copy size (in bytes)
 * from RING_START_ADDR: ring 0-2 data: struct ring_io
 *
 * page 1 - (1+RING_NUM): w0(wo): ring doorbell
 *
 * ring buffer bd format:
 * struct wd_dummy_cpy_msg {
 *   char *src_addr;
 *   char *tgt_addr;
 *   size_t size;
 *   void *ptr;
 *   uint32_t ret;
 * };
 *
 * page table entry format: struct pt_entry;
 */

#define FLAG_PASSTHROUGH 1

struct ring_io {
    uint64_t rbpa;
    uint64_t rbsz;
    uint64_t asid;
};

typedef struct WDDummyV2State {
    SysBusDevice parent_obj;

    MemoryRegion iomem;
    qemu_irq irq;
    uint64_t ptpa;
    uint64_t ptsz;
    uint64_t flags;
    uint64_t max_copy_size;
    uint32_t tail;
    struct ring_io rio[3];

    struct pt_entry *pt;
} WDDummyV2State;

static hwaddr _iommu_translate(WDDummyV2State *s, hwaddr iova)
{
    int i;
    const char *m = "fail";
    hwaddr pa = 0;
    uint64_t asid;

    return 0;

    if (s->flags & FLAG_PASSTHROUGH) {
        pa = iova;
        asid = 0;
        m = "passthrough";
    } else {
        for (i = 0; i < s->ptsz; i++) {
            if (s->pt[i].asid != (uint64_t)-1 && s->pt[i].iova == iova) {
                pa = s->pt[i].pa;
                m = "tran";
                asid = s->pt[i].asid;
                break;
            }
        }
    }

    trace_wd_dummy_v2_tran(m, asid, iova, pa);
    return pa;
}

static inline void _index_from_offset(hwaddr offset, int *pi, int *wi, int *ri)
{
    *pi = offset >> PAGE_SHIF; /*page index */
    *wi = (offset & 0xfff) >> 3; /* word index within page */
    if (*wi >= HEADER_WORDS)
        *ri = (*wi - HEADER_WORDS) / sizeof(struct ring_io); /* ring index */
    else
        *ri = -1;
}

static uint64_t wd_dummy_v2_read(void *opaque, hwaddr offset,
                           unsigned size)
{
    WDDummyV2State *s = (WDDummyV2State *)opaque;
    int pi,wi,ri,rii;

    _index_from_offset(offset, &pi, &wi, &ri);

    trace_wd_dummy_v2_read(offset);

    if (pi==0) {
	    switch(wi) {
        case 0:
            return DUMMY_TAG;
        case 1:
            return s->ptpa;
        case 2:
            return s->ptsz;
        case 3:
            return s->flags;
        case 4:
            return MAX_COPY_SIZE;
        }

        if (ri < 0 || ri > RING_NUM) {
                trace_wd_dummy_v2_err("ri out of range", ri);
                return 0; /* out of ring */
        }

        rii = (wi - HEADER_WORDS) - ri * sizeof(struct ring_io);
        switch(rii) {
        case 0:
            return s->rio[ri].rbpa;
        case 1:
            return s->rio[ri].rbsz;
        case 2:
            return s->rio[ri].asid;
        default:
            trace_wd_dummy_v2_err("rii out of range", rii);
            return 0;
        }
    }

    return 0;
}

static int _do_copy(WDDummyV2State *s, void *tgt_addr, void *src_addr,
        uint64_t size)
{
    AddressSpace *as = &address_space_memory;
    char buf[MAX_COPY_SIZE];
    int ret;

    ret = dma_memory_read(as, _iommu_translate(s, (uint64_t)src_addr), buf, size);
    ret = dma_memory_write(as, _iommu_translate(s, (uint64_t)tgt_addr), buf, size);

    if (ret) {
        trace_wd_dummy_v2_err("dummy_wd io error\n", ret);
        return -EIO;
    }

    return 0;
}

#define rbpa(s, rid, member) _iommu_translate(s, (s->rio[rid].rbpa + \
    offsetof(struct dummy_hw_queue_reg, member)))
static void _doorbell(WDDummyV2State *s, int rid, uint64_t value)
{
    AddressSpace *as = &address_space_memory;
	uint32_t head;
	uint32_t tail;
    int ret;
	struct ring_bd bd;

    if (s->rio[rid].rbpa == (uint64_t)-1 || !s->rio[rid].rbpa ||
        s->rio[rid].rbsz != Q_BDS) {
        trace_wd_dummy_v2_err("rbpa not set (db)", s->rio[rid].rbpa);
        return;
    }

    ret = dma_memory_read(as, rbpa(s, rid, head), &head, sizeof(head));
    if (ret) {
        trace_wd_dummy_v2_err("read head", ret);
        return;
    }

	if (head >= Q_BDS) {
		trace_wd_dummy_v2_err("dummy_wd io error", head);
		return;
	}

	tail = s->tail;
	while (s->tail != head) {
        ret = dma_memory_read(as,
                rbpa(s, rid, ring) + s->tail * sizeof(struct ring_bd),
                &bd, sizeof(bd));
        if (ret) {
            trace_wd_dummy_v2_err("read bd", ret);
            return;
        }
		if(bd.size > s->max_copy_size)
			bd.ret = -EINVAL;
		else
			bd.ret = _do_copy(s, bd.tgt_addr, bd.src_addr, bd.size);

        trace_wd_dummy_v2_copy((uint64_t)bd.tgt_addr, (uint64_t)bd.src_addr,
			                   bd.size, bd.ret);
        ret = dma_memory_write(as,
                rbpa(s, rid, ring) + s->tail * sizeof(struct ring_bd),
                &bd, sizeof(bd));
        if (ret) {
            trace_wd_dummy_v2_err("write bd", ret);
            return;
        }
		s->tail = (s->tail+1)%Q_BDS;
	}

	if (tail != s->tail) {
		trace_wd_dummy_v2_err("write back tail %d", head);
        ret = dma_memory_write(as, rbpa(s, rid, tail), &s->tail, sizeof(s->tail));
        if (ret) {
            trace_wd_dummy_v2_err("write bd", ret);
            return;
        }
        qemu_set_irq(s->irq, 1);
	} else
	    trace_wd_dummy_v2_err("doorbell with no data", value);
}

static void _set_rb(WDDummyV2State *s, int rid, uint64_t rbsz)
{
    int ret;
    AddressSpace *as = &address_space_memory;
    uint32_t init_val = 0;
    uint32_t rbd_n = Q_BDS;

    if (rbsz == 0) {
        s->rio[rid].rbpa = 0;
        s->rio[rid].rbsz = 0;
        s->rio[rid].asid = (uint64_t)-1;
        return;
    }

    if (s->rio[rid].rbpa == (uint64_t)-1 || !s->rio[rid].rbpa) {
        trace_wd_dummy_v2_err("rbpa not set", s->rio[rid].rbpa);
        return;
    }

    if (rbsz != Q_BDS) {
        trace_wd_dummy_v2_err("wrong rbsz size", rbsz);
        return;
    }

    ret = dma_memory_write(as, rbpa(s, rid, hw_tag), DUMMY_Q_TAG, DUMMY_HW_TAG_SZ);
    ret += dma_memory_write(as, rbpa(s, rid, ring_bd_num), &rbd_n, sizeof(uint32_t));
    ret += dma_memory_write(as, rbpa(s, rid, head), &init_val, sizeof(uint32_t));
    ret += dma_memory_write(as, rbpa(s, rid, tail), &init_val, sizeof(uint32_t));
    if (ret) {
        trace_wd_dummy_v2_err("set rb", ret);
        return;
    }
    s->rio[rid].rbsz = rbsz;
}


static void _set_new_pt(WDDummyV2State *s, uint64_t new_size)
{
    int ret;

    s->ptsz = new_size > MAX_PT_ENTRIES ? 0 : new_size;
    if (s->pt) {
        g_free(s->pt);
        s->pt = NULL;
    }

    if (s->ptsz > 0) {
        s->pt = g_malloc_n(s->ptsz, sizeof(*s->pt));
        ret = dma_memory_read(&address_space_memory, s->ptpa, s->pt,
                              s->ptsz * sizeof(*s->pt));
        if (ret) {
            trace_wd_dummy_v2_err("set new page table", ret);
            s->ptsz = 0;
            g_free(s->pt);
            s->pt = NULL;
        }
    }
}

static void wd_dummy_v2_write(void *opaque, hwaddr offset,
                        uint64_t value, unsigned size)
{
    WDDummyV2State *s = (WDDummyV2State *)opaque;
    int pi,wi,ri,rii;

    _index_from_offset(offset, &pi, &wi, &ri);

    trace_wd_dummy_v2_write(offset, value);

    if (pi==0) {
	    switch(wi) {
        case 0:
            return;
        case 1:
            s->ptpa = value;
            return;
        case 2:
            _set_new_pt(s, value);
            return;
        case 3:
            s->flags = value;
            return;
        case 4:
            s->max_copy_size = value;
            return;
        }

        if (ri < 0 || ri > RING_NUM) {
            trace_wd_dummy_v2_err("ri out of range", ri);
            return;
        }

        rii = (wi - HEADER_WORDS) - ri * sizeof(struct ring_io);
        switch(rii) {
        case 0:
            s->rio[ri].rbpa = value;
            return;
        case 1:
            _set_rb(s, ri, value);
            return;
        case 2:
            s->rio[ri].asid = value;
            return;
        default:
            trace_wd_dummy_v2_err("rii out of range", rii);
            return;
        }
    } else if (pi-1 < RING_NUM)
        _doorbell(s, pi-1, value);

    trace_wd_dummy_v2_err("invalid io write", offset);
}

static const MemoryRegionOps wd_dummy_v2_ops = {
    .read = wd_dummy_v2_read,
    .write = wd_dummy_v2_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl = {
        .min_access_size = 8,
        .max_access_size = 8,
    },
};

static const VMStateDescription wd_dummy_v2_vmsd = {
    .name = "wd_dummy_v2",
    .version_id = 2,
    .minimum_version_id = 2,
    .fields = (VMStateField[]) {
        VMSTATE_UINT64(flags, WDDummyV2State),
        VMSTATE_END_OF_LIST()
    }
};

static Property wd_dummy_v2_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void wd_dummy_v2_init(Object *obj)
{
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);
    WDDummyV2State *s = OBJECT_CHECK(WDDummyV2State, (obj), TYPE_WD_DUMMY_V2);

    memory_region_init_io(&s->iomem, OBJECT(s), &wd_dummy_v2_ops, s,
		    "wd_dummy_v2", 0xa000);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);

    s->ptpa = 0;
    s->ptsz = 0;
    s->flags = FLAG_PASSTHROUGH;
    s->pt = NULL;
    s->tail = 0;
}

static void wd_dummy_v2_realize(DeviceState *dev, Error **errp)
{
}

static void wd_dummy_v2_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    dc->realize = wd_dummy_v2_realize;
    dc->vmsd = &wd_dummy_v2_vmsd;
    dc->props = wd_dummy_v2_properties;
}

static const TypeInfo wd_dummyv2 = {
    .name          = TYPE_WD_DUMMY_V2,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(WDDummyV2State),
    .instance_init = wd_dummy_v2_init,
    .class_init    = wd_dummy_v2_class_init,
};

static void wd_dummy_v2_register_types(void)
{
    type_register_static(&wd_dummyv2);
}

type_init(wd_dummy_v2_register_types)
