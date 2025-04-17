/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __TESTE_TC_BPF_SKEL_H__
#define __TESTE_TC_BPF_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

#define BPF_SKEL_SUPPORTS_MAP_AUTO_ATTACH 1

struct teste_tc_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *valores;
		struct bpf_map *rodata;
	} maps;
	struct {
		struct bpf_program *pega_pkt;
	} progs;
	struct {
		struct bpf_link *pega_pkt;
	} links;

#ifdef __cplusplus
	static inline struct teste_tc_bpf *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct teste_tc_bpf *open_and_load();
	static inline int load(struct teste_tc_bpf *skel);
	static inline int attach(struct teste_tc_bpf *skel);
	static inline void detach(struct teste_tc_bpf *skel);
	static inline void destroy(struct teste_tc_bpf *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
teste_tc_bpf__destroy(struct teste_tc_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
teste_tc_bpf__create_skeleton(struct teste_tc_bpf *obj);

static inline struct teste_tc_bpf *
teste_tc_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct teste_tc_bpf *obj;
	int err;

	obj = (struct teste_tc_bpf *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = teste_tc_bpf__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	teste_tc_bpf__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct teste_tc_bpf *
teste_tc_bpf__open(void)
{
	return teste_tc_bpf__open_opts(NULL);
}

static inline int
teste_tc_bpf__load(struct teste_tc_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct teste_tc_bpf *
teste_tc_bpf__open_and_load(void)
{
	struct teste_tc_bpf *obj;
	int err;

	obj = teste_tc_bpf__open();
	if (!obj)
		return NULL;
	err = teste_tc_bpf__load(obj);
	if (err) {
		teste_tc_bpf__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
teste_tc_bpf__attach(struct teste_tc_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
teste_tc_bpf__detach(struct teste_tc_bpf *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *teste_tc_bpf__elf_bytes(size_t *sz);

static inline int
teste_tc_bpf__create_skeleton(struct teste_tc_bpf *obj)
{
	struct bpf_object_skeleton *s;
	struct bpf_map_skeleton *map __attribute__((unused));
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "teste_tc_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 2;
	s->map_skel_sz = 24;
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt,
			sizeof(*s->maps) > 24 ? sizeof(*s->maps) : 24);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	map = (struct bpf_map_skeleton *)((char *)s->maps + 0 * s->map_skel_sz);
	map->name = "valores";
	map->map = &obj->maps.valores;

	map = (struct bpf_map_skeleton *)((char *)s->maps + 1 * s->map_skel_sz);
	map->name = "teste_tc.rodata";
	map->map = &obj->maps.rodata;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "pega_pkt";
	s->progs[0].prog = &obj->progs.pega_pkt;
	s->progs[0].link = &obj->links.pega_pkt;

	s->data = teste_tc_bpf__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *teste_tc_bpf__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x20\x17\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x1c\0\
\x01\0\xb7\x01\0\0\0\0\0\0\x63\x1a\xfc\xff\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\
\0\0\xfc\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\
\x55\0\x05\0\0\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\x18\0\0\0\
\x85\0\0\0\x06\0\0\0\x05\0\x08\0\0\0\0\0\x79\x01\0\0\0\0\0\0\xbf\x06\0\0\0\0\0\
\0\x85\0\0\0\xd4\0\0\0\x79\x63\0\0\0\0\0\0\x18\x01\0\0\x18\0\0\0\0\0\0\0\0\0\0\
\0\xb7\x02\0\0\x30\0\0\0\x85\0\0\0\x06\0\0\0\xb7\0\0\0\x02\0\0\0\x95\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x45\x72\x72\x6f\x20\x6e\x6f\x20\x6c\x6f\x6f\x6b\x75\x70\x20\x64\x6f\x20\
\x6d\x61\x70\x61\x0a\0\x45\x53\x54\x41\x20\x43\x41\x50\x54\x41\x4e\x44\x4f\x20\
\x50\x4b\x54\x53\x21\x21\x21\x20\x76\x61\x6c\x6f\x72\x20\x64\x6f\x20\x70\x69\
\x64\x2c\x20\x6d\x61\x70\x61\x2d\x2d\x3e\x20\x25\x64\x0a\0\x47\x50\x4c\0\x23\0\
\0\0\x05\0\x08\0\x02\0\0\0\x08\0\0\0\x14\0\0\0\x04\x38\x60\x01\x50\x04\x68\x80\
\x01\x01\x50\0\x04\x70\x80\x01\x01\x51\0\x01\x11\x01\x25\x25\x13\x05\x03\x25\
\x72\x17\x10\x17\x1b\x25\x11\x1b\x12\x06\x73\x17\x8c\x01\x17\0\0\x02\x34\0\x03\
\x25\x49\x13\x3a\x0b\x3b\x0b\0\0\x03\x26\0\x49\x13\0\0\x04\x0f\0\x49\x13\0\0\
\x05\x15\x01\x49\x13\x27\x19\0\0\x06\x05\0\x49\x13\0\0\x07\x0f\0\0\0\x08\x26\0\
\0\0\x09\x2e\x01\x11\x1b\x12\x06\x40\x18\x7a\x19\x03\x25\x3a\x0b\x3b\x0b\x27\
\x19\x49\x13\x3f\x19\0\0\x0a\x34\0\x03\x25\x49\x13\x3a\x0b\x3b\x0b\x02\x18\0\0\
\x0b\x05\0\x03\x25\x3a\x0b\x3b\x0b\x49\x13\0\0\x0c\x34\0\x02\x18\x03\x25\x3a\
\x0b\x3b\x0b\x49\x13\0\0\x0d\x34\0\x02\x22\x03\x25\x3a\x0b\x3b\x0b\x49\x13\0\0\
\x0e\x34\0\x03\x25\x3a\x0b\x3b\x0b\x49\x13\0\0\x0f\x01\x01\x49\x13\0\0\x10\x21\
\0\x49\x13\x37\x0b\0\0\x11\x24\0\x03\x25\x3e\x0b\x0b\x0b\0\0\x12\x24\0\x03\x25\
\x0b\x0b\x3e\x0b\0\0\x13\x18\0\0\0\x14\x16\0\x49\x13\x03\x25\x3a\x0b\x3b\x0b\0\
\0\x15\x34\0\x03\x25\x49\x13\x3a\x0b\x3b\x05\0\0\x16\x34\0\x03\x25\x49\x13\x3f\
\x19\x3a\x0b\x3b\x0b\x02\x18\0\0\x17\x13\x01\x0b\x0b\x3a\x0b\x3b\x0b\0\0\x18\
\x0d\0\x03\x25\x49\x13\x3a\x0b\x3b\x0b\x38\x0b\0\0\x19\x04\x01\x49\x13\x03\x25\
\x0b\x0b\x3a\x0b\x3b\x05\0\0\x1a\x28\0\x03\x25\x1c\x0f\0\0\x1b\x13\x01\x03\x25\
\x0b\x0b\x3a\x0b\x3b\x05\0\0\x1c\x0d\0\x03\x25\x49\x13\x3a\x0b\x3b\x05\x38\x0b\
\0\0\0\x1e\x02\0\0\x05\0\x01\x08\0\0\0\0\x01\0\x1d\0\x01\x08\0\0\0\0\0\0\0\x02\
\x04\xb8\0\0\0\x08\0\0\0\x0c\0\0\0\x02\x03\x2f\0\0\0\x01\x40\x03\x34\0\0\0\x04\
\x39\0\0\0\x05\x49\0\0\0\x06\x49\0\0\0\x06\x4a\0\0\0\0\x07\x04\x4f\0\0\0\x08\
\x09\x04\xb8\0\0\0\x01\x5a\x1d\0\x24\x26\x01\0\0\x0a\x04\xab\0\0\0\0\x2b\x02\
\xa1\0\x02\x04\xab\0\0\0\0\x35\x0a\x04\x2a\x01\0\0\0\x3a\x02\xa1\x01\x0b\x20\0\
\x24\xd9\x01\0\0\x0c\x02\x91\x04\x13\0\x26\xf0\0\0\0\x0d\0\x1e\0\x27\xd4\x01\0\
\0\x0d\x01\x1f\0\x31\x26\x01\0\0\x0e\x28\0\x32\xf0\0\0\0\0\x0f\xb7\0\0\0\x10\
\xc0\0\0\0\x18\0\x03\xbc\0\0\0\x11\x05\x06\x01\x12\x06\x08\x07\x02\x07\xcc\0\0\
\0\x01\xb9\x03\xd1\0\0\0\x04\xd6\0\0\0\x05\xe7\0\0\0\x06\xeb\0\0\0\x06\xf0\0\0\
\0\x13\0\x11\x08\x05\x08\x04\xb7\0\0\0\x14\xf8\0\0\0\x0a\x02\x1b\x11\x09\x07\
\x04\x15\x0b\x05\x01\0\0\x01\xa9\x12\x03\x0a\x01\0\0\x04\x0f\x01\0\0\x05\x1a\
\x01\0\0\x06\x26\x01\0\0\0\x14\x22\x01\0\0\x0d\x02\x1f\x11\x0c\x07\x08\x11\x0e\
\x05\x04\x0f\xb7\0\0\0\x10\xc0\0\0\0\x30\0\x16\x0f\x41\x01\0\0\0\x3f\x02\xa1\
\x02\x0f\xbc\0\0\0\x10\xc0\0\0\0\x04\0\x16\x10\x58\x01\0\0\0\x1e\x02\xa1\x03\
\x17\x28\0\x18\x18\x11\x8a\x01\0\0\0\x19\0\x18\x12\x9b\x01\0\0\0\x1a\x08\x18\
\x13\xac\x01\0\0\0\x1b\x10\x18\x14\xb1\x01\0\0\0\x1c\x18\x18\x16\x9b\x01\0\0\0\
\x1d\x20\0\x04\x8f\x01\0\0\x0f\x26\x01\0\0\x10\xc0\0\0\0\x02\0\x04\xa0\x01\0\0\
\x0f\x26\x01\0\0\x10\xc0\0\0\0\x01\0\x04\xf0\0\0\0\x04\xb6\x01\0\0\x11\x15\x07\
\x08\x19\xf8\0\0\0\x1c\x04\x03\x27\x19\x1a\x17\0\x1a\x18\x01\x1a\x19\x02\x1a\
\x1a\x03\x1a\x1b\x04\0\x04\x1a\x01\0\0\x04\xde\x01\0\0\x1b\x27\x18\x03\x32\x19\
\x1c\x21\xf0\0\0\0\x03\x33\x19\0\x1c\x22\xf0\0\0\0\x03\x34\x19\x04\x1c\x23\xf0\
\0\0\0\x03\x35\x19\x08\x1c\x24\xf0\0\0\0\x03\x37\x19\x0c\x1c\x25\xf0\0\0\0\x03\
\x38\x19\x10\x1c\x26\xf0\0\0\0\x03\x3a\x19\x14\0\0\xa8\0\0\0\x05\0\0\0\0\0\0\0\
\x27\0\0\0\x36\0\0\0\x61\0\0\0\x75\0\0\0\x7d\0\0\0\x82\0\0\0\x96\0\0\0\xa7\0\0\
\0\xac\0\0\0\xb9\0\0\0\xbf\0\0\0\xce\0\0\0\xe1\0\0\0\xe7\0\0\0\xeb\0\0\0\xf3\0\
\0\0\xfb\0\0\0\0\x01\0\0\x0c\x01\0\0\x10\x01\0\0\x16\x01\0\0\x24\x01\0\0\x2c\
\x01\0\0\x38\x01\0\0\x41\x01\0\0\x4a\x01\0\0\x51\x01\0\0\x5e\x01\0\0\x69\x01\0\
\0\x72\x01\0\0\x76\x01\0\0\x7a\x01\0\0\x7e\x01\0\0\x83\x01\0\0\x8c\x01\0\0\x96\
\x01\0\0\xa6\x01\0\0\xb5\x01\0\0\xc4\x01\0\0\xcb\x01\0\0\x55\x62\x75\x6e\x74\
\x75\x20\x63\x6c\x61\x6e\x67\x20\x76\x65\x72\x73\x69\x6f\x6e\x20\x31\x38\x2e\
\x31\x2e\x33\x20\x28\x31\x75\x62\x75\x6e\x74\x75\x31\x29\0\x74\x65\x73\x74\x65\
\x5f\x74\x63\x2e\x62\x70\x66\x2e\x63\0\x2f\x68\x6f\x6d\x65\x2f\x75\x62\x75\x6e\
\x74\x75\x2f\x44\x6f\x63\x75\x6d\x65\x6e\x74\x73\x2f\x41\x72\x71\x75\x69\x74\
\x65\x74\x75\x72\x61\x2f\x73\x69\x67\x6e\x61\x6c\x73\0\x62\x70\x66\x5f\x6d\x61\
\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\x65\x6d\0\x5f\x5f\x5f\x5f\x66\x6d\
\x74\0\x63\x68\x61\x72\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\
\x54\x59\x50\x45\x5f\x5f\0\x62\x70\x66\x5f\x74\x72\x61\x63\x65\x5f\x70\x72\x69\
\x6e\x74\x6b\0\x6c\x6f\x6e\x67\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\
\x74\0\x5f\x5f\x75\x33\x32\0\x62\x70\x66\x5f\x6d\x69\x6e\x68\x61\x5f\x66\x75\
\x6e\x63\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\
\x67\0\x5f\x5f\x75\x36\x34\0\x69\x6e\x74\0\x4c\x49\x43\x45\x4e\x53\x45\0\x76\
\x61\x6c\x6f\x72\x65\x73\0\x74\x79\x70\x65\0\x6d\x61\x78\x5f\x65\x6e\x74\x72\
\x69\x65\x73\0\x6b\x65\x79\0\x76\x61\x6c\x75\x65\0\x75\x6e\x73\x69\x67\x6e\x65\
\x64\x20\x6c\x6f\x6e\x67\0\x70\x69\x6e\x6e\x69\x6e\x67\0\x58\x44\x50\x5f\x41\
\x42\x4f\x52\x54\x45\x44\0\x58\x44\x50\x5f\x44\x52\x4f\x50\0\x58\x44\x50\x5f\
\x50\x41\x53\x53\0\x58\x44\x50\x5f\x54\x58\0\x58\x44\x50\x5f\x52\x45\x44\x49\
\x52\x45\x43\x54\0\x78\x64\x70\x5f\x61\x63\x74\x69\x6f\x6e\0\x70\x65\x67\x61\
\x5f\x70\x6b\x74\0\x70\x74\x72\0\x70\x69\x64\0\x63\x74\x78\0\x64\x61\x74\x61\0\
\x64\x61\x74\x61\x5f\x65\x6e\x64\0\x64\x61\x74\x61\x5f\x6d\x65\x74\x61\0\x69\
\x6e\x67\x72\x65\x73\x73\x5f\x69\x66\x69\x6e\x64\x65\x78\0\x72\x78\x5f\x71\x75\
\x65\x75\x65\x5f\x69\x6e\x64\x65\x78\0\x65\x67\x72\x65\x73\x73\x5f\x69\x66\x69\
\x6e\x64\x65\x78\0\x78\x64\x70\x5f\x6d\x64\0\x74\x65\x6d\x70\0\x2c\0\0\0\x05\0\
\x08\0\0\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\x6c\x02\0\0\x6c\x02\0\0\x78\
\x02\0\0\0\0\0\0\0\0\0\x02\x03\0\0\0\x01\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\x01\
\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x02\0\0\0\x05\0\0\0\0\0\0\x01\
\x04\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\x02\x06\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\
\0\0\0\x04\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x02\x08\0\0\0\x19\0\0\0\0\0\0\x08\x09\
\0\0\0\x1f\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\x02\x0b\0\0\0\x2c\
\0\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\0\0\0\0\x05\0\0\x04\x28\0\0\0\x3a\0\0\0\
\x01\0\0\0\0\0\0\0\x3f\0\0\0\x05\0\0\0\x40\0\0\0\x4b\0\0\0\x07\0\0\0\x80\0\0\0\
\x4f\0\0\0\x0a\0\0\0\xc0\0\0\0\x55\0\0\0\x05\0\0\0\0\x01\0\0\x5d\0\0\0\0\0\0\
\x0e\x0c\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x02\x0f\0\0\0\x65\0\0\0\x06\0\0\x04\x18\
\0\0\0\x6c\0\0\0\x08\0\0\0\0\0\0\0\x71\0\0\0\x08\0\0\0\x20\0\0\0\x7a\0\0\0\x08\
\0\0\0\x40\0\0\0\x84\0\0\0\x08\0\0\0\x60\0\0\0\x94\0\0\0\x08\0\0\0\x80\0\0\0\
\xa3\0\0\0\x08\0\0\0\xa0\0\0\0\0\0\0\0\x01\0\0\x0d\x02\0\0\0\xb2\0\0\0\x0e\0\0\
\0\xb6\0\0\0\x01\0\0\x0c\x10\0\0\0\0\0\0\0\0\0\0\x0a\x13\0\0\0\x31\x02\0\0\0\0\
\0\x01\x01\0\0\0\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x12\0\0\0\x04\0\0\0\x18\
\0\0\0\x36\x02\0\0\0\0\0\x0e\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x12\0\
\0\0\x04\0\0\0\x30\0\0\0\x47\x02\0\0\0\0\0\x0e\x16\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x03\0\0\0\0\x13\0\0\0\x04\0\0\0\x04\0\0\0\x5a\x02\0\0\0\0\0\x0e\x18\0\0\0\x01\
\0\0\0\x62\x02\0\0\x01\0\0\x0f\0\0\0\0\x0d\0\0\0\0\0\0\0\x28\0\0\0\x68\x02\0\0\
\x02\0\0\x0f\0\0\0\0\x15\0\0\0\0\0\0\0\x18\0\0\0\x17\0\0\0\x18\0\0\0\x30\0\0\0\
\x70\x02\0\0\x01\0\0\x0f\0\0\0\0\x19\0\0\0\0\0\0\0\x04\0\0\0\0\x69\x6e\x74\0\
\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\
\x5f\x5f\x75\x33\x32\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x75\
\x6e\x73\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\0\x74\x79\x70\x65\0\x6d\x61\
\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\0\x6b\x65\x79\0\x76\x61\x6c\x75\x65\0\x70\
\x69\x6e\x6e\x69\x6e\x67\0\x76\x61\x6c\x6f\x72\x65\x73\0\x78\x64\x70\x5f\x6d\
\x64\0\x64\x61\x74\x61\0\x64\x61\x74\x61\x5f\x65\x6e\x64\0\x64\x61\x74\x61\x5f\
\x6d\x65\x74\x61\0\x69\x6e\x67\x72\x65\x73\x73\x5f\x69\x66\x69\x6e\x64\x65\x78\
\0\x72\x78\x5f\x71\x75\x65\x75\x65\x5f\x69\x6e\x64\x65\x78\0\x65\x67\x72\x65\
\x73\x73\x5f\x69\x66\x69\x6e\x64\x65\x78\0\x63\x74\x78\0\x70\x65\x67\x61\x5f\
\x70\x6b\x74\0\x78\x64\x70\0\x2f\x68\x6f\x6d\x65\x2f\x75\x62\x75\x6e\x74\x75\
\x2f\x44\x6f\x63\x75\x6d\x65\x6e\x74\x73\x2f\x41\x72\x71\x75\x69\x74\x65\x74\
\x75\x72\x61\x2f\x73\x69\x67\x6e\x61\x6c\x73\x2f\x74\x65\x73\x74\x65\x5f\x74\
\x63\x2e\x62\x70\x66\x2e\x63\0\x69\x6e\x74\x20\x70\x65\x67\x61\x5f\x70\x6b\x74\
\x28\x73\x74\x72\x75\x63\x74\x20\x78\x64\x70\x5f\x6d\x64\x20\x2a\x63\x74\x78\
\x29\x20\x7b\0\x20\x20\x20\x20\x5f\x5f\x75\x33\x32\x20\x6b\x65\x79\x20\x3d\x20\
\x30\x3b\0\x20\x20\x20\x20\x70\x74\x72\x20\x3d\x20\x20\x62\x70\x66\x5f\x6d\x61\
\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\x65\x6d\x28\x20\x26\x76\x61\x6c\
\x6f\x72\x65\x73\x2c\x20\x26\x6b\x65\x79\x29\x3b\0\x20\x20\x20\x20\x69\x66\x28\
\x70\x74\x72\x20\x3d\x3d\x20\x4e\x55\x4c\x4c\x20\x29\x7b\0\x20\x20\x20\x20\x20\
\x20\x20\x20\x62\x70\x66\x5f\x70\x72\x69\x6e\x74\x6b\x28\x22\x45\x72\x72\x6f\
\x20\x6e\x6f\x20\x6c\x6f\x6f\x6b\x75\x70\x20\x64\x6f\x20\x6d\x61\x70\x61\x5c\
\x6e\x22\x29\x3b\0\x20\x20\x20\x20\x69\x6e\x74\x20\x70\x69\x64\x20\x3d\x20\x2a\
\x70\x74\x72\x3b\0\x20\x20\x20\x20\x5f\x5f\x75\x33\x32\x20\x74\x65\x6d\x70\x20\
\x3d\x20\x62\x70\x66\x5f\x6d\x69\x6e\x68\x61\x5f\x66\x75\x6e\x63\x28\x70\x69\
\x64\x29\x3b\0\x20\x20\x20\x20\x62\x70\x66\x5f\x70\x72\x69\x6e\x74\x6b\x28\x22\
\x45\x53\x54\x41\x20\x43\x41\x50\x54\x41\x4e\x44\x4f\x20\x50\x4b\x54\x53\x21\
\x21\x21\x20\x76\x61\x6c\x6f\x72\x20\x64\x6f\x20\x70\x69\x64\x2c\x20\x6d\x61\
\x70\x61\x2d\x2d\x3e\x20\x25\x64\x5c\x6e\x22\x2c\x20\x20\x2a\x70\x74\x72\x29\
\x3b\0\x7d\0\x63\x68\x61\x72\0\x70\x65\x67\x61\x5f\x70\x6b\x74\x2e\x5f\x5f\x5f\
\x5f\x66\x6d\x74\0\x70\x65\x67\x61\x5f\x70\x6b\x74\x2e\x5f\x5f\x5f\x5f\x66\x6d\
\x74\x2e\x32\0\x4c\x49\x43\x45\x4e\x53\x45\0\x2e\x6d\x61\x70\x73\0\x2e\x72\x6f\
\x64\x61\x74\x61\0\x6c\x69\x63\x65\x6e\x73\x65\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\
\0\x14\0\0\0\x14\0\0\0\x9c\0\0\0\xb0\0\0\0\0\0\0\0\x08\0\0\0\xbf\0\0\0\x01\0\0\
\0\0\0\0\0\x11\0\0\0\x10\0\0\0\xbf\0\0\0\x09\0\0\0\0\0\0\0\xc3\0\0\0\xfd\0\0\0\
\0\x90\0\0\x08\0\0\0\xc3\0\0\0\x20\x01\0\0\x0b\x98\0\0\x20\0\0\0\xc3\0\0\0\x33\
\x01\0\0\x0c\xa4\0\0\x38\0\0\0\xc3\0\0\0\x64\x01\0\0\x08\xa8\0\0\x40\0\0\0\xc3\
\0\0\0\x7a\x01\0\0\x09\xac\0\0\x68\0\0\0\xc3\0\0\0\xaa\x01\0\0\x0f\xc4\0\0\x78\
\0\0\0\xc3\0\0\0\xbe\x01\0\0\x12\xc8\0\0\x80\0\0\0\xc3\0\0\0\xe4\x01\0\0\x05\
\xe8\0\0\xa8\0\0\0\xc3\0\0\0\x2f\x02\0\0\x01\xf4\0\0\0\0\0\0\x0c\0\0\0\xff\xff\
\xff\xff\x04\0\x08\0\x08\x7c\x0b\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb8\0\0\0\
\0\0\0\0\xc6\0\0\0\x05\0\x08\0\x82\0\0\0\x08\x01\x01\xfb\x0e\x0d\0\x01\x01\x01\
\x01\0\0\0\x01\0\0\x01\x01\x01\x1f\x04\0\0\0\0\x2b\0\0\0\x3c\0\0\0\x55\0\0\0\
\x03\x01\x1f\x02\x0f\x05\x1e\x04\x68\0\0\0\0\x61\xd3\x1a\xe5\x92\xa2\xce\xb4\
\xf3\xab\x4b\xde\x38\x70\x2c\x2b\x77\0\0\0\x01\x23\x79\x0f\xa8\x65\xc0\xb6\x47\
\xa0\x63\xaa\x3a\x37\xbd\x90\x78\x89\0\0\0\x02\xb8\x10\xf2\x70\x73\x3e\x10\x63\
\x19\xb6\x7e\xf5\x12\xc6\x24\x6e\x94\0\0\0\x03\xc7\x0f\x42\x66\xb0\xcf\xb8\xac\
\xf5\xb7\xb1\xf7\x93\x87\x5b\x0a\x04\0\0\x09\x02\0\0\0\0\0\0\0\0\x03\x23\x01\
\x05\x0b\x0a\x22\x05\x0c\x3f\x05\x08\x3d\x05\x09\x21\x06\x03\x55\x4a\x05\x0f\
\x06\x03\x31\x20\x06\x03\x4f\x20\x05\x12\x06\x03\x32\x20\x05\x05\x28\x05\x01\
\x5b\x02\x02\0\x01\x01\x2f\x68\x6f\x6d\x65\x2f\x75\x62\x75\x6e\x74\x75\x2f\x44\
\x6f\x63\x75\x6d\x65\x6e\x74\x73\x2f\x41\x72\x71\x75\x69\x74\x65\x74\x75\x72\
\x61\x2f\x73\x69\x67\x6e\x61\x6c\x73\0\x2f\x75\x73\x72\x2f\x69\x6e\x63\x6c\x75\
\x64\x65\x2f\x62\x70\x66\0\x2f\x75\x73\x72\x2f\x69\x6e\x63\x6c\x75\x64\x65\x2f\
\x61\x73\x6d\x2d\x67\x65\x6e\x65\x72\x69\x63\0\x2f\x75\x73\x72\x2f\x69\x6e\x63\
\x6c\x75\x64\x65\x2f\x6c\x69\x6e\x75\x78\0\x74\x65\x73\x74\x65\x5f\x74\x63\x2e\
\x62\x70\x66\x2e\x63\0\x62\x70\x66\x5f\x68\x65\x6c\x70\x65\x72\x5f\x64\x65\x66\
\x73\x2e\x68\0\x69\x6e\x74\x2d\x6c\x6c\x36\x34\x2e\x68\0\x62\x70\x66\x2e\x68\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xeb\0\0\0\x04\0\xf1\
\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x2a\x01\0\0\0\0\x03\0\x68\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x22\0\0\0\
\x01\0\x06\0\0\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0\x23\x01\0\0\0\0\x03\0\xa8\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x31\x01\0\0\x01\0\x06\0\x18\0\0\0\0\0\0\0\x30\0\0\0\0\
\0\0\0\0\0\0\0\x03\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x08\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x03\0\x0c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0e\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0f\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x03\0\x15\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x17\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x19\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x33\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\xb8\0\0\0\0\0\0\0\x69\0\0\0\x11\0\
\x05\0\0\0\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\x1b\x01\0\0\x11\0\x07\0\0\0\0\0\0\0\0\
\0\x04\0\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x01\0\0\0\x11\0\0\0\x40\0\0\0\0\0\0\0\
\x01\0\0\0\x07\0\0\0\x88\0\0\0\0\0\0\0\x01\0\0\0\x07\0\0\0\x08\0\0\0\0\0\0\0\
\x03\0\0\0\x09\0\0\0\x11\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x15\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x1f\0\0\0\0\0\0\0\x03\0\0\0\x0c\0\0\0\x23\0\0\0\0\0\0\0\
\x03\0\0\0\x08\0\0\0\x08\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x0c\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x10\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x14\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x18\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x1c\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x20\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x24\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x28\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x2c\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x30\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x34\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x38\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x3c\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x40\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x44\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x48\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x4c\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x50\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x54\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x58\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x5c\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x60\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x64\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x68\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x6c\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x70\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x74\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x78\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x7c\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x80\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x84\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x88\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x8c\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x90\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x94\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x98\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x9c\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\xa0\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\xa4\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\xa8\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x08\0\0\0\0\0\0\0\
\x02\0\0\0\x07\0\0\0\x10\0\0\0\0\0\0\0\x02\0\0\0\x07\0\0\0\x18\0\0\0\0\0\0\0\
\x02\0\0\0\x12\0\0\0\x20\0\0\0\0\0\0\0\x02\0\0\0\x11\0\0\0\x28\0\0\0\0\0\0\0\
\x02\0\0\0\x02\0\0\0\x40\x02\0\0\0\0\0\0\x04\0\0\0\x11\0\0\0\x58\x02\0\0\0\0\0\
\0\x03\0\0\0\x07\0\0\0\x64\x02\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x7c\x02\0\0\0\0\
\0\0\x04\0\0\0\x12\0\0\0\x2c\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x40\0\0\0\0\0\0\
\0\x04\0\0\0\x02\0\0\0\x50\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x60\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x70\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x80\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x90\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xa0\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\xb0\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xc0\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x14\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x18\0\0\0\0\0\0\0\
\x02\0\0\0\x02\0\0\0\x22\0\0\0\0\0\0\0\x03\0\0\0\x0f\0\0\0\x26\0\0\0\0\0\0\0\
\x03\0\0\0\x0f\0\0\0\x2a\0\0\0\0\0\0\0\x03\0\0\0\x0f\0\0\0\x2e\0\0\0\0\0\0\0\
\x03\0\0\0\x0f\0\0\0\x3a\0\0\0\0\0\0\0\x03\0\0\0\x0f\0\0\0\x4f\0\0\0\0\0\0\0\
\x03\0\0\0\x0f\0\0\0\x64\0\0\0\0\0\0\0\x03\0\0\0\x0f\0\0\0\x79\0\0\0\0\0\0\0\
\x03\0\0\0\x0f\0\0\0\x93\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\x10\x11\x04\x06\x12\
\0\x2e\x64\x65\x62\x75\x67\x5f\x61\x62\x62\x72\x65\x76\0\x2e\x74\x65\x78\x74\0\
\x2e\x72\x65\x6c\x2e\x42\x54\x46\x2e\x65\x78\x74\0\x70\x65\x67\x61\x5f\x70\x6b\
\x74\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x70\x65\x67\x61\x5f\x70\x6b\x74\0\x2e\
\x64\x65\x62\x75\x67\x5f\x6c\x6f\x63\x6c\x69\x73\x74\x73\0\x2e\x72\x65\x6c\x2e\
\x64\x65\x62\x75\x67\x5f\x73\x74\x72\x5f\x6f\x66\x66\x73\x65\x74\x73\0\x2e\x6d\
\x61\x70\x73\0\x76\x61\x6c\x6f\x72\x65\x73\0\x2e\x64\x65\x62\x75\x67\x5f\x73\
\x74\x72\0\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\x5f\x73\x74\x72\0\x2e\
\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x61\x64\x64\x72\0\x2e\x72\x65\x6c\x78\
\x64\x70\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x69\x6e\x66\x6f\0\x2e\
\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\0\x6c\x69\x63\x65\x6e\x73\x65\
\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\0\x2e\x72\x65\
\x6c\x2e\x64\x65\x62\x75\x67\x5f\x66\x72\x61\x6d\x65\0\x74\x65\x73\x74\x65\x5f\
\x74\x63\x2e\x62\x70\x66\x2e\x63\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\
\x6d\x74\x61\x62\0\x2e\x72\x6f\x64\x61\x74\x61\0\x2e\x72\x65\x6c\x2e\x42\x54\
\x46\0\x4c\x49\x43\x45\x4e\x53\x45\0\x4c\x42\x42\x30\x5f\x33\0\x4c\x42\x42\x30\
\x5f\x32\0\x70\x65\x67\x61\x5f\x70\x6b\x74\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\x2e\
\x32\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xfa\0\0\
\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd5\x15\0\0\0\0\0\0\x44\x01\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0f\0\0\0\x01\0\0\0\
\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa0\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\xb8\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x9c\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xe0\x10\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x1b\0\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\
\x10\0\0\0\0\0\0\0\x63\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf8\0\
\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x0a\x01\0\0\x01\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x20\x01\0\0\0\0\0\0\
\x48\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc2\0\0\0\
\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x68\x01\0\0\0\0\0\0\x04\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x3c\0\0\0\x01\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x6c\x01\0\0\0\0\0\0\x27\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x93\x01\0\0\0\0\0\0\x54\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\xa8\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xe7\x02\0\0\0\0\0\0\x22\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\xa4\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x10\x11\0\0\
\0\0\0\0\x50\0\0\0\0\0\0\0\x1b\0\0\0\x0a\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\
\0\0\x50\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x09\x05\0\0\0\0\0\0\
\xac\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x4c\0\0\0\
\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x60\x11\0\0\0\0\0\0\x90\x02\0\0\0\
\0\0\0\x1b\0\0\0\x0c\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x71\0\0\0\x01\0\
\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb5\x05\0\0\0\0\0\0\xd0\x01\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x90\0\0\0\x01\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\x07\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x8c\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\xf0\x13\0\0\0\0\0\0\x50\0\0\0\0\0\0\0\x1b\0\0\0\x0f\0\0\0\x08\0\0\
\0\0\0\0\0\x10\0\0\0\0\0\0\0\x16\x01\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\xb8\x07\0\0\0\0\0\0\xfc\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x12\x01\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\
\x14\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x1b\0\0\0\x11\0\0\0\x08\0\0\0\0\0\0\0\x10\0\
\0\0\0\0\0\0\x19\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb4\x0c\0\0\0\
\0\0\0\xd0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x15\
\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x80\x14\0\0\0\0\0\0\xa0\0\0\
\0\0\0\0\0\x1b\0\0\0\x13\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xde\0\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x88\x0d\0\0\0\0\0\0\x28\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xda\0\0\0\x09\0\0\0\x40\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x20\x15\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x1b\0\0\0\
\x15\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xce\0\0\0\x01\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\xb0\x0d\0\0\0\0\0\0\xca\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xca\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x40\x15\0\0\0\0\0\0\x90\0\0\0\0\0\0\0\x1b\0\0\0\x17\0\0\0\x08\0\0\0\0\0\
\0\0\x10\0\0\0\0\0\0\0\x7c\0\0\0\x01\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x7a\x0e\0\0\0\0\0\0\x9a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\
\0\0\0\0\0\0\xb4\0\0\0\x03\x4c\xff\x6f\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\xd0\
\x15\0\0\0\0\0\0\x05\0\0\0\0\0\0\0\x1b\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x02\x01\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x18\x0f\0\0\0\0\
\0\0\xc8\x01\0\0\0\0\0\0\x01\0\0\0\x10\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\
\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct teste_tc_bpf *teste_tc_bpf::open(const struct bpf_object_open_opts *opts) { return teste_tc_bpf__open_opts(opts); }
struct teste_tc_bpf *teste_tc_bpf::open_and_load() { return teste_tc_bpf__open_and_load(); }
int teste_tc_bpf::load(struct teste_tc_bpf *skel) { return teste_tc_bpf__load(skel); }
int teste_tc_bpf::attach(struct teste_tc_bpf *skel) { return teste_tc_bpf__attach(skel); }
void teste_tc_bpf::detach(struct teste_tc_bpf *skel) { teste_tc_bpf__detach(skel); }
void teste_tc_bpf::destroy(struct teste_tc_bpf *skel) { teste_tc_bpf__destroy(skel); }
const void *teste_tc_bpf::elf_bytes(size_t *sz) { return teste_tc_bpf__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
teste_tc_bpf__assert(struct teste_tc_bpf *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __TESTE_TC_BPF_SKEL_H__ */
