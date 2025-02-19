/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __TESTE_TC_SKEL_H__
#define __TESTE_TC_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct teste_tc {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *rodata_str1_1;
	} maps;
	struct {
		struct bpf_program *pega_pkt;
	} progs;
	struct {
		struct bpf_link *pega_pkt;
	} links;

#ifdef __cplusplus
	static inline struct teste_tc *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct teste_tc *open_and_load();
	static inline int load(struct teste_tc *skel);
	static inline int attach(struct teste_tc *skel);
	static inline void detach(struct teste_tc *skel);
	static inline void destroy(struct teste_tc *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
teste_tc__destroy(struct teste_tc *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
teste_tc__create_skeleton(struct teste_tc *obj);

static inline struct teste_tc *
teste_tc__open_opts(const struct bpf_object_open_opts *opts)
{
	struct teste_tc *obj;
	int err;

    printf("-->Entrou no open_opts\n");

	obj = (struct teste_tc *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = teste_tc__create_skeleton(obj);
	if (err){
	    printf("-->Erro ao chamar teste_tc__create_skeleton\n");
        goto err_out;
    }

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err){
		printf("-->Erro ao chamar bpf_object__open_skeleton()\n");
        perror("AQUIII O ERRO:");
        goto err_out;
    }

	return obj;
err_out:
	teste_tc__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct teste_tc *
teste_tc__open(void)
{
    printf("-->Entrou no __open\n");
	return teste_tc__open_opts(NULL);
}

static inline int
teste_tc__load(struct teste_tc *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct teste_tc *
teste_tc__open_and_load(void)
{
	struct teste_tc *obj;
	int err;
    
    printf("-->Entrou open_and_load\n");

	obj = teste_tc__open();
	if (!obj)
		return NULL;
	err = teste_tc__load(obj);
	if (err) {
		teste_tc__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
teste_tc__attach(struct teste_tc *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
teste_tc__detach(struct teste_tc *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *teste_tc__elf_bytes(size_t *sz);

static inline int
teste_tc__create_skeleton(struct teste_tc *obj)
{
	struct bpf_object_skeleton *s;
	int err;

    printf("-->Entrou no create_skeleton\n");

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "teste_tc";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 1;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	s->maps[0].name = ".rodata.str1.1";
	s->maps[0].map = &obj->maps.rodata_str1_1;

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

	s->data = teste_tc__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *teste_tc__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x20\x1c\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x1a\0\
\x01\0\xb7\x01\0\0\x21\x0a\0\0\x6b\x1a\xfc\xff\0\0\0\0\xb7\x01\0\0\x54\x53\x21\
\x21\x63\x1a\xf8\xff\0\0\0\0\x18\x01\0\0\x54\x41\x4e\x44\0\0\0\0\x4f\x20\x50\
\x4b\x7b\x1a\xf0\xff\0\0\0\0\x18\x01\0\0\x45\x53\x54\x41\0\0\0\0\x20\x43\x41\
\x50\x7b\x1a\xe8\xff\0\0\0\0\xb7\x01\0\0\0\0\0\0\x73\x1a\xfe\xff\0\0\0\0\xbf\
\xa1\0\0\0\0\0\0\x07\x01\0\0\xe8\xff\xff\xff\xb7\x02\0\0\x17\0\0\0\x85\0\0\0\
\x06\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x45\x53\x54\x41\x20\x43\x41\x50\
\x54\x41\x4e\x44\x4f\x20\x50\x4b\x54\x53\x21\x21\x21\x0a\0\x47\x50\x4c\0\x01\
\x11\x01\x25\x25\x13\x05\x03\x25\x72\x17\x10\x17\x1b\x25\x11\x1b\x12\x06\x73\
\x17\x74\x17\0\0\x02\x34\0\x03\x25\x49\x13\x3f\x19\x3a\x0b\x3b\x0b\x02\x18\0\0\
\x03\x01\x01\x49\x13\0\0\x04\x21\0\x49\x13\x37\x0b\0\0\x05\x24\0\x03\x25\x3e\
\x0b\x0b\x0b\0\0\x06\x24\0\x03\x25\x0b\x0b\x3e\x0b\0\0\x07\x34\0\x03\x25\x49\
\x13\x3a\x0b\x3b\x0b\0\0\x08\x0f\0\x49\x13\0\0\x09\x15\x01\x49\x13\x27\x19\0\0\
\x0a\x05\0\x49\x13\0\0\x0b\x18\0\0\0\x0c\x26\0\x49\x13\0\0\x0d\x16\0\x49\x13\
\x03\x25\x3a\x0b\x3b\x0b\0\0\x0e\x2e\x01\x11\x1b\x12\x06\x40\x18\x7a\x19\x03\
\x25\x3a\x0b\x3b\x0b\x27\x19\x49\x13\x3f\x19\0\0\x0f\x05\0\x03\x25\x3a\x0b\x3b\
\x0b\x49\x13\0\0\x10\x0b\x01\x55\x23\0\0\x11\x34\0\x02\x18\x03\x25\x3a\x0b\x3b\
\x0b\x49\x13\0\0\x12\x13\x01\x03\x25\x0b\x0b\x3a\x0b\x3b\x05\0\0\x13\x0d\0\x03\
\x25\x49\x13\x3a\x0b\x3b\x05\x38\x0b\0\0\x14\x0d\0\x49\x13\x3a\x0b\x3b\x05\x88\
\x01\x0f\x38\x0b\0\0\x15\x17\x01\x0b\x0b\x3a\x0b\x3b\x05\x88\x01\x0f\0\0\x16\
\x0d\0\x49\x13\x3a\x0b\x3b\x05\x38\x0b\0\0\x17\x17\x01\x0b\x0b\x3a\x0b\x3b\x05\
\0\0\x18\x13\x01\x0b\x0b\x3a\x0b\x3b\x05\0\0\0\xe4\x03\0\0\x05\0\x01\x08\0\0\0\
\0\x01\0\x0c\0\x01\x08\0\0\0\0\0\0\0\x02\x01\x90\0\0\0\x08\0\0\0\x0c\0\0\0\x02\
\x03\x32\0\0\0\0\x23\x02\xa1\0\x03\x3e\0\0\0\x04\x42\0\0\0\x04\0\x05\x04\x06\
\x01\x06\x05\x08\x07\x07\x06\x4e\0\0\0\x02\xab\x08\x53\0\0\0\x09\x64\0\0\0\x0a\
\x68\0\0\0\x0a\x72\0\0\0\x0b\0\x05\x07\x05\x08\x08\x6d\0\0\0\x0c\x3e\0\0\0\x0d\
\x7a\0\0\0\x09\x01\x1b\x05\x08\x07\x04\x0e\x01\x90\0\0\0\x01\x5a\x0a\0\x19\xa4\
\0\0\0\x0f\x0d\0\x19\xb4\0\0\0\x10\0\x11\x02\x91\0\x0c\0\x1e\xa8\0\0\0\0\0\x05\
\x0b\x05\x04\x03\x3e\0\0\0\x04\x42\0\0\0\x17\0\x08\xb9\0\0\0\x12\x53\xb8\x03\
\x95\x14\x13\x0e\x72\0\0\0\x03\x96\x14\0\x13\x0f\x72\0\0\0\x03\x97\x14\x04\x13\
\x10\x72\0\0\0\x03\x98\x14\x08\x13\x11\x72\0\0\0\x03\x99\x14\x0c\x13\x12\x72\0\
\0\0\x03\x9a\x14\x10\x13\x13\x72\0\0\0\x03\x9b\x14\x14\x13\x14\x72\0\0\0\x03\
\x9c\x14\x18\x13\x15\x72\0\0\0\x03\x9d\x14\x1c\x13\x16\x72\0\0\0\x03\x9e\x14\
\x20\x13\x17\x72\0\0\0\x03\x9f\x14\x24\x13\x18\x72\0\0\0\x03\xa0\x14\x28\x13\
\x19\x72\0\0\0\x03\xa1\x14\x2c\x13\x1a\x22\x02\0\0\x03\xa2\x14\x30\x13\x1b\x72\
\0\0\0\x03\xa3\x14\x44\x13\x1c\x72\0\0\0\x03\xa4\x14\x48\x13\x1d\x72\0\0\0\x03\
\xa5\x14\x4c\x13\x1e\x72\0\0\0\x03\xa6\x14\x50\x13\x1f\x72\0\0\0\x03\xa7\x14\
\x54\x13\x20\x72\0\0\0\x03\xaa\x14\x58\x13\x21\x72\0\0\0\x03\xab\x14\x5c\x13\
\x22\x72\0\0\0\x03\xac\x14\x60\x13\x23\x2e\x02\0\0\x03\xad\x14\x64\x13\x24\x2e\
\x02\0\0\x03\xae\x14\x74\x13\x25\x72\0\0\0\x03\xaf\x14\x84\x13\x26\x72\0\0\0\
\x03\xb0\x14\x88\x13\x27\x72\0\0\0\x03\xb3\x14\x8c\x14\xcd\x01\0\0\x03\xb4\x14\
\x08\x90\x15\x08\x03\xb4\x14\x08\x13\x28\x3a\x02\0\0\x03\xb4\x14\0\0\x13\x40\
\x3b\x03\0\0\x03\xb5\x14\x98\x13\x43\x72\0\0\0\x03\xb6\x14\xa0\x13\x44\x72\0\0\
\0\x03\xb7\x14\xa4\x14\x06\x02\0\0\x03\xb8\x14\x08\xa8\x15\x08\x03\xb8\x14\x08\
\x13\x45\x47\x03\0\0\x03\xb8\x14\0\0\x13\x52\x72\0\0\0\x03\xb9\x14\xb0\0\x03\
\x72\0\0\0\x04\x42\0\0\0\x05\0\x03\x72\0\0\0\x04\x42\0\0\0\x04\0\x08\x3f\x02\0\
\0\x12\x3f\x38\x03\x21\x18\x13\x29\x13\x03\0\0\x03\x22\x18\0\x13\x2c\x13\x03\0\
\0\x03\x23\x18\x02\x13\x2d\x13\x03\0\0\x03\x24\x18\x04\x13\x2e\x1f\x03\0\0\x03\
\x25\x18\x06\x13\x31\x1f\x03\0\0\x03\x26\x18\x07\x13\x32\x1f\x03\0\0\x03\x27\
\x18\x08\x13\x33\x1f\x03\0\0\x03\x28\x18\x09\x13\x34\x2b\x03\0\0\x03\x29\x18\
\x0a\x13\x36\x2b\x03\0\0\x03\x2a\x18\x0c\x13\x37\x2b\x03\0\0\x03\x2b\x18\x0e\
\x16\xb2\x02\0\0\x03\x2c\x18\x10\x17\x20\x03\x2c\x18\x16\xc0\x02\0\0\x03\x2d\
\x18\0\x18\x08\x03\x2d\x18\x13\x38\x33\x03\0\0\x03\x2e\x18\0\x13\x3a\x33\x03\0\
\0\x03\x2f\x18\x04\0\x16\xe3\x02\0\0\x03\x31\x18\0\x18\x20\x03\x31\x18\x13\x3b\
\x2e\x02\0\0\x03\x32\x18\0\x13\x3c\x2e\x02\0\0\x03\x33\x18\x10\0\0\x13\x3d\x72\
\0\0\0\x03\x36\x18\x30\x13\x3e\x33\x03\0\0\x03\x37\x18\x34\0\x0d\x1b\x03\0\0\
\x2b\x01\x18\x05\x2a\x07\x02\x0d\x27\x03\0\0\x30\x01\x15\x05\x2f\x08\x01\x0d\
\x13\x03\0\0\x35\x04\x19\x0d\x72\0\0\0\x39\x04\x1b\x0d\x43\x03\0\0\x42\x01\x1f\
\x05\x41\x07\x08\x08\x4c\x03\0\0\x12\x51\x50\x03\xee\x14\x13\x46\x72\0\0\0\x03\
\xef\x14\0\x13\x20\x72\0\0\0\x03\xf0\x14\x04\x13\x47\x72\0\0\0\x03\xf1\x14\x08\
\x13\x12\x72\0\0\0\x03\xf2\x14\x0c\x13\x10\x72\0\0\0\x03\xf3\x14\x10\x13\x16\
\x72\0\0\0\x03\xf4\x14\x14\x13\x48\x72\0\0\0\x03\xf6\x14\x18\x13\x49\x2e\x02\0\
\0\x03\xf7\x14\x1c\x13\x4a\x72\0\0\0\x03\xf8\x14\x2c\x13\x4b\x2b\x03\0\0\x03\
\xf9\x14\x30\x13\x4c\x72\0\0\0\x03\xfb\x14\x34\x13\x4d\x2e\x02\0\0\x03\xfc\x14\
\x38\x13\x4e\x72\0\0\0\x03\xfd\x14\x48\x13\x4f\xdf\x03\0\0\x03\xfe\x14\x4c\0\
\x0d\xa4\0\0\0\x50\x01\x1a\0\x14\0\0\0\x05\0\x08\0\x01\0\0\0\x04\0\0\0\x04\x08\
\x68\x04\x70\x80\x01\0\x54\x01\0\0\x05\0\0\0\0\0\0\0\x27\0\0\0\x32\0\0\0\xa2\0\
\0\0\xaa\0\0\0\xaf\0\0\0\xc3\0\0\0\xd4\0\0\0\xd9\0\0\0\xe6\0\0\0\xec\0\0\0\xf5\
\0\0\0\xf9\0\0\0\x01\x01\0\0\x05\x01\0\0\x09\x01\0\0\x12\x01\0\0\x17\x01\0\0\
\x25\x01\0\0\x2e\x01\0\0\x3b\x01\0\0\x44\x01\0\0\x4f\x01\0\0\x58\x01\0\0\x68\
\x01\0\0\x70\x01\0\0\x79\x01\0\0\x7c\x01\0\0\x81\x01\0\0\x8c\x01\0\0\x91\x01\0\
\0\x9a\x01\0\0\xa2\x01\0\0\xa9\x01\0\0\xb4\x01\0\0\xbe\x01\0\0\xc9\x01\0\0\xd3\
\x01\0\0\xdf\x01\0\0\xea\x01\0\0\xf4\x01\0\0\xfe\x01\0\0\x04\x02\0\0\x13\x02\0\
\0\x19\x02\0\0\x1f\x02\0\0\x2a\x02\0\0\x32\x02\0\0\x40\x02\0\0\x45\x02\0\0\x53\
\x02\0\0\x5c\x02\0\0\x65\x02\0\0\x6d\x02\0\0\x74\x02\0\0\x7a\x02\0\0\x80\x02\0\
\0\x89\x02\0\0\x90\x02\0\0\x99\x02\0\0\xa2\x02\0\0\xab\x02\0\0\xb1\x02\0\0\xbc\
\x02\0\0\xca\x02\0\0\xd1\x02\0\0\xe4\x02\0\0\xea\x02\0\0\xf3\x02\0\0\xfc\x02\0\
\0\xff\x02\0\0\x0c\x03\0\0\x11\x03\0\0\x19\x03\0\0\x21\x03\0\0\x2a\x03\0\0\x33\
\x03\0\0\x3b\x03\0\0\x43\x03\0\0\x49\x03\0\0\x5a\x03\0\0\x60\x03\0\0\x69\x03\0\
\0\x72\x03\0\0\x55\x62\x75\x6e\x74\x75\x20\x63\x6c\x61\x6e\x67\x20\x76\x65\x72\
\x73\x69\x6f\x6e\x20\x31\x34\x2e\x30\x2e\x30\x2d\x31\x75\x62\x75\x6e\x74\x75\
\x31\x2e\x31\0\x74\x65\x73\x74\x65\x5f\x74\x63\x2e\x63\0\x2f\x68\x6f\x6d\x65\
\x2f\x72\x69\x63\x61\x72\x64\x6f\x2f\x44\x6f\x63\x75\x6d\x65\x6e\x74\x73\x2f\
\x4d\x65\x73\x74\x72\x61\x64\x6f\x2f\x50\x72\x6f\x6a\x65\x74\x6f\x2d\x4d\x65\
\x73\x74\x72\x61\x64\x6f\x2f\x50\x72\x6f\x6a\x65\x74\x6f\x5f\x65\x42\x50\x46\
\x2f\x63\x6f\x64\x69\x67\x6f\x73\x5f\x65\x42\x50\x46\x2f\x63\x6f\x64\x69\x67\
\x6f\x5f\x70\x72\x6f\x70\x6f\x73\x74\x61\x2f\x41\x72\x71\x75\x69\x74\x65\x74\
\x75\x72\x61\x2f\x73\x69\x67\x6e\x61\x6c\x73\0\x4c\x49\x43\x45\x4e\x53\x45\0\
\x63\x68\x61\x72\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\
\x50\x45\x5f\x5f\0\x62\x70\x66\x5f\x74\x72\x61\x63\x65\x5f\x70\x72\x69\x6e\x74\
\x6b\0\x6c\x6f\x6e\x67\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x5f\
\x5f\x75\x33\x32\0\x70\x65\x67\x61\x5f\x70\x6b\x74\0\x69\x6e\x74\0\x5f\x5f\x5f\
\x5f\x66\x6d\x74\0\x63\x74\x78\0\x6c\x65\x6e\0\x70\x6b\x74\x5f\x74\x79\x70\x65\
\0\x6d\x61\x72\x6b\0\x71\x75\x65\x75\x65\x5f\x6d\x61\x70\x70\x69\x6e\x67\0\x70\
\x72\x6f\x74\x6f\x63\x6f\x6c\0\x76\x6c\x61\x6e\x5f\x70\x72\x65\x73\x65\x6e\x74\
\0\x76\x6c\x61\x6e\x5f\x74\x63\x69\0\x76\x6c\x61\x6e\x5f\x70\x72\x6f\x74\x6f\0\
\x70\x72\x69\x6f\x72\x69\x74\x79\0\x69\x6e\x67\x72\x65\x73\x73\x5f\x69\x66\x69\
\x6e\x64\x65\x78\0\x69\x66\x69\x6e\x64\x65\x78\0\x74\x63\x5f\x69\x6e\x64\x65\
\x78\0\x63\x62\0\x68\x61\x73\x68\0\x74\x63\x5f\x63\x6c\x61\x73\x73\x69\x64\0\
\x64\x61\x74\x61\0\x64\x61\x74\x61\x5f\x65\x6e\x64\0\x6e\x61\x70\x69\x5f\x69\
\x64\0\x66\x61\x6d\x69\x6c\x79\0\x72\x65\x6d\x6f\x74\x65\x5f\x69\x70\x34\0\x6c\
\x6f\x63\x61\x6c\x5f\x69\x70\x34\0\x72\x65\x6d\x6f\x74\x65\x5f\x69\x70\x36\0\
\x6c\x6f\x63\x61\x6c\x5f\x69\x70\x36\0\x72\x65\x6d\x6f\x74\x65\x5f\x70\x6f\x72\
\x74\0\x6c\x6f\x63\x61\x6c\x5f\x70\x6f\x72\x74\0\x64\x61\x74\x61\x5f\x6d\x65\
\x74\x61\0\x66\x6c\x6f\x77\x5f\x6b\x65\x79\x73\0\x6e\x68\x6f\x66\x66\0\x75\x6e\
\x73\x69\x67\x6e\x65\x64\x20\x73\x68\x6f\x72\x74\0\x5f\x5f\x75\x31\x36\0\x74\
\x68\x6f\x66\x66\0\x61\x64\x64\x72\x5f\x70\x72\x6f\x74\x6f\0\x69\x73\x5f\x66\
\x72\x61\x67\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x63\x68\x61\x72\0\x5f\x5f\
\x75\x38\0\x69\x73\x5f\x66\x69\x72\x73\x74\x5f\x66\x72\x61\x67\0\x69\x73\x5f\
\x65\x6e\x63\x61\x70\0\x69\x70\x5f\x70\x72\x6f\x74\x6f\0\x6e\x5f\x70\x72\x6f\
\x74\x6f\0\x5f\x5f\x62\x65\x31\x36\0\x73\x70\x6f\x72\x74\0\x64\x70\x6f\x72\x74\
\0\x69\x70\x76\x34\x5f\x73\x72\x63\0\x5f\x5f\x62\x65\x33\x32\0\x69\x70\x76\x34\
\x5f\x64\x73\x74\0\x69\x70\x76\x36\x5f\x73\x72\x63\0\x69\x70\x76\x36\x5f\x64\
\x73\x74\0\x66\x6c\x61\x67\x73\0\x66\x6c\x6f\x77\x5f\x6c\x61\x62\x65\x6c\0\x62\
\x70\x66\x5f\x66\x6c\x6f\x77\x5f\x6b\x65\x79\x73\0\x74\x73\x74\x61\x6d\x70\0\
\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\0\x5f\
\x5f\x75\x36\x34\0\x77\x69\x72\x65\x5f\x6c\x65\x6e\0\x67\x73\x6f\x5f\x73\x65\
\x67\x73\0\x73\x6b\0\x62\x6f\x75\x6e\x64\x5f\x64\x65\x76\x5f\x69\x66\0\x74\x79\
\x70\x65\0\x73\x72\x63\x5f\x69\x70\x34\0\x73\x72\x63\x5f\x69\x70\x36\0\x73\x72\
\x63\x5f\x70\x6f\x72\x74\0\x64\x73\x74\x5f\x70\x6f\x72\x74\0\x64\x73\x74\x5f\
\x69\x70\x34\0\x64\x73\x74\x5f\x69\x70\x36\0\x73\x74\x61\x74\x65\0\x72\x78\x5f\
\x71\x75\x65\x75\x65\x5f\x6d\x61\x70\x70\x69\x6e\x67\0\x5f\x5f\x73\x33\x32\0\
\x62\x70\x66\x5f\x73\x6f\x63\x6b\0\x67\x73\x6f\x5f\x73\x69\x7a\x65\0\x5f\x5f\
\x73\x6b\x5f\x62\x75\x66\x66\0\x14\0\0\0\x05\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\xf0\x02\0\0\xf0\x02\0\0\x8b\x02\0\0\
\0\0\0\0\0\0\0\x02\x02\0\0\0\x01\0\0\0\x20\0\0\x04\xb8\0\0\0\x0b\0\0\0\x03\0\0\
\0\0\0\0\0\x0f\0\0\0\x03\0\0\0\x20\0\0\0\x18\0\0\0\x03\0\0\0\x40\0\0\0\x1d\0\0\
\0\x03\0\0\0\x60\0\0\0\x2b\0\0\0\x03\0\0\0\x80\0\0\0\x34\0\0\0\x03\0\0\0\xa0\0\
\0\0\x41\0\0\0\x03\0\0\0\xc0\0\0\0\x4a\0\0\0\x03\0\0\0\xe0\0\0\0\x55\0\0\0\x03\
\0\0\0\0\x01\0\0\x5e\0\0\0\x03\0\0\0\x20\x01\0\0\x6e\0\0\0\x03\0\0\0\x40\x01\0\
\0\x76\0\0\0\x03\0\0\0\x60\x01\0\0\x7f\0\0\0\x05\0\0\0\x80\x01\0\0\x82\0\0\0\
\x03\0\0\0\x20\x02\0\0\x87\0\0\0\x03\0\0\0\x40\x02\0\0\x92\0\0\0\x03\0\0\0\x60\
\x02\0\0\x97\0\0\0\x03\0\0\0\x80\x02\0\0\xa0\0\0\0\x03\0\0\0\xa0\x02\0\0\xa8\0\
\0\0\x03\0\0\0\xc0\x02\0\0\xaf\0\0\0\x03\0\0\0\xe0\x02\0\0\xba\0\0\0\x03\0\0\0\
\0\x03\0\0\xc4\0\0\0\x07\0\0\0\x20\x03\0\0\xcf\0\0\0\x07\0\0\0\xa0\x03\0\0\xd9\
\0\0\0\x03\0\0\0\x20\x04\0\0\xe5\0\0\0\x03\0\0\0\x40\x04\0\0\xf0\0\0\0\x03\0\0\
\0\x60\x04\0\0\0\0\0\0\x08\0\0\0\x80\x04\0\0\xfa\0\0\0\x0a\0\0\0\xc0\x04\0\0\
\x01\x01\0\0\x03\0\0\0\0\x05\0\0\x0a\x01\0\0\x03\0\0\0\x20\x05\0\0\0\0\0\0\x0c\
\0\0\0\x40\x05\0\0\x13\x01\0\0\x03\0\0\0\x80\x05\0\0\x1c\x01\0\0\0\0\0\x08\x04\
\0\0\0\x22\x01\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x03\
\0\0\0\x06\0\0\0\x05\0\0\0\x2f\x01\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\0\
\0\0\x03\0\0\0\0\x03\0\0\0\x06\0\0\0\x04\0\0\0\0\0\0\0\x01\0\0\x05\x08\0\0\0\
\x43\x01\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02\x15\0\0\0\x4d\x01\0\0\0\0\0\
\x08\x0b\0\0\0\x53\x01\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\0\0\0\0\x01\0\0\x05\
\x08\0\0\0\x66\x01\0\0\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02\x16\0\0\0\0\0\0\0\
\x01\0\0\x0d\x0f\0\0\0\x69\x01\0\0\x01\0\0\0\x6d\x01\0\0\0\0\0\x01\x04\0\0\0\
\x20\0\0\x01\x71\x01\0\0\x01\0\0\x0c\x0e\0\0\0\x5f\x02\0\0\0\0\0\x01\x01\0\0\0\
\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x11\0\0\0\x06\0\0\0\x04\0\0\0\x64\x02\0\
\0\0\0\0\x0e\x12\0\0\0\x01\0\0\0\x6c\x02\0\0\x01\0\0\x0f\0\0\0\0\x13\0\0\0\0\0\
\0\0\x04\0\0\0\x74\x02\0\0\0\0\0\x07\0\0\0\0\x82\x02\0\0\0\0\0\x07\0\0\0\0\0\
\x5f\x5f\x73\x6b\x5f\x62\x75\x66\x66\0\x6c\x65\x6e\0\x70\x6b\x74\x5f\x74\x79\
\x70\x65\0\x6d\x61\x72\x6b\0\x71\x75\x65\x75\x65\x5f\x6d\x61\x70\x70\x69\x6e\
\x67\0\x70\x72\x6f\x74\x6f\x63\x6f\x6c\0\x76\x6c\x61\x6e\x5f\x70\x72\x65\x73\
\x65\x6e\x74\0\x76\x6c\x61\x6e\x5f\x74\x63\x69\0\x76\x6c\x61\x6e\x5f\x70\x72\
\x6f\x74\x6f\0\x70\x72\x69\x6f\x72\x69\x74\x79\0\x69\x6e\x67\x72\x65\x73\x73\
\x5f\x69\x66\x69\x6e\x64\x65\x78\0\x69\x66\x69\x6e\x64\x65\x78\0\x74\x63\x5f\
\x69\x6e\x64\x65\x78\0\x63\x62\0\x68\x61\x73\x68\0\x74\x63\x5f\x63\x6c\x61\x73\
\x73\x69\x64\0\x64\x61\x74\x61\0\x64\x61\x74\x61\x5f\x65\x6e\x64\0\x6e\x61\x70\
\x69\x5f\x69\x64\0\x66\x61\x6d\x69\x6c\x79\0\x72\x65\x6d\x6f\x74\x65\x5f\x69\
\x70\x34\0\x6c\x6f\x63\x61\x6c\x5f\x69\x70\x34\0\x72\x65\x6d\x6f\x74\x65\x5f\
\x69\x70\x36\0\x6c\x6f\x63\x61\x6c\x5f\x69\x70\x36\0\x72\x65\x6d\x6f\x74\x65\
\x5f\x70\x6f\x72\x74\0\x6c\x6f\x63\x61\x6c\x5f\x70\x6f\x72\x74\0\x64\x61\x74\
\x61\x5f\x6d\x65\x74\x61\0\x74\x73\x74\x61\x6d\x70\0\x77\x69\x72\x65\x5f\x6c\
\x65\x6e\0\x67\x73\x6f\x5f\x73\x65\x67\x73\0\x67\x73\x6f\x5f\x73\x69\x7a\x65\0\
\x5f\x5f\x75\x33\x32\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x5f\
\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x66\
\x6c\x6f\x77\x5f\x6b\x65\x79\x73\0\x5f\x5f\x75\x36\x34\0\x75\x6e\x73\x69\x67\
\x6e\x65\x64\x20\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\0\x73\x6b\0\x63\x74\x78\0\
\x69\x6e\x74\0\x70\x65\x67\x61\x5f\x70\x6b\x74\0\x74\x63\0\x2f\x68\x6f\x6d\x65\
\x2f\x72\x69\x63\x61\x72\x64\x6f\x2f\x44\x6f\x63\x75\x6d\x65\x6e\x74\x73\x2f\
\x4d\x65\x73\x74\x72\x61\x64\x6f\x2f\x50\x72\x6f\x6a\x65\x74\x6f\x2d\x4d\x65\
\x73\x74\x72\x61\x64\x6f\x2f\x50\x72\x6f\x6a\x65\x74\x6f\x5f\x65\x42\x50\x46\
\x2f\x63\x6f\x64\x69\x67\x6f\x73\x5f\x65\x42\x50\x46\x2f\x63\x6f\x64\x69\x67\
\x6f\x5f\x70\x72\x6f\x70\x6f\x73\x74\x61\x2f\x41\x72\x71\x75\x69\x74\x65\x74\
\x75\x72\x61\x2f\x73\x69\x67\x6e\x61\x6c\x73\x2f\x74\x65\x73\x74\x65\x5f\x74\
\x63\x2e\x63\0\x69\x6e\x74\x20\x70\x65\x67\x61\x5f\x70\x6b\x74\x28\x73\x74\x72\
\x75\x63\x74\x20\x5f\x5f\x73\x6b\x5f\x62\x75\x66\x66\x20\x2a\x63\x74\x78\x29\
\x20\x7b\0\x20\x20\x20\x20\x62\x70\x66\x5f\x70\x72\x69\x6e\x74\x6b\x28\x22\x45\
\x53\x54\x41\x20\x43\x41\x50\x54\x41\x4e\x44\x4f\x20\x50\x4b\x54\x53\x21\x21\
\x21\x5c\x6e\x22\x29\x3b\0\x20\x20\x20\x20\x72\x65\x74\x75\x72\x6e\x20\x54\x43\
\x5f\x41\x43\x54\x5f\x4f\x4b\x3b\0\x63\x68\x61\x72\0\x4c\x49\x43\x45\x4e\x53\
\x45\0\x6c\x69\x63\x65\x6e\x73\x65\0\x62\x70\x66\x5f\x66\x6c\x6f\x77\x5f\x6b\
\x65\x79\x73\0\x62\x70\x66\x5f\x73\x6f\x63\x6b\0\0\x9f\xeb\x01\0\x20\0\0\0\0\0\
\0\0\x14\0\0\0\x14\0\0\0\x5c\0\0\0\x70\0\0\0\0\0\0\0\x08\0\0\0\x7a\x01\0\0\x01\
\0\0\0\0\0\0\0\x10\0\0\0\x10\0\0\0\x7a\x01\0\0\x05\0\0\0\0\0\0\0\x7d\x01\0\0\
\xf8\x01\0\0\0\x64\0\0\x08\0\0\0\x7d\x01\0\0\x1e\x02\0\0\x05\x78\0\0\x68\0\0\0\
\x7d\x01\0\0\0\0\0\0\0\0\0\0\x70\0\0\0\x7d\x01\0\0\x1e\x02\0\0\x05\x78\0\0\x80\
\0\0\0\x7d\x01\0\0\x49\x02\0\0\x05\x80\0\0\0\0\0\0\x0c\0\0\0\xff\xff\xff\xff\
\x04\0\x08\0\x08\x7c\x0b\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x90\0\0\0\0\0\0\0\
\xc5\0\0\0\x05\0\x08\0\x97\0\0\0\x08\x01\x01\xfb\x0e\x0d\0\x01\x01\x01\x01\0\0\
\0\x01\0\0\x01\x01\x01\x1f\x04\0\0\0\0\x70\0\0\0\x89\0\0\0\x9a\0\0\0\x03\x01\
\x1f\x02\x0f\x05\x1e\x05\xad\0\0\0\0\xa1\x01\x7f\x0e\x37\x15\x75\xa9\x0c\x1e\
\x78\x10\x5f\x11\xc3\x4d\xb8\0\0\0\x01\xb8\x10\xf2\x70\x73\x3e\x10\x63\x19\xb6\
\x7e\xf5\x12\xc6\x24\x6e\xc3\0\0\0\x02\xea\xdf\x4a\x8b\xcf\x7a\xc4\xe7\xbd\x6d\
\x2c\xb6\x66\x45\x22\x42\xd5\0\0\0\x03\x9a\xe8\xd3\xe7\x79\x4a\xed\x0d\xb7\xa0\
\xa2\x34\x5a\xb8\x81\xee\xdb\0\0\0\x03\x52\xec\x79\xa3\x8e\x49\xac\x7d\x1d\xc9\
\xe1\x46\xba\x88\xa7\xb1\x04\0\0\x09\x02\0\0\0\0\0\0\0\0\x03\x18\x01\x05\x05\
\x0a\x25\x05\0\x06\x03\x62\xba\x05\x05\x03\x1e\x20\x06\x30\x02\x02\0\x01\x01\
\x2f\x68\x6f\x6d\x65\x2f\x72\x69\x63\x61\x72\x64\x6f\x2f\x44\x6f\x63\x75\x6d\
\x65\x6e\x74\x73\x2f\x4d\x65\x73\x74\x72\x61\x64\x6f\x2f\x50\x72\x6f\x6a\x65\
\x74\x6f\x2d\x4d\x65\x73\x74\x72\x61\x64\x6f\x2f\x50\x72\x6f\x6a\x65\x74\x6f\
\x5f\x65\x42\x50\x46\x2f\x63\x6f\x64\x69\x67\x6f\x73\x5f\x65\x42\x50\x46\x2f\
\x63\x6f\x64\x69\x67\x6f\x5f\x70\x72\x6f\x70\x6f\x73\x74\x61\x2f\x41\x72\x71\
\x75\x69\x74\x65\x74\x75\x72\x61\x2f\x73\x69\x67\x6e\x61\x6c\x73\0\x2f\x75\x73\
\x72\x2f\x69\x6e\x63\x6c\x75\x64\x65\x2f\x61\x73\x6d\x2d\x67\x65\x6e\x65\x72\
\x69\x63\0\x2f\x75\x73\x72\x2f\x69\x6e\x63\x6c\x75\x64\x65\x2f\x62\x70\x66\0\
\x2f\x75\x73\x72\x2f\x69\x6e\x63\x6c\x75\x64\x65\x2f\x6c\x69\x6e\x75\x78\0\x74\
\x65\x73\x74\x65\x5f\x74\x63\x2e\x63\0\x69\x6e\x74\x2d\x6c\x6c\x36\x34\x2e\x68\
\0\x62\x70\x66\x5f\x68\x65\x6c\x70\x65\x72\x5f\x64\x65\x66\x73\x2e\x68\0\x62\
\x70\x66\x2e\x68\0\x74\x79\x70\x65\x73\x2e\x68\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\xc7\0\0\0\x04\0\xf1\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x06\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x03\0\x0a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0c\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x03\0\x13\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x15\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x17\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x22\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\x90\0\0\0\0\0\0\0\xeb\0\0\0\x11\0\
\x05\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\x03\0\0\0\x03\0\0\0\
\x11\0\0\0\0\0\0\0\x03\0\0\0\x05\0\0\0\x15\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\
\x1f\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x23\0\0\0\0\0\0\0\x03\0\0\0\x04\0\0\0\
\x08\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x0c\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\x10\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x14\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\x18\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x1c\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\x20\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x24\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\x28\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x2c\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\x30\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x34\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\x38\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x3c\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\x40\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x44\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\x48\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x4c\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\x50\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x54\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\x58\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x5c\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\x60\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x64\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\x68\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x6c\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\x70\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x74\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\x78\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x7c\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\x80\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x84\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\x88\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x8c\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\x90\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x94\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\x98\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x9c\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\xa0\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\xa4\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\xa8\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\xac\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\xb0\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\xb4\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\xb8\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\xbc\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\xc0\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\xc4\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\xc8\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\xcc\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\xd0\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\xd4\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\xd8\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\xdc\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\xe0\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\xe4\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\xe8\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\xec\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\xf0\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\xf4\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\xf8\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\xfc\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\0\
\x01\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x04\x01\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\
\x08\x01\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x0c\x01\0\0\0\0\0\0\x03\0\0\0\x06\0\0\
\0\x10\x01\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x14\x01\0\0\0\0\0\0\x03\0\0\0\x06\0\
\0\0\x18\x01\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x1c\x01\0\0\0\0\0\0\x03\0\0\0\x06\
\0\0\0\x20\x01\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x24\x01\0\0\0\0\0\0\x03\0\0\0\
\x06\0\0\0\x28\x01\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x2c\x01\0\0\0\0\0\0\x03\0\0\
\0\x06\0\0\0\x30\x01\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x34\x01\0\0\0\0\0\0\x03\0\
\0\0\x06\0\0\0\x38\x01\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x3c\x01\0\0\0\0\0\0\x03\
\0\0\0\x06\0\0\0\x40\x01\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x44\x01\0\0\0\0\0\0\
\x03\0\0\0\x06\0\0\0\x48\x01\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x4c\x01\0\0\0\0\0\
\0\x03\0\0\0\x06\0\0\0\x50\x01\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x54\x01\0\0\0\0\
\0\0\x03\0\0\0\x06\0\0\0\x08\0\0\0\0\0\0\0\x02\0\0\0\x0c\0\0\0\x10\0\0\0\0\0\0\
\0\x02\0\0\0\x02\0\0\0\xe8\x02\0\0\0\0\0\0\x04\0\0\0\x0c\0\0\0\x2c\0\0\0\0\0\0\
\0\x04\0\0\0\x02\0\0\0\x40\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x50\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x60\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x70\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x80\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x14\0\0\0\0\0\0\0\
\x03\0\0\0\x08\0\0\0\x18\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\x22\0\0\0\0\0\0\0\
\x03\0\0\0\x0a\0\0\0\x26\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x2a\0\0\0\0\0\0\0\
\x03\0\0\0\x0a\0\0\0\x2e\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x3a\0\0\0\0\0\0\0\
\x03\0\0\0\x0a\0\0\0\x4f\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x64\0\0\0\0\0\0\0\
\x03\0\0\0\x0a\0\0\0\x79\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x8e\0\0\0\0\0\0\0\
\x03\0\0\0\x0a\0\0\0\xa8\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\x0b\x0c\0\x2e\x64\
\x65\x62\x75\x67\x5f\x61\x62\x62\x72\x65\x76\0\x2e\x74\x65\x78\x74\0\x2e\x72\
\x65\x6c\x2e\x42\x54\x46\x2e\x65\x78\x74\0\x70\x65\x67\x61\x5f\x70\x6b\x74\0\
\x2e\x64\x65\x62\x75\x67\x5f\x72\x6e\x67\x6c\x69\x73\x74\x73\0\x2e\x72\x65\x6c\
\x2e\x64\x65\x62\x75\x67\x5f\x73\x74\x72\x5f\x6f\x66\x66\x73\x65\x74\x73\0\x2e\
\x64\x65\x62\x75\x67\x5f\x73\x74\x72\0\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\
\x65\x5f\x73\x74\x72\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x61\x64\x64\
\x72\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x69\x6e\x66\x6f\0\x2e\x6c\
\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\0\x6c\x69\x63\x65\x6e\x73\x65\0\
\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\0\x2e\x72\x65\x6c\
\x2e\x64\x65\x62\x75\x67\x5f\x66\x72\x61\x6d\x65\0\x74\x63\0\x74\x65\x73\x74\
\x65\x5f\x74\x63\x2e\x63\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\
\x61\x62\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\0\x4c\x49\x43\x45\x4e\x53\x45\0\x2e\
\x72\x6f\x64\x61\x74\x61\x2e\x73\x74\x72\x31\x2e\x31\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd2\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x1a\x1b\0\0\0\0\0\0\x02\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x0f\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\xc4\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x90\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf3\0\0\0\x01\
\0\0\0\x32\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd0\0\0\0\0\0\0\0\x17\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x9b\0\0\0\x01\0\0\0\x03\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\xe7\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\xeb\0\0\0\0\0\0\0\x27\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x81\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x12\x02\
\0\0\0\0\0\0\xe8\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x7d\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x38\x14\0\0\0\0\0\0\
\x50\0\0\0\0\0\0\0\x19\0\0\0\x07\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x2b\
\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xfa\x05\0\0\0\0\0\0\x18\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x3f\0\0\0\x01\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x12\x06\0\0\0\0\0\0\x58\x01\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x3b\0\0\0\x09\0\0\0\x40\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x88\x14\0\0\0\0\0\0\x40\x05\0\0\0\0\0\0\x19\0\0\0\x0a\0\0\
\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x52\0\0\0\x01\0\0\0\x30\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x6a\x07\0\0\0\0\0\0\x7c\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\
\0\0\0\0\0\x01\0\0\0\0\0\0\0\x71\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\xe6\x0a\0\0\0\0\0\0\x18\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x6d\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc8\x19\0\0\
\0\0\0\0\x20\0\0\0\0\0\0\0\x19\0\0\0\x0d\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\
\0\0\xe6\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0b\0\0\0\0\0\0\x93\
\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe2\0\0\0\
\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe8\x19\0\0\0\0\0\0\x10\0\0\0\0\0\
\0\0\x19\0\0\0\x0f\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x19\0\0\0\x01\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x94\x10\0\0\0\0\0\0\x90\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x15\0\0\0\x09\0\0\0\x40\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\xf8\x19\0\0\0\0\0\0\x60\0\0\0\0\0\0\0\x19\0\0\0\x11\0\0\0\
\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xb7\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x28\x11\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\xb3\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x58\
\x1a\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x19\0\0\0\x13\0\0\0\x08\0\0\0\0\0\0\0\x10\0\
\0\0\0\0\0\0\xa7\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x50\x11\0\0\0\
\0\0\0\xc9\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa3\
\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x78\x1a\0\0\0\0\0\0\xa0\0\0\
\0\0\0\0\0\x19\0\0\0\x15\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x5d\0\0\0\
\x01\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x19\x12\0\0\0\0\0\0\xe3\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x8d\0\0\0\x03\x4c\xff\
\x6f\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\x18\x1b\0\0\0\0\0\0\x02\0\0\0\0\0\0\0\
\x19\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xda\0\0\0\x02\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x13\0\0\0\0\0\0\x38\x01\0\0\0\0\0\0\x01\0\0\0\x0b\
\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct teste_tc *teste_tc::open(const struct bpf_object_open_opts *opts) { return teste_tc__open_opts(opts); }
struct teste_tc *teste_tc::open_and_load() { return teste_tc__open_and_load(); }
int teste_tc::load(struct teste_tc *skel) { return teste_tc__load(skel); }
int teste_tc::attach(struct teste_tc *skel) { return teste_tc__attach(skel); }
void teste_tc::detach(struct teste_tc *skel) { teste_tc__detach(skel); }
void teste_tc::destroy(struct teste_tc *skel) { teste_tc__destroy(skel); }
const void *teste_tc::elf_bytes(size_t *sz) { return teste_tc__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
teste_tc__assert(struct teste_tc *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __TESTE_TC_SKEL_H__ */
