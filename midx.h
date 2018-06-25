#ifndef __MIDX_H__
#define __MIDX_H__

#include "repository.h"

struct multi_pack_index;

struct multi_pack_index *load_multi_pack_index(const char *object_dir);
int prepare_multi_pack_index_one(struct repository *r, const char *object_dir);

int write_midx_file(const char *object_dir);

#endif
