/*
 * test-mktemp.c: code to exercise the creation of temporary files
 */
#include "test-tool.h"
#include "cache.h"
#include "midx.h"
#include "repository.h"
#include "object-store.h"

static int read_midx_file(const char *object_dir)
{
	struct multi_pack_index *m = load_multi_pack_index(object_dir);

	if (!m)
		return 0;

	printf("header: %08x %d %d %d\n",
	       m->signature,
	       m->version,
	       m->num_chunks,
	       m->num_packs);

	printf("chunks:");

	if (m->chunk_pack_names)
		printf(" pack_names");

	printf("\n");

	printf("object_dir: %s\n", m->object_dir);

	return 0;
}

int cmd__read_midx(int argc, const char **argv)
{
	if (argc != 2)
		usage("read-midx <object_dir>");

	return read_midx_file(argv[1]);
}
