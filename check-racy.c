#include "cache.h"

int main(int ac, char **av)
{
	int i;
	int dirty, clean, racy;

	dirty = clean = racy = 0;
	read_index(&the_index);
	for (i = 0; i < the_index.cache_nr; i++) {
		struct cache_entry *ce = the_index.cache[i];
		struct stat st;

		if (lstat(ce->name, &st)) {
			error_errno("lstat(%s)", ce->name);
			continue;
		}

		if (ie_match_stat(&the_index, ce, &st, 0))
			dirty++;
		else if (ie_match_stat(&the_index, ce, &st, CE_MATCH_RACY_IS_DIRTY))
			racy++;
		else
			clean++;
	}
	printf("dirty %d, clean %d, racy %d\n", dirty, clean, racy);
	return 0;
}
