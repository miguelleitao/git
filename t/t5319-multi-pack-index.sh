#!/bin/sh

test_description='multi-pack-indexes'
. ./test-lib.sh

midx_read_expect() {
	NUM_PACKS=$1
	cat >expect <<- EOF
	header: 4d494458 1 2 $NUM_PACKS
	chunks: pack_names oid_lookup
	packs:
	EOF
	if [ $NUM_PACKS -ge 1 ]
	then
		ls pack/ | grep idx | sort >> expect
	fi
	printf "object_dir: .\n" >>expect &&
	test-tool read-midx . >actual &&
	test_cmp expect actual
}

test_expect_success 'write midx with no packs' '
	test_when_finished rm pack/multi-pack-index &&
	git multi-pack-index --object-dir=. write &&
	midx_read_expect 0
'

test_expect_success 'create objects' '
	for i in `test_seq 1 5`
	do
		iii=$(printf '%03i' $i)
		test-tool genrandom "bar" 200 > wide_delta_$iii &&
		test-tool genrandom "baz $iii" 50 >> wide_delta_$iii &&
		test-tool genrandom "foo"$i 100 > deep_delta_$iii &&
		test-tool genrandom "foo"$(expr $i + 1) 100 >> deep_delta_$iii &&
		test-tool genrandom "foo"$(expr $i + 2) 100 >> deep_delta_$iii &&
		echo $iii >file_$iii &&
		test-tool genrandom "$iii" 8192 >>file_$iii &&
		git update-index --add file_$iii deep_delta_$iii wide_delta_$iii &&
		i=$(expr $i + 1) || return 1
	done &&
	{ echo 101 && test-tool genrandom 100 8192; } >file_101 &&
	git update-index --add file_101 &&
	tree=$(git write-tree) &&
	commit=$(git commit-tree $tree </dev/null) && {
	echo $tree &&
	git ls-tree $tree | sed -e "s/.* \\([0-9a-f]*\\)	.*/\\1/"
	} >obj-list &&
	git update-ref HEAD $commit
'

test_expect_success 'write midx with one v1 pack' '
	pack=$(git pack-objects --index-version=1 pack/test <obj-list) &&
	test_when_finished rm pack/test-$pack.pack pack/test-$pack.idx pack/multi-pack-index &&
	git multi-pack-index --object-dir=. write &&
	midx_read_expect 1
'

test_expect_success 'write midx with one v2 pack' '
	git pack-objects --index-version=2,0x40 pack/test <obj-list &&
	git multi-pack-index --object-dir=. write &&
	midx_read_expect 1
'

test_expect_success 'Add more objects' '
	for i in `test_seq 6 5`
	do
		iii=$(printf '%03i' $i)
		test-tool genrandom "bar" 200 > wide_delta_$iii &&
		test-tool genrandom "baz $iii" 50 >> wide_delta_$iii &&
		test-tool genrandom "foo"$i 100 > deep_delta_$iii &&
		test-tool genrandom "foo"$(expr $i + 1) 100 >> deep_delta_$iii &&
		test-tool genrandom "foo"$(expr $i + 2) 100 >> deep_delta_$iii &&
		echo $iii >file_$iii &&
		test-tool genrandom "$iii" 8192 >>file_$iii &&
		git update-index --add file_$iii deep_delta_$iii wide_delta_$iii &&
		i=$(expr $i + 1) || return 1
	done &&
	{ echo 101 && test-tool genrandom 100 8192; } >file_101 &&
	git update-index --add file_101 &&
	tree=$(git write-tree) &&
	commit=$(git commit-tree $tree -p HEAD</dev/null) && {
	echo $tree &&
	git ls-tree $tree | sed -e "s/.* \\([0-9a-f]*\\)	.*/\\1/"
	} >obj-list2 &&
	git update-ref HEAD $commit
'

test_expect_success 'write midx with two packs' '
	git pack-objects --index-version=1 pack/test-2 <obj-list2 &&
	git multi-pack-index --object-dir=. write &&
	midx_read_expect 2
'

test_expect_success 'Add more packs' '
	for j in `test_seq 1 10`
	do
		iii=$(printf '%03i' $i)
		test-tool genrandom "bar" 200 > wide_delta_$iii &&
		test-tool genrandom "baz $iii" 50 >> wide_delta_$iii &&
		test-tool genrandom "foo"$i 100 > deep_delta_$iii &&
		test-tool genrandom "foo"$(expr $i + 1) 100 >> deep_delta_$iii &&
		test-tool genrandom "foo"$(expr $i + 2) 100 >> deep_delta_$iii &&
		echo $iii >file_$iii &&
		test-tool genrandom "$iii" 8192 >>file_$iii &&
		git update-index --add file_$iii deep_delta_$iii wide_delta_$iii &&
		{ echo 101 && test-tool genrandom 100 8192; } >file_101 &&
		git update-index --add file_101 &&
		tree=$(git write-tree) &&
		commit=$(git commit-tree $tree -p HEAD</dev/null) && {
		echo $tree &&
		git ls-tree $tree | sed -e "s/.* \\([0-9a-f]*\\)	.*/\\1/"
		} >obj-list &&
		git update-ref HEAD $commit &&
		git pack-objects --index-version=2 pack/test-pack <obj-list &&
		i=$(expr $i + 1) || return 1 &&
		j=$(expr $j + 1) || return 1
	done
'

test_expect_success 'write midx with twelve packs' '
	git multi-pack-index --object-dir=. write &&
	midx_read_expect 12
'

test_done
