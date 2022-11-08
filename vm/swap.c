#include "vm/swap.h"
#include <stdio.h>
#include <string.h>
#include <bitmap.h>
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"

static struct block *s_block;
static struct lock s_lock;

static struct bitmap *s_map;
static unsigned s_size;

void
init_swap(){
	s_block = block_get_role(BLOCK_SWAP);
	lock_init(&s_lock);

	s_size = block_size (s_block); 
  s_map = bitmap_create (s_size);
}

size_t
store_swap_page(void *address){
	lock_acquire(&s_lock);
	size_t i = bitmap_scan_and_flip (s_map, 0, (PGSIZE / BLOCK_SECTOR_SIZE), false);

  	ASSERT (i != BITMAP_ERROR);

  	size_t ofs, ind = i;
  	for (ofs = 0; ofs < (PGSIZE / BLOCK_SECTOR_SIZE); ++ofs)
    {
      	ASSERT (i < s_size);
      	ASSERT (bitmap_test (s_map, ind));

      	block_write (s_block, ind, address + ofs * (PGSIZE / BLOCK_SECTOR_SIZE));
      	++ind;
    }
  	lock_release (&s_lock);

  return i;
}

void
load_swap_page(size_t ind, void *address){
	lock_acquire(&s_lock);

	size_t ofs;
	for(ofs = 0; ofs < (PGSIZE / BLOCK_SECTOR_SIZE); ++ofs){
		 ASSERT (ind < s_size);
      	 ASSERT ( bitmap_test (s_map, ind));

      	 block_read (s_block, ind, address + ofs * (PGSIZE / BLOCK_SECTOR_SIZE));
      	 ++ind;
	}

	lock_release(&s_lock);
}


void
free_swap_page(size_t ind){
	lock_acquire(&s_lock);

	size_t ofs;
	for (ofs = 0; ofs < (PGSIZE / BLOCK_SECTOR_SIZE); ++ofs)
    {
      /* Make sure the index is valid. */
      ASSERT (ind < s_size);
      ASSERT ( bitmap_test (s_map, ind) );

      bitmap_reset (s_map, ind);
      ++ind;
    }
  lock_release (&s_lock);
}