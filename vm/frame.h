#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "hash.h"
#include "threads/thread.h"
#include "threads/palloc.h"

struct struct_frame
{
	void *page;  //actual page
	struct thread *thread; //owner thread
	uint32_t *pte; //page table entry of frame's page
	void *vaddr; //address of page
	struct hash_elem hash_elem;
	struct lock llock; //lock for sync access to frame_pages list
	struct list frame_pages; //list of pages sharing same frame
	struct list_elem page_elem;
	int pin;
};

void vm_frame_init (void);

#endif /* vm/frame.h*/