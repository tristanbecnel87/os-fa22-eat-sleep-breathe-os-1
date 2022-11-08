#include "vm/frame.h"
#include <stdio.h>
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "vm/page.h"

static struct lock frame_lock;
static struct lock eviction_lock;
static struct hash frames;

//frames list
static struct list list_of_frames;
static struct list_elem *next_to_evict;

unsigned frame_hash (const struct hash_elem *, void *);
bool frame_comparator (const struct hash_elem *, const struct hash_elem *, void *);
//static bool delete_frame (struct struct_frame *f);
static struct struct_frame *find_frame (void *);
static void delete_frame (struct struct_frame *f);
static struct struct_frame * find_frame (void *pg);
static bool add_frame (void *pg);
static bool find_page_to_evict(struct struct_frame *f);
static void move_to_next_eviction(void);
static void remove_evict_pointer(struct struct_frame *frame_to_evict);
static void circular_evict(void);

//Initializes frames hash, called from threads/init.c
//from main function
void
vm_frame_init (void)
{
	lock_init (&frame_lock);
	lock_init (&eviction_lock);
	hash_init (&frames, frame_hash, frame_comparator, NULL);
	list_init (&list_of_frames);

}

struct struct_page*
get_page_from_frame(void *fr, uint32_t *page_dir){
	struct struct_frame *f = find_frame(fr);
	struct list_elem *e;

	if(f == NULL){
		return NULL;
	}

	lock_acquire(&f->llock);
	for(e = list_begin(&f->frame_pages); e != list_end(&f->frame_pages); e = list_next(e)){
		struct struct_page *p = list_entry(e, struct struct_page, f_elem);
		if(p->pointer_to_pagedir == page_dir){
			lock_release(&f->llock);
			return p;
		}
	}
	lock_release(&f->llock);
	return NULL;
}

bool
set_page_in_frame(void *f, struct struct_page *p){
	struct struct_frame *frame = find_frame(f);
	if(f == NULL){
		return false;
	}

	lock_acquire(&frame->llock);
	list_push_back(&frame->frame_pages, &p->f_elem);
	lock_release(&frame->llock);
	return true;
}

//returns hash value for frame e
unsigned frame_hash (const struct hash_elem *e_, void *aux UNUSED)
{
	const struct struct_frame *sf = hash_entry (e_, struct struct_frame,
		                                        hash_elem);
	return hash_int ((unsigned) sf->page);
}


//Frame comparator by pages in it
bool
frame_comparator (const struct hash_elem *first_, const struct hash_elem *second_,
	             void *aux UNUSED)
{
	const struct struct_frame *f = hash_entry (first_, 
		                           struct struct_frame, hash_elem); 
	const struct struct_frame *s = hash_entry (second_, 
		                           struct struct_frame, hash_elem); 
	return f->page < s->page;
}


//Frees resources
//void
//free_vm_frames (void *pg)
//{
//	delete_frame (pg);
//	palloc_free_page (pg);
//}

//Deletes a frame, free its memory
static void
delete_frame (struct struct_frame *f)
{
	//struct struct_frame *f = find_frame (pg);
	//if (f == NULL)
	 //{
	// 	return false;
	 //}

	 lock_acquire (&frame_lock);
	 remove_evict_pointer(f);
	 hash_delete (&frames, &f->hash_elem);
	 list_remove(&f->page_elem);
	 free (f);
	 lock_release (&frame_lock);

	 //return true;
}


//returns frame for given page
static struct struct_frame *
find_frame (void *pg)
{
	struct struct_frame sf;
	struct hash_elem *elm;

	sf.page = pg;
	elm = hash_find (&frames, &sf.hash_elem);
	if (elm == NULL)
	 {
	 	return NULL;
	 }

	return hash_entry (elm, struct struct_frame, hash_elem); 

}

//------
/*
//Maps User virtual page to frame of vm by help of pte
bool
upage_to_frame_mapping (void *frame, uint32_t *pte, void *vaddr)
{
	struct struct_frame *sf = find_frame (frame);
	if (sf == NULL)
	 {
	 	return false;
	 }
	 sf->pte = pte;
	 sf->vaddr = vaddr;
	 return true;
}
*/
//------

//Adds frame to Hash by allocating memory
static bool
add_frame (void *pg)
{
	struct struct_frame *sf;
	sf = (struct struct_frame *) malloc (sizeof (struct struct_frame));

	if(sf == NULL)
	 {
	 	return false;
	 }

	 sf->thread = thread_current ();
	 sf->page = pg;

	 lock_acquire (&frame_lock);
	 hash_insert (&frames, &sf->hash_elem);
	 lock_release (&frame_lock);

	 return true;
}

//Gets a free frame
void *
get_frame (enum palloc_flags flags)
{
	void *pg = palloc_get_page (flags);
	if (pg != NULL)
	 {
	 	struct struct_frame *vf;
	 	vf = (struct struct_frame *) malloc (sizeof (struct struct_frame));
	 	
	 	if (vf  == NULL)
	 	 {
	 	 	return false;
	 	 }
	 	 vf->page = pg;
	 	 //pinn this frame so it can not evict before
	 	 //caller loads data on it
	 	 vf->pin = 1;
	 	 list_init (&vf->frame_pages);
	 	 lock_init (&vf->llock);
	 	 lock_acquire (&frame_lock);
	 	 list_push_back (&list_of_frames, &vf->page_elem);
	 	 hash_insert (&frames, &vf->hash_elem);
	 	 lock_release (&frame_lock);
	 }
	 else
	  {
	  	#ifndef VM
			printf("\nsys_exit from frame...\n");
	  		exit (-1);
	  	#endif
	  	//PANIC ("Eviction needed !");	
	  	circular_evict ();
    	return get_frame (flags);
	  }

	  return pg;
}

void *
frame_lookup(off_t block_id)
{
	void *address = NULL;

	struct hash_iterator hi;

	lock_acquire(&frame_lock);
	hash_first(&hi, &frames);
	while(hash_next(&hi) && address == NULL){
		struct struct_frame *f = NULL;
		f = hash_entry(hash_cur(&hi), struct struct_frame, hash_elem);
		lock_acquire(&f->llock);

		struct list_elem *e = list_begin(&f->frame_pages);
		struct struct_page *fpage = list_entry(e, struct struct_page, f_elem);
		if(fpage->type == 1 && fpage->file.block_id== block_id){
			address = f->page;
			f->pin = 1;
		}

		lock_release(&f->llock);
	}

	lock_release(&frame_lock);
	return address;
}

//Mapping for page to frame
bool
set_frame(void *f, struct struct_page *p){
	struct struct_frame *frame = find_frame(f);
	if(frame == NULL){
		return false;
	}

	lock_acquire(&frame->llock);
	list_push_back(&frame->frame_pages, &p->f_elem);
	lock_release(&frame->llock);
	return true;
}

void
free_frame(void *address, uint32_t *page_dir){
	lock_acquire(&eviction_lock);
	struct struct_frame *f = find_frame(address);
	struct list_elem *e;

	if(f == NULL){
		lock_release(&eviction_lock);
		return;
	}

	if(page_dir == NULL){
		lock_acquire(&f->llock);
		while(!list_empty(&f->frame_pages)){
			e = list_begin(&f->frame_pages);
			struct struct_page *p = list_entry (e, struct struct_page, f_elem);
			list_remove(&p->f_elem);
			vm_unload(p, f->page);
		}
		lock_release(&f->llock);
	}
	else{
		struct struct_page *p = get_page_from_frame(address, page_dir);
		if(p !=NULL){
			lock_acquire (&f->llock);
          	list_remove (&p->f_elem);
          	lock_release (&f->llock);
         	vm_unload (p, f->page);
		}
	}

	if(list_empty(&f->frame_pages)){
		delete_frame(f);
		palloc_free_page(address);
	}

	lock_release(&eviction_lock);
}

void
pin(void *address){
	struct struct_frame *f = find_frame(address);
	if(f != NULL){
		f->pin = 1;
	}
}

void
unpin(void *address){
	struct struct_frame *f = find_frame(address);
	if(f != NULL){
		f->pin = 0;
	}
}

static bool
find_page_to_evict(struct struct_frame *f){
	struct list_elem *e;

	for(e=list_begin(&f->frame_pages); e != list_end(&f->frame_pages); e = list_next(e)){
		struct struct_page *p = list_entry(e, struct struct_page, f_elem);

	if (pagedir_is_accessed (p->pointer_to_pagedir, p->address) )
        {
          pagedir_set_accessed (p->pointer_to_pagedir, p->address, false);
          return false;
        }
	}
	return true;
}

static struct struct_frame*
get_next_page_for_eviction(void){
	if(next_to_evict == NULL || next_to_evict == list_end(&list_of_frames)){
		next_to_evict = list_begin(&list_of_frames);
	}

	if(next_to_evict != NULL){
		struct struct_frame *f = list_entry (next_to_evict, struct struct_frame, page_elem);
      	return f;
	}

	NOT_REACHED();
}

static void
circular_evict(void){
	struct struct_frame *frame_to_evict = NULL;

	lock_acquire(&eviction_lock);
	lock_acquire(&frame_lock);

	while(frame_to_evict == NULL){
		struct struct_frame *f = get_next_page_for_eviction();
		ASSERT(f != NULL);

		if(f->pin == 1 || find_page_to_evict(f) == false){
				move_to_next_eviction();
				continue;
		}

		frame_to_evict = f;
	}

	lock_release(&frame_lock);
	lock_release(&eviction_lock);
	free_frame(frame_to_evict->page, NULL);
}


static void
move_to_next_eviction(void){
	if (next_to_evict == NULL || next_to_evict == list_end (&list_of_frames) )
    	next_to_evict = list_begin (&list_of_frames);
  	else
    	next_to_evict = list_next (next_to_evict); 
}

static void
remove_evict_pointer(struct struct_frame *frame_to_evict){
	if (next_to_evict == NULL || next_to_evict == list_end (&list_of_frames) )
		return;
	struct struct_frame *f = list_entry (next_to_evict, struct struct_frame, page_elem);

	if (f == frame_to_evict)
		move_to_next_eviction ();
}