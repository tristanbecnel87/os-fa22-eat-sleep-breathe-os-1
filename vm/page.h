#ifndef VM_PAGE_H
#define VM_PAGE_H
	
#include <list.h>
#include <stdbool.h>
#include "filesys/file.h"
#include <stddef.h>

	struct struct_page
	{
		int type; //0-zeroed, 1-File, 2-swap
		bool is_page_loaded;
		bool is_writable;
		void *address;
		void *frame_page;
		uint32_t *pointer_to_pagedir;
		struct list_elem f_elem;

		struct
		{
			struct file *file_name;
			off_t ofs;
			size_t read_bytes;
			size_t zero_bytes;
			off_t block_id;
		} file;

		struct
		{
			size_t swap_index;
		}swap_data;

	};
    void vm_page_init ();
#endif