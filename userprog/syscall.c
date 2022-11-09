#include "userprog/syscall.h"
#include <stdio.h>
#include <list.h>
#include <syscall-nr.h>
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "lib/string.h"
#include "devices/input.h"
#include "vm/page.h"
#include "vm/frame.h"

static void syscall_handler (struct intr_frame *);
struct lock file_lock; //lock for handing file sys
struct file* get_file_handle(int file_desc);
void get_arguments_from_stack (struct intr_frame *f, int *arg, int n);
struct child_process* add_child (int pid);
void close_all_files (void);
static void *esp_value;

//struct semaphore rw_sema;

static void syscall_handler (struct intr_frame *);
static void copy_in (void *dst_, const void *usrc_, size_t size);
static char* copy_in_string (const char *us);
static inline bool get_user (uint8_t *dst, const uint8_t *usrc);
void exit (int status);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned length);
bool create (const char *file, unsigned initial_size);
int open (const char *file);
int filesize (int fd);
int wait (int pid);
bool remove (const char *file);
void seek (int fd, unsigned position);
unsigned tell (int fd);
int exec (const char *cmd_line);
void close (int fd);

//File structre
struct file_struct
{
	struct file* file; //file pointer
	int file_desc;     //file discriptor
	struct list_elem elem;
};


void syscall_init (void) 
{
	lock_init (&file_lock);
  	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler (struct intr_frame *f UNUSED) 
{
	unsigned callNum;
	int args[3];  

	if (!(f->esp < PHYS_BASE && pagedir_get_page (thread_current ()->pagedir, f->esp) != NULL))
    	exit(-1);
	
	switch(*(int*)f->esp)
	{
		case SYS_HALT:
		 {
			shutdown_power_off();
			break;
		 }
		case SYS_EXIT:
		 {
			copy_in (args, (uint32_t *) f->esp + 1, sizeof *args);
		 	exit(args[0]);
		 	break;
		 }
		case SYS_WAIT:
		 {
			copy_in (args, (uint32_t *) f->esp + 1, sizeof *args);
		 	f->eax = wait (args[0]);
		 	break;
		 }
		case SYS_CREATE:
		 {
			copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 2);
		 	f->eax = create ((const char *)args[0], (unsigned) args[1]);
		 	break;
		 }
		case SYS_REMOVE:
		 {
			copy_in (args, (uint32_t *) f->esp + 1, sizeof *args);
		 	f->eax = remove ((const char *) args[0]);
		 	break;	
		 }
		case SYS_READ:
		 {
			copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 3);
		 	f->eax = read (args[0], (void *) args[1], (unsigned) args[2]);
		 	break;
		 }
		case SYS_WRITE:
		 {
			int fd = *((int*)f->esp+1);
			void* buffer = (void*)(*((int*)f->esp+2));
			unsigned size = *((unsigned*)f->esp+3);
			f->eax = write (fd, buffer, size);
		 	break;
		 }
		case SYS_OPEN:
		 {
			copy_in (args, (uint32_t *) f->esp + 1, sizeof *args);
		 	f->eax = open ((const char *)args[0]);
		 	break;
		 }
		case SYS_FILESIZE:
		 {
			copy_in (args, (uint32_t *) f->esp + 1, sizeof *args);
		 	f->eax = filesize (args[0]);
		 	break;
		 }   
		case SYS_SEEK:
		 {
			copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 2);
		 	seek (args[0], (unsigned) args[1]);
		 	break;
		 } 
		case SYS_TELL:
		 {
		 	copy_in (args, (uint32_t *) f->esp + 1, sizeof *args);
			f->eax = tell (args[0]);
		 	break;
		 } 
		case SYS_EXEC:
		 {
			copy_in (args, (uint32_t *) f->esp + 1, sizeof *args);
		 	f->eax = exec ((const char*)args[0]);
		 	break;
		 } 
		case SYS_CLOSE:
		 {
			copy_in (args, (uint32_t *) f->esp + 1, sizeof *args);
		 	close(args[0]);
		 	break;
		 } 

	}
  
}

/* Copies SIZE bytes from user address USRS to kernel address
   DST.
   Call thread_exit() if any of the user accesses are invalid. */
static void
copy_in (void *dst_, const void *usrc_, size_t size) 
{
  uint8_t *dst = dst_;
  const uint8_t *usrc = usrc_;
 
  for (; size > 0; size--, dst++, usrc++) 
    if (usrc >= (uint8_t *) PHYS_BASE || !get_user (dst, usrc)) 
      exit (-1);
}



/* Creates a copy of user string US in kernel memory
   and returns it as a page that must be freed with
   palloc_free_page().
   Truncates the string at PGSIZE bytes in size.
   Call thread_exit() if any of the user accesses are invalid. */
static char *
copy_in_string (const char *us) 
{
  char *ks;
  size_t length;
 
  ks = palloc_get_page (0);
  if (ks == NULL) 
    thread_exit ();
 
  for (length = 0; length < PGSIZE; length++)
    {
      if (us >= (char *) PHYS_BASE || !get_user (ks + length, us++)) 
        {
          palloc_free_page (ks);
          thread_exit (); 
        }
       
      if (ks[length] == '\0')
        return ks;
    }
  ks[PGSIZE - 1] = '\0';
  return ks;
}

/* Copies a byte from user address USRC to kernel address DST.
   USRC must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
get_user (uint8_t *dst, const uint8_t *usrc)
{
  int eax;
  asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
       : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
  return eax != 0;
}


//Finds file handle for given file discriptor by searching in
// list of files owned
struct file* get_file_handle (int file_desc)
{
   struct list_elem *e = list_begin (&thread_current()->files_owned_list);
   struct list_elem *next;
   while (e != list_end (&thread_current()->files_owned_list))
   {

     struct file_struct *f = list_entry (e, struct file_struct, elem);
     next = list_next(e);
     if (file_desc == f->file_desc)
       {
        return f->file;
       }
     e = next;
   }
   return NULL;

}

/* System calls. */
void exit (int status)
{
	struct thread *current = thread_current();
    current->exit_status = status;
    thread_get_child_data(current->parent, current->tid)->exit_status=current->exit_status;
    thread_exit();
}

//read sys call, returns no of bytes read from buffer or file
//STDIN_FILENO is reading from buffer
int read (int fd, void *buf, unsigned length)
{
	const void *esp = (const void*)esp_value;
	if(length <= 0)
		return 0;

        int ret = 0; 
	if (fd == 0)
	{
		int iter;
		for (iter = 0; iter < length; iter++)
		{
			input_getc();
		}
		return length;
	}
    lock_acquire (&file_lock);	
	struct file* file_ptr = get_file_handle (fd);
	if (!file_ptr)
	{
		lock_release (&file_lock);
		return -1;
	}
	if (!(buf < PHYS_BASE && pagedir_get_page (thread_current ()->pagedir, buf) != NULL))
    	exit(-1);

	int bytes_read = file_read(file_ptr, buf, length);
	lock_release(&file_lock);
	return bytes_read;
}

int write (int fd, const void *buffer, unsigned length)
{
	const void *esp = (const void *)esp_value;

        int ret = 0;
	if (fd == 1)
	 {
		putbuf(buffer, length);
		return length;

	 }

	lock_acquire(&file_lock); 
	struct file *file_ptr = get_file_handle (fd);
	
	if (!file_ptr)
	{
		lock_release(&file_lock);
		return 0;
	}
	if (!(buffer < PHYS_BASE && pagedir_get_page (thread_current ()->pagedir, buffer) != NULL))
    	exit(-1);
	int bytes_written = file_write(file_ptr, buffer, length);
	lock_release(&file_lock);
	return bytes_written;
}

//create sys call, calls file_create sys call
bool create (const char *file, unsigned initial_size)
{
	bool success = false;
	if (!file || !(file < PHYS_BASE && pagedir_get_page (thread_current ()->pagedir, file) != NULL))
    	exit(-1);

	success = filesys_create (file, initial_size);

	return success;
}

int open (const char *file)
{
	if (file == NULL)
		 {
		 	exit (-1);
		 }

	if (!(file < PHYS_BASE && pagedir_get_page (thread_current ()->pagedir, file) != NULL))
    	exit(-1);


	lock_acquire (&file_lock);
	struct file *handle = filesys_open (file);

	if (handle == NULL)
		 {
		 	lock_release (&file_lock);
		 	return -1;
		 }

	struct file_struct *file_ptr = malloc (sizeof (struct file_struct));
	if (file_ptr == NULL)
		 {
		 	lock_release (&file_lock);
		 	return -1;
		 }
	file_ptr->file_desc = thread_current ()->file_desc;

	thread_current ()->file_desc++; 
	file_ptr->file = handle;
	list_push_back (&thread_current ()->files_owned_list , &file_ptr->elem);

	if (strcmp (file, thread_current ()->name) == 0)
	 {
	 	file_deny_write (handle);
	 }

	lock_release (&file_lock);	 
	return file_ptr->file_desc;
}


//File size sys call, gets file handle and then returns,
// file_length of file
int filesize (int fd)
{
	int size;

	lock_acquire (&file_lock);	
	struct file *file_ptr = get_file_handle (fd);
	size = file_length (file_ptr);
	lock_release (&file_lock);
	return size;
}

int wait (int pid)
{
	return process_wait (pid);
}


bool remove (const char *file)
{
	bool success;
	lock_acquire (&file_lock);
	success = filesys_remove (file);
	lock_release (&file_lock);

	return success;	
}

void seek (int fd, unsigned position)
{
	lock_acquire (&file_lock);
	struct file *file_ptr = get_file_handle (fd); 

	if(file_ptr)
		file_seek (file_ptr, position);	

	lock_release (&file_lock);
}

//tell sys call, gets file handle and calls file_tell
unsigned tell (int fd)
{
	unsigned pos;

	struct file *file_ptr = get_file_handle (fd);
	pos = file_tell (file_ptr);

	return pos;
}


//close sys call, gets file handle and closes file
void close (int fd)
{
	struct file_struct *file_ptr = NULL;
        struct list_elem *e = list_begin (&thread_current()->files_owned_list);
        struct list_elem *next;
        while (e != list_end (&thread_current()->files_owned_list))
        {

                struct file_struct *f = list_entry (e, struct file_struct,
                                          elem);
                next = list_next(e);
                if (fd == f->file_desc)
                {
                        file_ptr = f;
                        break;
                }
                e = next;
        }

	if (file_ptr != NULL)
		 {
		 	if (fd == file_ptr->file_desc)
		 	{
		 		file_close (file_ptr->file);
		 		list_remove (&file_ptr->elem);
		 		free (file_ptr);
		 	}	
		 }
	

}



//Exec call, calls process execute
int exec (const char *cmd_line)
{
	if(!cmd_line)
		return -1;
	if (!(cmd_line < PHYS_BASE && pagedir_get_page (thread_current ()->pagedir, cmd_line) != NULL))
    	exit(-1);

	int pid = process_execute(cmd_line);

	if(pid == TID_ERROR)
		return -1;

	return pid;	 
}





//get arguments from stack
void get_arguments_from_stack (struct intr_frame *f, int *arg, int n)
{
	int i;
	
	for(i = 0; i < n; ++i)
		 {
		 	int *ptr = (int *)f->esp + i + 1;	
		 	if(!is_user_vaddr((const void*)ptr))
				exit(-1);
		 	arg[i] = *ptr;
		 }
}


//CLose open files
void close_all_files (void)
{
   struct list_elem *el = list_begin (&thread_current()->files_owned_list);
   struct list_elem *nxt;
   while (el != list_end (&thread_current()->files_owned_list))
   {
     struct file_struct *fs = list_entry (el, struct file_struct,
                                          elem);
     nxt = list_next(el);
     file_close (fs->file);
     list_remove (&fs->elem);
     free (fs);
     el = nxt;
   }
}

void sys_filelock(int flag){
if(flag)
	lock_acquire(&file_lock);
else
	lock_release(&file_lock);
}