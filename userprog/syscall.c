#include "userprog/syscall.h"
#include <stdio.h>
#include <list.h>
#include <syscall-nr.h>
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

struct semaphore rw_sema;

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

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  sema_init (&rw_sema, 1);  
}

static void
syscall_handler (struct intr_frame *f) 
{
  unsigned callNum;
  int args[3];

  if (!(f->esp < PHYS_BASE && pagedir_get_page (thread_current ()->pagedir, f->esp) != NULL))
    exit(-1);

  switch (*(int*)f->esp)
  {
    case SYS_HALT:
    {
      shutdown_power_off();
      break;
    }
    case SYS_EXIT:
    {
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args);
      exit (args[0]);
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
      f->eax = create (args[0], args[1]);
      break; 
    }
    case SYS_REMOVE:
    {
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args);
      f->eax = remove (args[0]);
      break;
    }
    case SYS_READ:
    {
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * 3);
      f->eax = read (args[0], args[1], args[2]);
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
      f->eax = open (args[0]);
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
      seek (args[0], args[1]);
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
      f->eax = exec (args[0]);
      break;
    }
    case SYS_CLOSE:
    {
      copy_in (args, (uint32_t *) f->esp + 1, sizeof *args);
      close (args[0]);
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

/* Find and return the file that pertains to FD from within
   the current thread's files list.

   RW_SEMA should be down before calling. */
struct file *get_file (int fd)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;
  struct file_helper *f;

  for (e = list_begin (&cur->files); e != list_end (&cur->files);
       e = list_next (e)){
    f = list_entry (e, struct file_helper, file_elem);
    if (f->fd == fd)
      return f->file;
  }
  return NULL;
}

/* Find and return the file helper that contains FD from within
   the current thread's files list.

   RW_SEMA should be down before calling. */
struct file_helper *get_file_helper (int fd)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;
  struct file_helper *f;

  for (e = list_begin (&cur->files); e != list_end (&cur->files);
       e = list_next (e)){

    f = list_entry (e, struct file_helper, file_elem);
    if (f->fd == fd)
      return f;
  }
  return NULL;
}

/* System calls. */
void exit (int status)
{
  struct thread *cur = thread_current();
  cur->c_h->exit_status = status;
  
  thread_exit();
}

int read (int fd, void *buffer, unsigned length)
{
  if(length <= 0)
    return 0;

  if (fd == 0) {
    int iter;
    for (iter = 0; iter < length; iter++)
      input_getc ();
    return length;
  }
  
  sema_down (&rw_sema);
  struct file *read_file = get_file (fd);

  if (!read_file) {
    sema_up (&rw_sema);
    return -1;
  }

  if (!(buffer < PHYS_BASE && pagedir_get_page (thread_current ()->pagedir, buffer) != NULL))
    exit (-1);

  int bytes_read = file_read (read_file, buffer, length);
  sema_up (&rw_sema);

  return bytes_read;
}

int write (int fd, const void *buffer, unsigned length)
{
  if (fd == 1) {
    putbuf (buffer, length);
    return length;
  }

  sema_down (&rw_sema);
  struct file *write_file = get_file (fd);

  if (!write_file){
    sema_up (&rw_sema);
    return 0;
  }

  if (!(buffer < PHYS_BASE && pagedir_get_page (thread_current ()->pagedir, buffer) != NULL))
    exit (-1);

  int bytes_written = file_write (write_file, buffer, length);
  sema_up (&rw_sema);  

  return bytes_written;   
}

bool create (const char *file, unsigned initial_size)
{
  bool success = false;

  if (!file || !(file < PHYS_BASE && pagedir_get_page (thread_current ()->pagedir, file) != NULL))
    exit (-1);
  
  sema_down (&rw_sema); 
  success =  filesys_create (file, initial_size);
  sema_up (&rw_sema);

  return success;
}

int open (const char *file)
{
  struct thread *cur = thread_current ();
  struct file *open_file;
  static struct file_helper fh;

  if (!file) 
    return -1;

  if (!(file < PHYS_BASE && pagedir_get_page (thread_current ()->pagedir, file) != NULL))
    exit (-1);
  
  sema_down (&rw_sema);
  open_file = filesys_open (file);

  if (open_file) {
    fh.fd = cur->fd_next;
    cur->fd_next++;

    fh.file = open_file;
    list_push_front (&cur->files, &fh.file_elem);
    sema_up (&rw_sema);

    return fh.fd;
  }
  sema_up (&rw_sema);
  return -1;
}

int filesize (int fd)
{
  int size;

  sema_down (&rw_sema);
  struct file *f = get_file (fd);
  size = file_length (f);
  sema_up (&rw_sema); 

  return size;
}

int wait (int pid)
{
  return process_wait (pid);
}

bool remove (const char *file)
{
  bool success;
  sema_down (&rw_sema);
  success = filesys_remove (file);
  sema_up (&rw_sema);
  
  return success;
}

void seek (int fd, unsigned position)
{
  sema_down (&rw_sema);
  struct file *seek_file = get_file (fd);

  if (seek_file)
    file_seek (seek_file, position);

  sema_up (&rw_sema);
}

unsigned tell (int fd)
{
  unsigned pos;

  sema_down (&rw_sema);
  struct file *tell_file = get_file (fd);
  pos = file_tell (tell_file);
  sema_up (&rw_sema);

  return pos;
}

int exec (const char *cmd_line)
{
  if (!cmd_line)
    return -1;
    
  if (!(cmd_line < PHYS_BASE && pagedir_get_page (thread_current ()->pagedir, cmd_line) != NULL))
    exit (-1);

  static char *cmd_line_;
  cmd_line_ = copy_in_string (cmd_line);
  int pid = process_execute (cmd_line_);

  if (pid == TID_ERROR)
    return -1;

  return pid;
}

void close (int fd)
{
  sema_down (&rw_sema);
  struct file_helper *f = get_file_helper (fd);
  if (f){
    file_close (f->file);
    list_remove (&f->file_elem);
  }
  sema_up (&rw_sema);
}