#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "filesys/free-map.h"
#include "filesys/filesys.h"
#include "filesys/directory.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"
#include "lib/user/syscall.h"
#include "userprog/exception.h"

static void syscall_handler(struct intr_frame *f UNUSED);

static bool user_check(const char *uaddr);

/* Copies a byte from user address USRC to kernel address DST.
   USRC must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
get_user(uint8_t *dst, const uint8_t *usrc)
{
    int eax;
    asm("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
        : "=m"(*dst), "=&a"(eax)
        : "m"(*usrc));
    return eax != 0;
}

/* Creates a copy of user string US in kernel memory
   and returns it as a page that must be freed with
   palloc_free_page().
   Truncates the string at PGSIZE bytes in size.
   Call thread_exit() if any of the user accesses are invalid. */
static char *
copy_in_string(const char *us)
{
    char *ks;
    size_t length;

    ks = palloc_get_page(0);
    if (ks == NULL)
        thread_exit();

    for (length = 0; length < PGSIZE; length++)
    {
        if (us >= (char *)PHYS_BASE || !get_user(ks + length, us++))
        {
            palloc_free_page(ks);
            thread_exit();
        }

        if (ks[length] == '\0')
            return ks;
    }
    ks[PGSIZE - 1] = '\0';
    return ks;
}


void
syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&filesys_lock);
}

static int tokenize(char **splitStrings, char* real, char* saveptr){
    int i = 0;
    char* token = strtok_r (real, "/", &saveptr);
    for (; token != NULL; token = strtok_r (NULL, "/", &saveptr)) {
        splitStrings[i] = token;
        i++;
    }
    i--;
    return i;
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
    //**NEED TO READ THE SYSCALL NUMBER SOMEHOW? RIGHT NOW IM MANUALLY SETTING

    void *esp = f->esp;
    //uint32_t *eax = &f->eax;
    int sysnumber;

    if((!verify_user ( ((int *) esp) )) || (!verify_user ( ((int *) esp)+1 )))
        exit (-1);
    sysnumber = *((int *) esp);

    switch(sysnumber){         
        case SYS_HALT:     /* Halt the operating system. */
            shutdown_power_off();
            break;

        case SYS_EXIT:     /* Terminate this process. */
            exit(*(((int *) esp) + 1));
            break;

        case SYS_EXEC:     /* Start another process. */
            *&f->eax = (uint32_t)exec(*(((char **) esp) + 1));
            break;

        case SYS_WAIT:     /* Wait for a child process to die. */
            *&f->eax = (uint32_t)wait(*(((pid_t *) esp) + 1));
            break;

        case SYS_CREATE:   /* Create a file. */
            *&f->eax = (uint32_t)create(*(((char **) esp) + 1), *(((unsigned *) esp) + 2));
            break;

        case SYS_REMOVE:   /* Delete a file. */
            *&f->eax = (uint32_t)remove(*(((char **) esp) + 1));
            break;

        case SYS_OPEN:     /* Open a file. */
            *&f->eax = (uint32_t)open(*(((char **) esp) + 1));
            break;

        case SYS_FILESIZE: /* Obtain a file's size. */
            *&f->eax = (uint32_t)filesize(*(((int *) esp) + 1));
            break;
        
        case SYS_READ:     /* Read from a file. */
            *&f->eax = (uint32_t)read(*(((int *) esp) + 1), (void *) *(((int **) esp) + 2), *(((unsigned *) esp) + 3));
            break;

        case SYS_WRITE:    /* Write to a file. */
            *&f->eax = (uint32_t)write (*(((int *) esp) + 1), (void *) *(((int **) esp) + 2), *(((unsigned *) esp) + 3));
            break;

        case SYS_SEEK:     /* Change position in a file. */
            seek (*(((int *) esp) + 1), *(((unsigned *) esp) + 2));
            break;

        case SYS_TELL:     /* Report current position in a file. */
            *&f->eax = (uint32_t)tell (*(((int *) esp) + 1));
            break;

        case SYS_CLOSE:    /* Close a file. */
            close (*(((int *) esp) + 1));
            break;

        case SYS_CHDIR:
            *&f->eax = (uint32_t)chdir((char *) *(((int **) esp) + 1));
            break;

        case SYS_INUMBER:
            *&f->eax = (uint32_t)inumber(*(((int *) esp) + 1));
            break;

        case SYS_MKDIR:
            *&f->eax = (uint32_t)mkdir((char *) *(((int **) esp) + 1));
            break;

        case SYS_READDIR:
            *&f->eax = (uint32_t)readdir(*(((int *) esp) + 1),  (char *) *(((int **) esp) + 2));
            break;
            
        case SYS_ISDIR:
            *&f->eax = (uint32_t)isdir(*(((int *) esp) + 1));
            break;
    }
}


//METHOD IMPLEMENTATION//
//returns filesize
int filesize (int fd){
    struct file_desc* fdesc = findFile(thread_current(), fd);

    if(fdesc == NULL){
        return 0;
    }

    lock_acquire(&filesys_lock); 
    int size = file_length(fdesc->file); /*Thread blocking the file so no other one tries to access it*/
    lock_release(&filesys_lock);

    return size;
}


unsigned tell (int fd){
    struct file_desc* fdesc = findFile(thread_current(), fd);

    if(fdesc == NULL){
        return 0;
    }

    lock_acquire(&filesys_lock);
    unsigned result = file_tell(fdesc->file);/*Thread blocking the file so no other one tries to access it*/
    lock_release(&filesys_lock);

    return result;
}

//returns the inode number of the inode associated with fd//
int inumber(int fd){
    struct file_desc *check = findFile(thread_current(), fd);

    if(check == NULL){
        return 0;
    }

    return file_inumber(check->file);
}

void
inversion(const char *relative, char *buffer)
{
  if (*relative == '/') {
    strlcpy (buffer, relative, strlen(relative)+1);
    return;
  }

  int k = 0;
  char *save_ptr;
  char **rel_splitStrings = (char **)malloc(sizeof(char)*512);
  char **cur_splitStrings = (char **)malloc(sizeof(char)*512);

  char *rel_copy = (char *)malloc(sizeof(char)*512);
  char *cur_copy = (char *)malloc(sizeof(char)*512);

  /* Tokenize the relative path and process' current path */
  strlcpy (rel_copy, relative, strlen(relative)+1);
 
    int i = tokenize(rel_splitStrings, rel_copy, save_ptr) + 1;
  strlcpy (cur_copy, thread_current()->directory, strlen(thread_current()->directory)+1);
  
    int j = tokenize(cur_splitStrings, cur_copy, save_ptr) + 1;
  /* Change cur_splitStrings to hold the absolute path */
  for (k = 0; k < i; k++) {
    if (strcmp(rel_splitStrings[k], ".") == 0){
    } else if (strcmp(rel_splitStrings[k], "..") == 0) {
      if (j > 0) {
        cur_splitStrings[j-1] = NULL;
        j--;
      }
    } else {
      cur_splitStrings[j] = rel_splitStrings[k];
      j++;
    }
  }

  /* Copy the absolute path into BUFFER */
  if (j == 0) {
    strlcpy (buffer, "/", 2);
  } else {
    strlcpy (buffer, "", 1);
    for (k = 0; k < j; k++) {
      strlcat (buffer, "/", strlen(buffer)+2);
      strlcat (buffer, cur_splitStrings[k], strlen(buffer)+strlen(cur_splitStrings[k])+1);
    }
  }

  free (rel_splitStrings);
  free (cur_splitStrings);
  free (rel_copy);
  free (cur_copy);
}
//terminates user status and returns status to the kernel
void exit(int status){  
    struct thread *cur = thread_current();
    cur->status_stop = status; //exiting the current thread with the current status
    thread_exit();   
}

//waits for child process pid and retrieves child exit status.
int wait(pid_t pid){
    return process_wait(pid); //waiting on the current process
}

//runs executable whose name is given in the cmd line
pid_t exec (const char *cmd_line){
    if (!cmd_line){
        return -1;
    }

    //checks if cmd_line is valid   
    if(!user_check(cmd_line)){
        exit(-1);
    }      

    static char *cmd_line_;
    cmd_line_ = copy_in_string(cmd_line);   
    int pid = process_execute(cmd_line);

    if (pid == TID_ERROR)
        return -1;

    return pid;
}


//opens a file
int open (const char *file){
    bool check = user_check((void *) file);

    if (!check){
        exit(-1);
    }

    char **splitStrings = (char **)malloc(sizeof(char)*512);
    char *real = (char *)malloc(sizeof(char)*512);
    struct inode *inode;
    struct dir *parent;
    char *token;
    char *save;
    bool result = true;

    inversion(file, real);

    int i =tokenize(splitStrings, real, save);

    if(splitStrings[i] == NULL){
        struct file_desc *new = palloc_get_page(0);
        new->fd = thread_current()->fd;
        thread_current()->fd++;
        new->file = (struct file *) dir_open_root();

        if(new->file == NULL) {
            palloc_free_page(new);
            free(splitStrings);  
            free(real);
            return -1;
        }
        new->directory = file_isdir(new->file);
        list_push_back(&thread_current()->fds, &new->elem);
        free (splitStrings);  
        free (real);
        return new->fd;
    }

    parent = dir_open_root();

    for(int j=0; j<i; j++) {
        if(!dir_lookup (parent, splitStrings[j], &inode)) {
            result = false;
            break;
        }

        dir_close (parent);
        parent = dir_open(inode);
    }

    if (result) {
        struct file_desc *new = palloc_get_page(0);
        new->fd = thread_current()->fd;
        thread_current()->fd++;

        lock_acquire(&filesys_lock);
        new->file = filesys_open(splitStrings[i], true, parent);
        lock_release(&filesys_lock);

        if (new->file == NULL) {
            palloc_free_page(new);
            dir_close(parent);
            free(real);
            free(splitStrings);  
            return -1;
        }

        new->directory = file_isdir(new->file);
        list_push_back(&thread_current()->fds, &new->elem);
        dir_close(parent);
        free(splitStrings);  
        free(real);
        return new->fd;
    }

  dir_close(parent);
  free(real);
  free(splitStrings);  
  return -1;
}

//removes a file
bool remove (const char *file){
    if (!user_check(file)){
        exit (-1);
    }

    char **splitStrings = (char **)malloc(sizeof(char)*512);
    char *real = (char *)malloc(sizeof(char)*512);
    bool result = true;
   
    char *token;
    char *save_ptr;
    struct dir *parent;
    struct inode *inode;
    
    inversion(file, real);

    

    int i = tokenize(splitStrings, real, save_ptr);

    if (splitStrings[i] == NULL) {
        /* Not a valid file name */
        free (splitStrings);  
        free (real);
        return false;
    }

    parent = dir_open_root ();
    for (int j = 0; j < i; j++) {
        if(!dir_lookup (parent, splitStrings[j], &inode)) {
            result = false;
            break;
        }
        dir_close (parent);
        parent = dir_open (inode);
    }
    if (result) {
        lock_acquire (&filesys_lock);
        result = filesys_remove(splitStrings[i],true, parent);
        lock_release (&filesys_lock);
    }

    dir_close (parent);

    free (splitStrings);  
    free (real);
    return result;
}

//create a new file with file size
bool create (const char *file, unsigned initial_size){
    if (!user_check(file)){
        exit (-1);
    }

    char **splitStrings = (char **)malloc(sizeof(char)*512);
    char *real = (char *)malloc(sizeof(char)*512);
    bool result = true;

    char *token;
    char *save_ptr;
    struct dir *parent;
    struct inode *inode;

    inversion(file, real);



    int i = tokenize(splitStrings, real, save_ptr);

    if (splitStrings[i] == NULL) {
        /* Not a valid file name */
        free (splitStrings);  
        free (real);
        return false;
    }

    parent = dir_open_root ();
    for (int j = 0; j < i; j++) {
        if(!dir_lookup (parent, splitStrings[j], &inode)) {
            result = false;
            break;
        }
        dir_close (parent);
        parent = dir_open (inode);
    }
    if (result) {
        lock_acquire (&filesys_lock);
        result = filesys_create(splitStrings[i], initial_size,true, parent);
        lock_release (&filesys_lock);
    }

    dir_close (parent);
    free (splitStrings);  
    free (real);
    return result;
    }
//returns true if fd represents a directory, false if a ordinary file//
bool isdir(int fd){
    struct file_desc *fdesc = findFile(thread_current(), fd);

    if(fdesc == NULL){
        return false;

    }else{
        return file_isdir(fdesc->file);
    }
}
//reads a file
int read (int fd, void *buffer, unsigned size){
    int bytecount = 0;
    bool check = user_check(buffer);

    if (!check){
        exit(-1);
    }
    
    if (fd == 0)
    {
        int iter;
        for (iter = 0; iter < size; iter++)
            input_getc();
        return size;
    }
    else{
        struct file_desc *fdesc = findFile(thread_current(), fd);

        if (fdesc == NULL){
            return -1;
        }

        lock_acquire (&filesys_lock);
        bytecount = file_read (fdesc->file, buffer, size);/*Thread blocking the file so no other one tries to access it*/
        lock_release (&filesys_lock);
    }

    return bytecount;
}

void close (int fd){
    struct file_desc* fdesc = findFile(thread_current(), fd);

    if(fdesc == NULL){
        return;
    }
    if(fdesc->directory){
        dir_close((struct dir*)fdesc->file);
    }
    else{
        lock_acquire (&filesys_lock);
        
        file_close(fdesc->file);
        lock_release (&filesys_lock);/*Thread blocking the file so no other one tries to access it*/
    }
    list_remove(&fdesc->elem);
    palloc_free_page(fdesc);
    return;
}

void seek (int fd, unsigned position){
    struct file_desc* fdesc = findFile(thread_current(), fd);

    if(fdesc){
        lock_acquire (&filesys_lock);
        file_seek(fdesc->file, position);/*Thread blocking the file so no other one tries to access it*/
        lock_release (&filesys_lock);
    }

    return;
}

//writes to a file
int write (int fd, const void *buffer, unsigned size){
    int bytecount = 0;
    
    bool check = user_check(buffer);

    if (!check){
        exit(-1);
    }

    char *bufChar = (char *)buffer;

    if(fd == 1) {
        
        while(size > 200) {
            putbuf(bufChar, 200);
            bufChar += 200;
            size -= 200; //putting the buffer into STD_OUT
            bytecount += 200;
        }

        putbuf(bufChar, size);
        bytecount += size;

    }else{
        struct file_desc *fdesc = findFile(thread_current(), fd);
        if(fdesc->directory){
            return -1;
        }
        if (fdesc == NULL){
            return 0;
        }

        lock_acquire (&filesys_lock);
        bytecount = file_write (fdesc->file, buffer, size);/*Thread blocking the file so no other one tries to access it*/
        lock_release (&filesys_lock);
    }

    return bytecount;
}



bool chdir(const char *dir){
    if (!user_check(dir)){
        return false;
    }

    struct thread *t = thread_current ();
    char **splitStrings = (char **)malloc(sizeof(char)*512);
    char *real = (char *)malloc(sizeof(char)*512);
    bool result = true;
    char *token;
    char *save_ptr;
    struct dir *parent;
    struct inode *inode;

    inversion(dir, real);

    
    int i = tokenize(splitStrings, real, save_ptr) + 1;

    if (splitStrings[i] == NULL) {
        strlcpy (t->directory, "/", 2);
        free (splitStrings);  
        free (real);
        return true;
    }

    /* Make sure the directory exists */
    parent = dir_open_root ();

    for (int j = 0; j < i; j++) {
        if(!dir_lookup (parent, splitStrings[j], &inode)) {
            result = false;
            break;
        }

        dir_close (parent);
        parent = dir_open (inode);
    }

    if (result) {
        strlcpy (t->directory, "", 1);
        for (int j = 0; j < i; j++) {
            strlcat (t->directory, "/", strlen(t->directory)+2);
            strlcat (t->directory, splitStrings[j], strlen(t->directory)+strlen(splitStrings[j])+1);
        }
    }

    dir_close (parent);
    free (splitStrings);  
    free (real);
    return result;
    }

//creates the directory named dir. Fails if dir already exists//
bool mkdir(const char *dir){
    if (!user_check(dir)){
        return false;
    }

    char **splitStrings = (char **)malloc(sizeof(char)*512);
    char *real = (char *)malloc(sizeof(char)*512);
    bool result = true;
   
    block_sector_t s;
    char *token;
    char *save;
    struct dir *parent;
    struct inode *inode;

    inversion(dir, real);

    
    int i = tokenize(splitStrings, real, save);
    if (splitStrings[i] == NULL) {
        free (splitStrings);  
        free (real);
        return false;
    }

    parent = dir_open_root();

    for (int j = 0; j < i; j++) {
        if(!dir_lookup (parent, splitStrings[j], &inode)) {
            result = false;
            break;
        }

        dir_close (parent);
        parent = dir_open (inode);
    }

    if (result && !dir_lookup (parent, splitStrings[i], &inode)) {
        if (free_map_allocate(1, &s)) {
        if (dir_create(s, 16)) {
            result = dir_add(parent, splitStrings[i], s);
        } else {
            result = false;
        }

        } else{
        result = false;
        }
    } else{
        result = false;
    }

    dir_close (parent);
    free (splitStrings);  
    free (real);
    return result;
}


//reads a directory entry from file descriptor fd//
bool readdir(int fd, char *name){
    if(!user_check(name)){
        exit(-1);
    }

    struct file_desc *check = findFile(thread_current(), fd);
    if((check == NULL) || (!check->directory)){
        return false;
    }

    return dir_readdir((struct dir *)check->file, name);
}






//HELPER IMPLEMENTATION//
static bool user_check(const char *uaddr){       //checks to see if user memory is valid
    if(!verify_user(uaddr)){
        return false;
    }
    return true;
}