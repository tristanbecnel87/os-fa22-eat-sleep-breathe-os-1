#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/tss.h"

#define LOGGING_LEVEL 6

#include <log.h>

static thread_func start_process NO_RETURN;
static bool load(const char *cmdline, void(**eip) (void), void **esp);

// Duplicate a string
char *strdup(const char *s)
{
    size_t slen = strlen(s);
    char *result = malloc(slen + 1);
    if (result == NULL)
    {
        return NULL;
    }

    memcpy(result, s, slen + 1);
    return result;
}

static void check_lock(void);
static void remove_File(void);


struct file_desc* findFile(struct thread* t, int fd){     //find a file 
    if((t == NULL) || (fd < 3)){
        return NULL;
    }


    if(!list_empty(&t->fds)){
        struct list_elem *e;
 
      for (e = list_begin (&t->fds); e != list_end (&t->fds); e = list_next (e))
      {
        struct file_desc *f = list_entry(e, struct file_desc, elem);
        
        if(fd == f->fd){
            return f;
        }
      }
    }
    
    return NULL;
}

void setDirectory(struct thread* t, bool rootOrChild){

    if(t->directory != NULL){
        return;
    }
    else{
        t->directory = (char *)palloc_get_page(0);       
    }

    if(rootOrChild){
        strlcpy(t->directory, "/", 2);
    }
    
}
/* Starts a new thread running a user program loaded from
 * FILENAME.  The new thread may be scheduled (and may even exit)
 * before process_execute() returns.  Returns the new process's
 * thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute(const char *file_name){
    char *fn_copy;
    
    tid_t tid;
    
    // NOTE:
    // To see this print, make sure LOGGING_LEVEL in this file is <= L_TRACE (6)
    // AND LOGGING_ENABLE = 1 in lib/log.h
    // Also, probably won't pass with logging enabled.
    log(L_TRACE, "Started process execute: %s", file_name);

    /* Make a copy of FILE_NAME.
     * Otherwise there's a race between the caller and load(). */
    fn_copy = palloc_get_page(0);
    if (fn_copy == NULL) {
        return TID_ERROR;
    }
    
    strlcpy(fn_copy, file_name, PGSIZE);
      
    /* Create a new thread to execute FILE_NAME. */
    tid = thread_create(file_name, PRI_DEFAULT, start_process, fn_copy);    
    
    struct thread* youngin = NULL;
    if (tid == TID_ERROR) {
        palloc_free_page(fn_copy);
    }
    else{
        youngin = get_thread (tid);
    }
    struct thread* current = thread_current();   
  /* Add the child thread to parent's children list and wait
     to see if the child loaded correctly */
  if (youngin != NULL) {
    list_push_back(&current->inheritors, &youngin->inheritorelem);
    sema_down (&youngin->load);
    
    if(youngin->status_load == -1) {   
      tid = TID_ERROR;
    }
    
    setDirectory(current, true);
    setDirectory(youngin, false);
    strlcpy(youngin->directory, current->directory, strlen(current->directory)+1);
  }
    //printf("%s\n", current->directory);
    return tid;
}

/* A thread function that loads a user process and starts it
 * running. */
static void start_process(void *file_name_){
    char *file_name = file_name_;
    struct intr_frame if_;
    bool success;
    struct thread *t = thread_current();
    
    log(L_TRACE, "start_process()");
  

    /* Initialize interrupt frame and load executable. */
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    success = load(file_name, &if_.eip, &if_.esp);

    /* If load failed, quit. */
    palloc_free_page(file_name);
    if (!success) {
        t->status_load = -1;
        sema_up (&t->load);
        thread_exit();
    }
    sema_up (&t->load);
    /* Start the user process by simulating a return from an
     * interrupt, implemented by intr_exit (in
     * threads/intr-stubs.S).  Because intr_exit takes all of its
     * arguments on the stack in the form of a `struct intr_frame',
     * we just point the stack pointer (%esp) to our stack frame
     * and jump to it. */
    asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
    NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
tid_t process_wait(tid_t child_tid){

    struct thread *t = thread_current ();
    int exit_status;
    struct list_elem *parser = list_begin (&t->inheritors);
    struct thread *youngin = NULL;
  
    //printf("made it here 1!\n");
  /* Get child whose tid is tid if one exists */

    for (; parser != list_end (&t->inheritors); parser = list_next (parser)){
        
        youngin = list_entry (parser, struct thread, inheritorelem);
     
        if(youngin->tid == child_tid){
            goto moveon;
        }
    }
    moveon:

    if(parser == list_end(&t->inheritors)){ 
        return -1;
    }
    list_remove(&youngin->inheritorelem);
    
    sema_down(&youngin->wait);
 
    exit_status = youngin->status_stop;

    sema_up(&youngin->stop);
  
    return exit_status;
}

/* Free the current process's resources. */
void process_exit(void){
    
    struct thread *curThread = thread_current ();
    
    check_lock();
  
    remove_File();

     if(curThread->instruction != NULL){
        printf("%s: exit(%d)\n", curThread->instruction, curThread->status_stop);
     }
     
    sema_up (&curThread->wait);

    struct thread *youngin = NULL;

    struct list_elem *parser = list_begin (&curThread->inheritors);
    
    for(; parser != list_end (&curThread->inheritors); parser = list_next (parser)){
      
      youngin = list_entry(parser, struct thread, inheritorelem);
      sema_up (&youngin->stop);
      sema_down (&youngin->wait);
      
    }
    /* Destroy the current process's page directory and switch back
     * to the kernel-only page directory. */
    uint32_t *pd;
    pd = curThread->pagedir;
    palloc_free_page(curThread->directory);
    sema_down (&curThread->stop);
    //palloc_free_page (cur->instruction);
    if (pd != NULL) {
        /* Correct ordering here is crucial.  We must set
         * cur->pagedir to NULL before switching page directories,
         * so that a timer interrupt can't switch back to the
         * process page directory.  We must activate the base page
         * directory before destroying the process's page
         * directory, or our active page directory will be one
         * that's been freed (and cleared). */
        curThread->pagedir = NULL;
        pagedir_activate(NULL);
        pagedir_destroy(pd);
    }
}

/* Sets up the CPU for running user code in the current
 * thread.
 * This function is called on every context switch. */
void process_activate(void){
    struct thread *t = thread_current();

    /* Activate thread's page tables. */
    pagedir_activate(t->pagedir);

    /* Set thread's kernel stack for use in processing
     * interrupts. */
    tss_update();
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
 * There are e_phnum of these, starting at file offset e_phoff
 * (see [ELF1] 1-6). */
struct Elf32_Phdr {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0          /* Ignore. */
#define PT_LOAD    1          /* Loadable segment. */
#define PT_DYNAMIC 2          /* Dynamic linking info. */
#define PT_INTERP  3          /* Name of dynamic loader. */
#define PT_NOTE    4          /* Auxiliary info. */
#define PT_SHLIB   5          /* Reserved. */
#define PT_PHDR    6          /* Program header table. */
#define PT_STACK   0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void **esp, const char *command);

static bool validate_segment(const struct Elf32_Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *EIP
 * and its initial stack pointer into *ESP.
 * Returns true if successful, false otherwise. */
bool load(const char *file_name, void(**eip) (void), void **esp){
    log(L_TRACE, "load()");
    struct thread *t = thread_current();
    struct Elf32_Ehdr ehdr;
    struct file *file = NULL;
    off_t file_ofs;
    bool success = false;
    int i;
    
    /* Allocate and activate page directory. */
    t->pagedir = pagedir_create();
    if (t->pagedir == NULL) {
        goto done;
    }
    process_activate();
    /* Open executable file. */

    char* fn_copy = palloc_get_page(0);
    if (fn_copy == NULL) {
        return TID_ERROR;
    }
    
    strlcpy(fn_copy, file_name, PGSIZE);
    char* saveptr;
    char* file_new = strtok_r(fn_copy, " ", &saveptr );
   
  
    file = filesys_open(file_new, false, NULL);
    
     
  
    t->instruction = palloc_get_page (0);
    strlcpy(t->instruction, file_new, strlen(file_new)+1);
   
    
    
    if (file == NULL) {
        printf("load: %s: open failed\n", file_name);
        goto done;
    }
    
    file_deny_write(file);
 
    
    struct file_desc* thisOne = palloc_get_page(0);
    thisOne->file = file;
    thisOne->fd = t->fd;
    t->fd++;
    list_push_back(&t->fds, &thisOne->elem);
    

    palloc_free_page(fn_copy);

    /* Read and verify executable header. */
    if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr
        || memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7)
        || ehdr.e_type != 2
        || ehdr.e_machine != 3
        || ehdr.e_version != 1
        || ehdr.e_phentsize != sizeof(struct Elf32_Phdr)
        || ehdr.e_phnum > 1024) {
        printf("load: %s: error loading executable\n", file_name);
        goto done;
    }

    /* Read program headers. */
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++) {
        struct Elf32_Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length(file)) {
            goto done;
        }
        file_seek(file, file_ofs);

        if (file_read(file, &phdr, sizeof phdr) != sizeof phdr) {
            goto done;
        }
        file_ofs += sizeof phdr;
        switch (phdr.p_type) {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
            /* Ignore this segment. */
            break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
            goto done;
        case PT_LOAD:
            if (validate_segment(&phdr, file)) {
                bool writable = (phdr.p_flags & PF_W) != 0;
                uint32_t file_page = phdr.p_offset & ~PGMASK;
                uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
                uint32_t page_offset = phdr.p_vaddr & PGMASK;
                uint32_t read_bytes, zero_bytes;
                if (phdr.p_filesz > 0) {
                    /* Normal segment.
                     * Read initial part from disk and zero the rest. */
                    read_bytes = page_offset + phdr.p_filesz;
                    zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE)
                                  - read_bytes);
                } else {
                    /* Entirely zero.
                     * Don't read anything from disk. */
                    read_bytes = 0;
                    zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                }
                if (!load_segment(file, file_page, (void *)mem_page,
                                  read_bytes, zero_bytes, writable)) {
                    goto done;
                }
            } else {
                goto done;
            }
            break;
        }
    }
    /* Set up stack. */
    if (!setup_stack(esp, file_name)) {
        goto done;
    }

    /* Start address. */
    *eip = (void (*)(void))ehdr.e_entry;

    success = true;

done:
    /* We arrive here whether the load is successful or not. */
  
    return success;
}

/* load() helpers. */

static bool install_page(void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr *phdr, struct file *file){
    /* p_offset and p_vaddr must have the same page offset. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) {
        return false;
    }

    /* p_offset must point within FILE. */
    if (phdr->p_offset > (Elf32_Off)file_length(file)) {
        return false;
    }

    /* p_memsz must be at least as big as p_filesz. */
    if (phdr->p_memsz < phdr->p_filesz) {
        return false;
    }

    /* The segment must not be empty. */
    if (phdr->p_memsz == 0) {
        return false;
    }

    /* The virtual memory region must both start and end within the
     * user address space range. */
    if (!is_user_vaddr((void *)phdr->p_vaddr)) {
        return false;
    }
    if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz))) {
        return false;
    }

    /* The region cannot "wrap around" across the kernel virtual
     * address space. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr) {
        return false;
    }

    /* Disallow mapping page 0.
     * Not only is it a bad idea to map page 0, but if we allowed
     * it then user code that passed a null pointer to system calls
     * could quite likely panic the kernel by way of null pointer
     * assertions in memcpy(), etc. */
    if (phdr->p_vaddr < PGSIZE) {
        return false;
    }

    /* It's okay. */
    return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 *      - READ_BYTES bytes at UPAGE must be read from FILE
 *        starting at offset OFS.
 *
 *      - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable){
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    log(L_TRACE, "load_segment()");

    file_seek(file, ofs);
    while (read_bytes > 0 || zero_bytes > 0) {
        /* Calculate how to fill this page.
         * We will read PAGE_READ_BYTES bytes from FILE
         * and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* Get a page of memory. */
        uint8_t *kpage = palloc_get_page(PAL_USER);
        if (kpage == NULL) {
            return false;
        }

        /* Load this page. */
        if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
            palloc_free_page(kpage);
            return false;
        }
        memset(kpage + page_read_bytes, 0, page_zero_bytes);

        /* Add the page to the process's address space. */
        if (!install_page(upage, kpage, writable)) {
            palloc_free_page(kpage);
            return false;
        }

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
 * user virtual memory. */
static bool
setup_stack(void **esp, const char *command)
{
    uint8_t *kpage;
    bool success = false;

    log(L_TRACE, "setup_stack()");

    kpage = palloc_get_page(PAL_USER | PAL_ZERO);

    setDirectory(thread_current(), true);

    if (kpage != NULL)
    {
        uint8_t *upage = ((uint8_t *)PHYS_BASE) - PGSIZE;
        success = install_page(upage, kpage, true);
        if (success)
        {
            *esp = PHYS_BASE;

            const char *arguments[80];       // Hold arguments for program
            const char *arguments_stack[80]; // Hold addresses of arguments in the stack

            // Parser to split command into arguments
            char *cl_copy, *to_free, *token, *save_ptr;
            cl_copy = to_free = strdup(command);

            int i = 0;
            while ((token = strtok_r(cl_copy, " ", &save_ptr)))
            {
                arguments[i] = token;
                i++;
                cl_copy = NULL;
            }
            arguments[i] = NULL;

            /*Write each argument (including the executable name) in reverse order, as well as in reverse
            for each string, to the stack.*/
            int copy_i = i - 1;
            while (copy_i != -1)
            {
                *esp -= 1;                                                                            // For null character
                *esp -= strlen(arguments[copy_i]);                                                    // Save memory space for argument
                arguments_stack[copy_i] = memcpy(*esp, arguments[copy_i], strlen(arguments[copy_i])); // Write argument to stack
                copy_i--;
            }

            // The necessary number of 0s to word-align to 4 bytes
            size_t word_align = ((size_t)*esp) % sizeof(char *);
            *esp -= word_align;
            memset(*esp, 0, word_align);

            // The last argument, consisting of four bytes of 0
            *esp -= sizeof(int);
            memset(*esp, 0, sizeof(int));

            // Write the addresses pointing to each of the arguments
            copy_i = i - 1;
            char **p;
            while (copy_i != -1)
            {
                *esp -= sizeof(char *);
                p = memcpy(*esp, &arguments_stack[copy_i], sizeof(char *));
                copy_i--;
            }

            // Write the address of argv[0]
            *esp -= sizeof(char **);
            memcpy(*esp, &p, sizeof(char **));

            // Number of arguments
            *esp -= 4;
            memset(*esp, i, 1);

            // Add NULL to the start
            *esp -= sizeof(void *);
            memset(*esp, NULL, sizeof(void *));

            return success;
        }
        else
        {
            palloc_free_page(kpage);
        }
        // hex_dump( *(int*)esp, *esp, 128, true ); // NOTE: uncomment this to check arg passing
    }
}



/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool install_page(void *upage, void *kpage, bool writable){
    struct thread *t = thread_current();

    /* Verify that there's not already a page at that virtual
     * address, then map our page there. */
    return pagedir_get_page(t->pagedir, upage) == NULL
           && pagedir_set_page(t->pagedir, upage, kpage, writable);
}

static void check_lock(void){
    if(lock_held_by_current_thread(&filesys_lock)){
        lock_release (&filesys_lock);
    }
}

static void remove_File(void){
    struct file_desc *of = findFile(thread_current(),2);;
   
    if (of != NULL) {
        lock_acquire (&filesys_lock);
        file_close (of->file);
        lock_release (&filesys_lock);
        list_remove (&of->elem);
        palloc_free_page (of);
  }
}
