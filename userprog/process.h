// #ifndef USERPROG_PROCESS_H
// #define USERPROG_PROCESS_H

// #include "threads/thread.h"
// #include "threads/synch.h"

// struct exec_helper
// {
//   char *file_name_;
//   struct semaphore ld_sema;
//   bool ld_success;
//   struct thread *parent;
// };

// static void *push(uint8_t *kpage, size_t *offset, const void *buf, size_t size );
// tid_t process_execute(const char *file_name);

// static void start_process(void *file_name);
// struct child_helper *process_get_child(tid_t child_tid);
// int process_wait(tid_t);
// void process_exit(void);
// void process_activate(void);

// #endif /* userprog/process.h */

#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

//extern char *tokens[64] = {NULL};
struct exec_helper
{
  char *file_name_;
  struct semaphore ld_sema;
  bool ld_success;
  struct thread *parent;
};

static void *push(uint8_t *kpage, size_t *offset, const void *buf, size_t size );

tid_t process_execute(const char *file_name);
static void start_process(void *file_name);
struct child_helper *process_get_child(tid_t child_tid); 
char* strdup(const char* s);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);

#endif /* userprog/process.h */
