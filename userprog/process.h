#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
void setDirectory(struct thread* t, bool rootOrChild);
struct file_desc* findFile(struct thread* t, int fd);
#endif /* userprog/process.h */