#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

void syscall_init (void);
void close_all_files (void);
void exit (int status);
#endif /* userprog/syscall.h */