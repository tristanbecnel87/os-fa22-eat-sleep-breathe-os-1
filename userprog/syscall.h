#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);
void exit(int status);
//static void syscall_handler (struct intr_frame *);

#endif /* userprog/syscall.h */

// #ifndef USERPROG_SYSCALL_H
// #define USERPROG_SYSCALL_H

// #include <stdbool.h>

// /* Thread identifier type.
//  * You can redefine this to whatever type you like. */
// typedef int pid_t;
// #define PID_ERROR ((pid_t)-1) /* Error value for tid_t. */


// void syscall_init(void);
// void halt(void);
// void exit(int status);
// pid_t exec(const char*cmd_line);
// int wait(pid_t pid);
// bool create(const char *file, unsigned initial_size);
// bool remove(const char *file);
// int open(const char *file);
// int filesize(int fd);
// int read(int fd, void *buffer, unsigned size);
// int write(int fd, const void *buffer, unsigned size);
// void seek(int fd, unsigned position);
// unsigned tell(int fd);
// void close(int fd);


// #endif /* userprog/syscall.h */
