#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

typedef int pid_t;

void syscall_init(void);
int filesize (int);
void halt(void);
void exit(int);
int wait(pid_t pid);
void seek (int fd, unsigned position);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
pid_t exec (const char *cmd_line);
int write (int fd, const void *buffer, unsigned size);
unsigned tell (int fd);
void close (int);
int read (int fd, void *buffer, unsigned size);

void inversion(const char *relative, char* buffer);
bool chdir(const char *);
bool mkdir(const char *);
bool readdir(int, char *);
bool isdir(int);
int inumber(int);

#endif /* userprog/syscall.h */