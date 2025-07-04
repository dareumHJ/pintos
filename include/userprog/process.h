#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
void args_stack (char **argv, int argc, void **rsp);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);
struct lazy_load_args{
    struct file *file;
    off_t ofs;
    uint32_t read_bytes;
    uint32_t zero_bytes;
};
bool lazy_load_segment (struct page *page, void *aux);

#endif /* userprog/process.h */
