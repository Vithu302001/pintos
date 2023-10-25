#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H


#include "threads/synch.h"
#include "threads/thread.h"

#include <user/syscall.h>


tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct  description_file{
    struct list_elem element;
    int file_id;
    struct file *ptr_file;

  
}


//creating structure for PCB(process control block)



#endif /* userprog/process.h */
