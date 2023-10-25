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

  
};


//creating structure for PCB(process control block)

struct PCB{
    pid_t process_id; //PID

    struct list_elem element; //list_elem structure to store element
    const char *ptr_command_line; 
    struct thread *ptr_parent_process; // process's parent
    bool is_exit;
    int32_t exit_code;
    bool is_wait;
    
    struct semaphore semaphore_wait;  //until the child exit block the process

};

#endif /* userprog/process.h */
