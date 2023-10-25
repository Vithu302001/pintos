#include "userprog/syscall.h"
#include <stdio.h>
#include <user/syscall.h>
#include <syscall-nr.h>
#include "threads/thread.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "process.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"


static void syscall_handler (struct intr_frame *);
static int get_user_addr(const uint8_t *user_addr);
static void memoryStack(uint8_t *user_addr, uint8_t *ptr_arg, size_t argumentSize);
int syscall_write(int x, const void *ptr_buffer, unsigned size);
int syscall_create(const char *file, unsigned initial_size);
int syscall_read(int x, void *ptr_buffer, unsigned size);
void syscall_close(int x);
pid_t syscall_exec (const char * file);
void system_exit(int status_code);
int syscall_open(const char *file);



void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void memoryStack(uint8_t *user_addr, uint8_t *ptr_arg, size_t argumentSize)
{
  int32_t address;

  for (int j = 0; j < argumentSize; j++)
  {
    address = get_user_addr(user_addr + j);
    if (address == -1)
    {
      printf("Failure in Acessing Memory!!\n");
      thread_exit();
    }

    *(char *)(ptr_arg + j) = address & 0xff;
  }
}


static void
syscall_handler (struct intr_frame *f UNUSED) 
{
     int system_call_number;
     int sys_call_num_size  = sizeof(system_call_number);
    memoryStack(f->esp, &system_call_number, sys_call_num_size);

    switch  (system_call_number)
    {
    case SYS_HALT:
    {
        shutdown_power_off();
        NOT_REACHED();
        break;
    }
    case SYS_EXEC:
    {
        char *cmd_line;
        memoryStack(f->esp + 4, &cmd_line, sizeof(cmd_line));
        f->eax = (uint32_t)syscall_exec(cmd_line);
        break;
    }
    case SYS_EXIT:
    {
        int exitStatus;
        memoryStack(f->esp + 4, &exitStatus, sizeof(exitStatus));
        system_exit(exitStatus);

        NOT_REACHED();

        break;
    }
    case SYS_WAIT:
    {
        pid_t process_id;
        memoryStack(f->esp + 4, &process_id, sizeof(pid_t));

        f->eax = (uint32_t)process_wait(process_id);
        break;
    }
    case SYS_WRITE:
    {
        
        unsigned size;
        const void *ptr_buffer;
        int x;

        memoryStack(f->esp + 4, &x, sizeof(x));

        memoryStack(f->esp + 8, &ptr_buffer, sizeof(ptr_buffer));
        memoryStack(f->esp + 12, &size, sizeof(size));
        f->eax = (uint32_t)syscall_write(x, ptr_buffer, size);

        break;
    }
    case SYS_CREATE:
    {
        char *file;
        int initial_size;
        memoryStack(f->esp + 4, &file, sizeof(file));

        memoryStack(f->esp + 8, &initial_size, sizeof(initial_size));
        f->eax = (uint32_t)syscall_create(file, initial_size);
        break;
    }
    
    case SYS_OPEN:
    {
        char *file;
        memoryStack(f->esp + 4, &file, sizeof(file));

        f->eax = (uint32_t)syscall_open(file);
        break;
    }
    
    case SYS_READ:
    {
        unsigned size;
        int x;
        void *ptr_buffer;
        
        memoryStack(f->esp + 4, &x, sizeof(x));

        memoryStack(f->esp + 8, &ptr_buffer, sizeof(ptr_buffer));

        memoryStack(f->esp + 12, &size, sizeof(size));

        f->eax = (uint32_t)syscall_read(x, ptr_buffer, size);
        break;
    }
    case SYS_CLOSE:
    {
        int x;

        memoryStack(f->esp + 4, &x, sizeof(x));

        syscall_close(x);

        break;
    }
    default:
    {
        printf("System call implementation not found!\n");
        thread_exit();
    }
    }
}







int syscall_write(int x, const void *ptr_buffer, unsigned size)
{
  struct list_elem *listElement;


  struct thread *currentThread=thread_current();

	if(x == 1)
	{
		putbuf(ptr_buffer, size);

    return size;
	}
  
  for (listElement = list_front(&currentThread->file_descriptors); listElement != NULL; listElement = listElement->next)
  {
      struct description_file *file_Desc = list_entry (listElement, struct description_file, element);
      if (file_Desc->file_id == x)
      {
        int bytes_written = (int) file_write(file_Desc->ptr_file, ptr_buffer, size);
        return bytes_written;
      }
  }
  return -1;
}

int syscall_create(const char *ptr_file, unsigned initial_size)
{
    

   bool fileStatus = filesys_create(ptr_file, initial_size);

   return fileStatus;

}



int syscall_open(const char *file)
{
  struct description_file *file_description;
   struct file *openFile;

  openFile = filesys_open(file);

  if (!openFile){
    return -1;
  }

  file_description = malloc(sizeof(struct description_file));

  file_description -> ptr_file = openFile;

  struct list *fileList = &thread_current ()->file_descriptors;

  if (list_empty(fileList)){
    file_description ->file_id = 2;
  }else{
    file_description -> file_id = (list_entry(list_back(fileList), struct description_file, element) -> file_id) +1;
  }
  list_push_back(fileList, &file_description ->element);

  return file_description->file_id;
}



int syscall_read(int x, void *buffer, unsigned size)
{
  struct list_elem *listElement;

  struct thread *currentThread=thread_current();

  if (x == 0)
  {
    return (int) input_getc();
  }

  if (x == 1 || list_empty(&currentThread->file_descriptors))
  {
    return 0;
  }

  for (listElement = list_front(&currentThread->file_descriptors); listElement != NULL; listElement = listElement->next)
  {
      struct description_file *file_Desc = list_entry (listElement, struct description_file, element);
      if (file_Desc->file_id == x)
      {
        int bytes = (int) file_read(file_Desc->ptr_file, buffer, size);
        return bytes;
      }
  }
  return -1;
}




void syscall_close (int x)
{
  


  struct list_elem *listElement;
  struct thread *currThread=thread_current();

  if (list_empty(&currThread->file_descriptors))
  {
    return;
  }

  for (listElement = list_front(&currThread->file_descriptors); listElement != NULL; listElement = listElement->next)
  {
      struct description_file *file_Description = list_entry (listElement, struct description_file, element);
      if (file_Description->file_id == x)
      {
        file_close(file_Description->ptr_file);
        list_remove(&file_Description->element);
        return;
      }
  }

  return;
}



static int get_user_addr(const uint8_t *user_addr)//Reads a byte from the user's virtual address specified as user_addr. The user_addr must be within the valid address range, which should be below PHYS_BASE. If the operation is successful, it returns the value of the byte that was read. However, if a segmentation fault (segfault) occurs, it returns -1 to indicate an error.
{
  int result_code;
  asm("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a"(result_code)
      : "m"(*user_addr));
  return result_code;
}


pid_t syscall_exec (const char * ptr_file)
{
	if(!ptr_file)
	{
		return -1;
	}
	pid_t thread_id_child = process_execute(ptr_file);
	return thread_id_child;
} 


void system_exit(int status_code)
{
  struct thread *currThread = thread_current();
  if (status_code < 0){
    status_code = -1;
  }
  printf("%s: exit(%d)\n", currThread->name, status_code); 
  thread_exit();
}