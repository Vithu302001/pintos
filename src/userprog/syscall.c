
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include <user/syscall.h>
#include "filesys/file.h"
#include "process.h"
#include "filesys/filesys.h"
#include "lib/kernel/console.h"
#include "lib/stdbool.h"
#include "lib/stdint.h"
#include "lib/user/syscall.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

static void validate_user_address(uint8_t *user_addr, size_t size);
static int32_t get_user(const uint8_t *user_addr);
static bool put_user(uint8_t *udst, uint8_t byte);

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
    address = get_user(user_addr + j);
    if (address == -1)
    {
      printf("Failure in Acessing Memory!!\n");
      thread_exit();
    }

    *(char *)(ptr_arg + j) = address & 0xff;
  }
}


void system_exit(int statusNum)
{
  struct thread *currentThread = thread_current();
  if (statusNum < 0){
    statusNum = -1;
  }
  printf("%s: exit(%d)\n", currentThread->name, statusNum); 
  thread_exit();
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
        f->eax = (uint32_t)process_execute(cmd_line);
        break;
    }
    case SYS_EXIT:
    {
        int status;
        memoryStack(f->esp + 4, &status, sizeof(status));
        system_exit(status);

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
        int fd;
        const void *buffer;
        unsigned size;
        memoryStack(f->esp + 4, &fd, sizeof(fd));
        memoryStack(f->esp + 8, &buffer, sizeof(buffer));
        memoryStack(f->esp + 12, &size, sizeof(size));
        f->eax = (uint32_t)syscall_write(fd, buffer, size);
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
    case SYS_REMOVE:
    {
        char *file;
        copy_user_buffer((uint8_t *)&file, (uint8_t *)(f->esp + 4), sizeof(file));
        f->eax = (uint32_t)syscall_remove(file);
        break;
    }
    case SYS_OPEN:
    {
        char *file;
        memoryStack(f->esp + 4, &file, sizeof(file));
        f->eax = (uint32_t)syscall_open(file);
        break;
    }
    case SYS_FILESIZE:
    {
        int fd;
        copy_user_buffer((uint8_t *)&fd, (uint8_t *)(f->esp + 4), sizeof(fd));
        f->eax = (uint32_t)syscall_filesize(fd);
        break;
    }
    case SYS_READ:
    {
        int fd;
        void *buffer;
        unsigned size;
        memoryStack(f->esp + 4, &fd, sizeof(fd));
        memoryStack(f->esp + 8, &buffer, sizeof(buffer));
        memoryStack(f->esp + 12, &size, sizeof(size));
        f->eax = (uint32_t)syscall_read(fd, buffer, size);
        break;
    }
    case SYS_CLOSE:
    {
        int fd;
        memoryStack(f->esp + 4, &fd, sizeof(fd));
        syscall_close(fd);
        break;
    }
    default:
    {
        printf("System call implementation not found!\n");
        thread_exit();
    }
    }
}

void syscall_halt(void)
{
    shutdown_power_off();
}

void syscall_exit(int status)
{
    struct thread *current_thread = thread_current();
    if (status < 0)
    {
        status = -1;
    }
    console_lock_acquire();
    printf("%s: exit(%d)\n", current_thread->name, status);
    console_lock_release();
    thread_exit();
}

int syscall_exec(const char *cmd_line)
{
    validate_user_address((uint8_t *)cmd_line, sizeof(cmd_line));
    return process_execute(cmd_line);
}

int syscall_wait(pid_t pid)
{
    return process_wait(pid);
}

int syscall_write(int fd, const void *buffer, unsigned size)
{
  struct list_elem *listElement;


  struct thread *cuurentThread=thread_current();

	if(fd == 1)
	{
		putbuf(buffer, size);

    return size;
	}
  
  for (listElement = list_front(&cuurentThread->file_descriptors); listElement != NULL; listElement = listElement->next)
  {
      struct description_file *file_Desc = list_entry (listElement, struct description_file, element);
      if (file_Desc->file_id == fd)
      {
        int bytes_written = (int) file_write(file_Desc->ptr_file, buffer, size);
        return bytes_written;
      }
  }
  return -1;
}

int syscall_create(const char *file, unsigned initial_size)
{
    validate_user_address((uint8_t *)file, sizeof(file));
    return filesys_create(file, initial_size);
}

int syscall_remove(const char *file)
{
    validate_user_address((uint8_t *)file, sizeof(file));
    return filesys_remove(file);
}

int syscall_open(const char *file)
{
    validate_user_address((uint8_t *)file, sizeof(file));
    struct file *f = filesys_open(file);
    if (f)
    {
        int fd = process_add_file(f);
        return fd;
    }
    return -1;
}

int syscall_filesize(int fd)
{
    struct file *f = get_file(fd);
    if (f)
    {
        return file_length(f);
    }
    return -1;
}

int syscall_read(int fd, void *buffer, unsigned size)
{
  struct list_elem *listElement;

  struct thread *currentThread=thread_current();

  if (fd == 0)
  {
    return (int) input_getc();
  }

  if (fd == 1 || list_empty(&currentThread->file_descriptors))
  {
    return 0;
  }

  for (listElement = list_front(&currentThread->file_descriptors); listElement != NULL; listElement = listElement->next)
  {
      struct description_file *file_Desc = list_entry (listElement, struct description_file, element);
      if (file_Desc->file_id == fd)
      {
        int bytes = (int) file_read(file_Desc->ptr_file, buffer, size);
        return bytes;
      }
  }
  return -1;
}

void syscall_seek(int fd, unsigned position)
{
    struct file *file = get_file(fd);
    if (file)
    {
        file_seek(file, position);
    }
}

unsigned syscall_tell(int fd)
{
    struct file *file = get_file(fd);
    if (file)
    {
        return (unsigned)file_tell(file);
    }
    return -1;
}

void syscall_close(int fd)
{
    process_close_file(fd);
}

static void validate_user_address(uint8_t *user_addr, size_t size)
{
    uint8_t *max_user_addr = user_addr + size;
    for (uint8_t *p = user_addr; p < max_user_addr; p++)
    {
        if (!is_user_vaddr(p))
        {
            syscall_exit(-1);
        }
    }
}

static int get_user(const uint8_t *user_addr)
{
  int result_code;
  asm("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a"(result_code)
      : "m"(*user_addr));
  return result_code;
}

static bool put_user(uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a"(error_code), "=m"(*udst)
      : "q"(byte));
  return error_code != -1;
}


