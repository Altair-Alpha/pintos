#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);
static void syscall_exit(struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int syscall_type = *(int *)f->esp;
  // printf ("system call! TYPE: %d\n", syscall_type);
  switch (syscall_type)
  {
  case SYS_HALT:
    /* code */
    break;
  case SYS_EXIT:
    syscall_exit(f);
    break;
  
  case SYS_WRITE:
    // printf("WRITE\n");
    break;
  
  default:
    break;
  }
  // thread_exit ();
}

static void 
syscall_halt(struct intr_frame *f)
{
  
}

static void 
syscall_exit(struct intr_frame *f)
{
  // exit_code is passed as ARG0, after syscall number
  int exit_code = *(int *)(f->esp + sizeof(void *));
  // printf("EXIT CODE: %d\n", exit_code);
  thread_current()->exit_code = exit_code;
  thread_exit();
}