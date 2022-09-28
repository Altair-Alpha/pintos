#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);
static void syscall_halt(struct intr_frame *) NO_RETURN;
static void syscall_exit(struct intr_frame *) NO_RETURN;
static void syscall_exec(struct intr_frame *);
static void syscall_wait(struct intr_frame *);

static void syscall_create(struct intr_frame *);

static void syscall_write(struct intr_frame *);

static void *check_read_user_ptr(void *, size_t);
static bool check_user_str(void *);

// static bool check_write_user_ptr(const void *, const void *, size_t);

static int get_user (const uint8_t *);
static bool put_user (uint8_t *, uint8_t);

static void terminate_process(void);

static size_t ptr_size = sizeof(void *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  // printf("CHECK SYSCALL\n");
  // if (!check_read_user_ptr(f->esp, sizeof(int))) {
  //   // printf("INVALID SYSCALL\n");
  //   terminate_process();
  // }

  int syscall_type = *(int *)check_read_user_ptr(f->esp, sizeof(int));//f->esp;
  // printf ("system call! TYPE: %d\n", syscall_type);
  switch (syscall_type)
  {
  case SYS_HALT:
    syscall_halt(f);
    break;
  case SYS_EXIT:
    syscall_exit(f);
    break;
  case SYS_EXEC:
    syscall_exec(f);
    break;
  case SYS_WAIT:
    syscall_wait(f);
    break;
  case SYS_CREATE:
    syscall_create(f);
  case SYS_WRITE:
    syscall_write(f);
    break;
  
  default:
    // printf("OTHER SYSCALL: %d\n", syscall_type);
    break;
    NOT_REACHED();
  }
  // thread_exit ();
}

static void 
syscall_halt(struct intr_frame *f UNUSED)
{
  shutdown_power_off();
}

static void 
syscall_exit(struct intr_frame *f)
{
  // exit_code is passed as ARG0, after syscall number
  // if (!check_read_user_ptr(f->esp + ptr_size, sizeof(int))) {
  //   terminate_process();
  // }
  int exit_code = *(int *)check_read_user_ptr(f->esp + ptr_size, sizeof(int));
  // printf("EXIT CODE: %d\n", exit_code);
  thread_current()->exit_code = exit_code;
  thread_exit();
}

static void 
syscall_exec(struct intr_frame *f)
{
  // if (!check_read_user_ptr(f->esp + ptr_size, ptr_size)) {
  //   terminate_process();
  // }
  char *cmd = *(char **)check_read_user_ptr(f->esp + ptr_size, ptr_size);
  if (!check_user_str(cmd)) {
    terminate_process();
  }
  // printf("EXEC %s\n", cmd);
  f->eax = process_execute(cmd);
}

static void 
syscall_wait(struct intr_frame *f)
{
  // if (!check_read_user_ptr(f->esp + ptr_size, sizeof(int))) {
  //   terminate_process();
  // }
  int pid = *(int *)check_read_user_ptr(f->esp + ptr_size, sizeof(int));
  f->eax = process_wait(pid);
}

static void 
syscall_create(struct intr_frame *f)
{
  // return;
  char *file_name = *(char **)check_read_user_ptr(f->esp + ptr_size, ptr_size);
  if (!check_user_str(file_name)) {
    terminate_process();
  }
  
  unsigned file_size = *(unsigned *)check_read_user_ptr(f->esp + 2 * ptr_size, sizeof(unsigned));
  
  f->eax = filesys_create(file_name, file_size);
}

static void 
syscall_write(struct intr_frame *f)
{
  int fd = *(int *)(f->esp + ptr_size);
  char *buf = *(char **)(f->esp + 2*ptr_size);
  int size = *(int *)(f->esp + 3*ptr_size);

  if (fd == 1) { // write to stdout
    putbuf(buf, size);
    f->eax = size;
  }
}

/** Check if a user-provided pointer is valid. Return the pointer itself if safe, 
 * or call terminate_process() (which do not returns) to kill the process. */
static void * 
check_read_user_ptr(void *ptr, size_t size)
{
  if (!is_user_vaddr(ptr)) {
    terminate_process();
  }
  for (size_t i = 0; i < size; i++) {
    // printf("CHECK %p\n", ptr+i);
    if (get_user(ptr + i) == -1) {
      terminate_process();
    }
  }
  return ptr;
}

static bool 
check_user_str(void *ptr)
{
  if (!is_user_vaddr(ptr)) return false;

  uint8_t *str = (uint8_t *)ptr;
  while (true) {
    int c = get_user(str);
    // printf("CHAR %c AT %p\n", c, str);
    if (c == -1) {
      // printf("PAGE FAULT AT BYTE %p\n", str);
      return false;
    } else if (c == '\0') {
      return true;
    }
    ++str;
  }
  return true;
}

// static bool 
// check_write_user_ptr(const void *ptr, const void *data, size_t size)
// {
//   if (!is_user_vaddr(ptr)) return false;

//   for (size_t i = 0; i < size; i++) {
//     if (!put_user(ptr + i, *(data + i))) {
//       printf("PAGE FAULT WRITE BYTE %p\n", ptr+i);
//       return false;
//     }
//   }
//   return true;
// }

// static bool is_valid_str(const char *str)
// {
//     if (!check_user_ptr(str))
//         return false;

//     for (const char *c = str; *c != '\0';)
//     {
//         ++c;
//         if (c - str + 2 == PGSIZE || !check_user_ptr(c))
//             return false;
//     }

//     return true;
// }

// static bool is_user_mem(const void *start, size_t size)
// {
//     for (const void *ptr = start; ptr < start + size; ptr += PGSIZE)
//     {
//         if (!check_user_ptr(ptr))
//             return false;
//     }

//     if (size > 1 && !check_user_ptr(start + size - 1))
//         return false;

//     return true;
// }

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

static void 
terminate_process(void)
{
  thread_current()->exit_code = -1;
  thread_exit();
  NOT_REACHED();
}