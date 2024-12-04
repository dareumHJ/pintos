#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <debug.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/malloc.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/file.h" // include +
#include "filesys/inode.h"
#include "filesys/filesys.h" // include +
#include "threads/synch.h" // include +
#include "devices/input.h" // include +
#include "userprog/process.h" // include +
#include "threads/palloc.h" // include +

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

// To implement syscalls, virtual address space에서 data를 읽고 쓸 방법을 구현해야 함....
// System call의 인자로 들어온 pointer로부터 data를 읽어야 할 때 필요. (그래서 여기서 구현)

#ifndef VM
void check_address(void *addr){
	// if (addr == NULL || is_kernel_vaddr(addr) || pml4_get_page(thread_current() -> pml4, addr) == NULL)
	if (addr == NULL) exit(-1);
	if (is_kernel_vaddr(addr)) exit(-1);
}
#else
struct page *check_address(void *addr) {
	struct thread *cur_t = thread_current();
	if (addr == NULL || is_kernel_vaddr(addr) || (spt_find_page(&cur_t -> spt, addr) == NULL)){
		exit(-1);
	}
	return spt_find_page(&cur_t -> spt, addr);
}
#endif


void check_valid_buffer(void *buffer, size_t size, bool writable){
	if ((buffer >= (USER_STACK - (1<<20)) && buffer <= USER_STACK)) return;
	for (int i = 0; i < size; i++){
		struct page *page = check_address(buffer + i);
		if (page == NULL || (writable && !(page -> writable))) exit(-1);
	}
}

void check_invalid_write(void *addr){
	// struct page *p;
	// if ((addr < (USER_STACK - (1<<20)) && addr > USER_STACK) && (p = spt_find_page(&thread_current() -> spt, addr))
	// 		&& (p -> writable == false)){
	// 	exit(-1);
	// }
	if ((addr >= (USER_STACK - (1<<20)) && addr <= USER_STACK)) return;
	struct page *p = spt_find_page(&thread_current() -> spt, addr);
	if (p == NULL || (p -> writable == false)) exit(-1);
}

// ADD: To allocate fd(file descriptor) from the current thread's fd table
int allocate_fd(struct file *file){
	/* 현재 스레드에서 관리하는 fd table을 통해 fd를 배정해줘야 함
	   스레드의 fd_index 값부터 시작해서 가능한 fd를 탐색
	   array에서 NULL인 자리를 만날 때까지 fd++
	   만약 fd의 최대값을 넘어간다면 바로 -1 return
	   thread의 fd 관련 변수들을 최신화 해주고 fd return*/
	struct thread *cur_t = thread_current();
	int fd;

	// FD_LIMIT is define at threads/thread.h
	for(fd = (cur_t -> fd_index); (cur_t -> fd_array[fd] != NULL); fd++){
		if (fd >= FD_LIMIT){
			cur_t -> fd_index = FD_LIMIT;
			return -1;
		}
	}

	cur_t -> fd_index = fd;
	cur_t -> fd_array[fd] = file;
	return fd;
}

// To find the file having this specific fd(file descriptor) for the current thread.
struct file *find_file(int fd){
	if(fd < 2 || fd >= FD_LIMIT) return NULL; // 0 for STDIN, 1 for STDOUT, AND fd should be less than the LIMIT
	return (thread_current() -> fd_array[fd]);
}

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&syscall_lock); // We need a lock to read or write a file in mutual-exclusive manner
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	int syscall_num = (f->R.rax);

	#ifdef VM
	(thread_current() -> rsp) = (f -> rsp);
	#endif

	switch(syscall_num){
	 	case SYS_HALT:
	 		halt();
	 		break;
	 	case SYS_EXIT:
	 		exit(f->R.rdi);
	 		break;
	 	case SYS_FORK:
	 		(f->R.rax) = fork(f->R.rdi, f);
	 		break;
	 	case SYS_EXEC:
	 		(f->R.rax) = exec(f->R.rdi);
	 		break;
	 	case SYS_WAIT:
	 		(f->R.rax) = wait(f->R.rdi);
	 		break;
	 	case SYS_CREATE:
	 		(f->R.rax) = create(f->R.rdi, f->R.rsi);
	 		break;
	 	case SYS_REMOVE:
	 		(f->R.rax) = remove(f->R.rdi);
	 		break;
	 	case SYS_OPEN:
	 		(f->R.rax) = open(f->R.rdi);
	 		break;
	 	case SYS_FILESIZE:
	 		(f->R.rax) = filesize(f->R.rdi);
	 		break;
	 	case SYS_READ:
	 		(f->R.rax) = read(f->R.rdi, f->R.rsi, f->R.rdx);
	 		break;
	 	case SYS_WRITE:
	 		(f->R.rax) = write(f->R.rdi, f->R.rsi, f->R.rdx);
	 		break;
	 	case SYS_SEEK:
	 		seek(f->R.rdi, f->R.rsi);
	 		break;
	 	case SYS_TELL:
	 		(f->R.rax) = tell(f->R.rdi);
	 		break;
	 	case SYS_CLOSE:
	 		close(f->R.rdi);
			break;
		case SYS_MMAP:
			(f->R.rax) = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
			break;
		case SYS_MUNMAP:
			munmap(f->R.rdi);
	}
}

void halt (void){		/* DONE */
 	power_off();
}

void exit (int status){			/* DONE */
	/* Should implement code about returning state */
	printf ("%s: exit(%d)\n", thread_name(), status);

	thread_current() -> exit_code = status;
	thread_exit();
}

int fork (const char *thread_name, struct intr_frame *f){			/* DONE? */
	check_address(thread_name);

	/* current의 tf는 kernel stack에 대한 rsp를 가지고 있음... */
	// additional comments: so, we should use the interrupt frame from the system call
	return process_fork(thread_name, f);
}

int exec (const char *cmd_line){			/* DONE */
	check_address(cmd_line);
	//이따가 cmd_line을 parsing해야 하는데 argument로 들어온 cmd_line은 const이므로 복사해줌
	char *copy = palloc_get_page(PAL_ZERO);
	strlcpy(copy, cmd_line, PGSIZE);		//copy의 사이즈가 pgsize만큼일테니까

	if(process_exec(copy) == -1) exit(-1);
}

int wait (int pid){
	return process_wait(pid);
}

bool create (const char *file, unsigned initial_size){		/* DONE */
	check_address(file);
	return filesys_create(file, initial_size);
}
bool remove (const char *file){		/* DONE */
	check_address(file);
	return filesys_remove(file);
}

int open (const char *file){		/* DONE */
	/* filesys_open으로 파일을 우선 open
	   만약 열린 파일이 NULL이라면 제대로 열리지 않은 것이므로 fd -1 return
	   allocate_fd를 통해 fd를 배정해줌
	   만약 fd가 -1이 배정되었다면 뭔가 문제가 생긴 것이므로 파일을 닫고 -1 return
	   이제 배정받은 fd를 return 해주면 끝! */
	check_address(file);

	// Check whether open file IS NOT NULL
	struct file *open_file = filesys_open(file);
	if (open_file == NULL) return -1;

	// Check whether file descriptor IS NOT -1 (NO remaining space in fd_table)
	int fd = allocate_fd(open_file);
	if(fd == -1) file_close(open_file);

	return fd;
}

int filesize (int fd){		/* DONE */
	struct file *open_file = find_file(fd);
	if(open_file == NULL) return -1;

	return file_length(open_file);
}

int read (int fd, void *buffer, unsigned size){		/* DONE */
	/* fd = 0 -> stdin
	   fd = 1 -> stdout, not read! -> return -1
	   그 외 -> size만큼 읽어서 buffer에 넣어줌
	   
	   읽는 동안 다른 놈들이 건들면 안 됨
	   lock을 걸어줘야 한다*/

	// Check the validity for the beginning of the buffer and the end of the buffer
	// check_address(buffer);
	check_valid_buffer(buffer, size, true);
	// check_address(buffer + size - 1);
	// check_invalid_write(buffer);
	// check_invalid_write(buffer + size - 1);

	struct file *open_file = find_file(fd);
	int count;

	if (fd == 0) {		// In case of STDIN, use input_getc in devices/input.c
		for(count = 0; count < size; count++){
			*(char *)buffer = input_getc();
			buffer++;
			// if (input == '\n') break;		// I think this line is not needed......
		}
	}

	else if (open_file == NULL) return -1;		// In case of the fd is not valid

	else{
		lock_acquire(&syscall_lock);
		count = file_read(open_file, buffer, size);
		lock_release(&syscall_lock);
	}

	return count;
}
int write (int fd, const void *buffer, unsigned size){		/* DONE */
	/* stdout인 경우, 그냥 buffer 값을 출력하면 됨
	   stdin인 경우, write랑 상관 x, -1 return
	   그 외 -> size만큼 읽어주기
	   
	   이번에도 읽는 동안은 lock을 걸어서 읽는 내용에 변화가 없게 해줘야 함*/

	// Check the validity for the beginning of the buffer and the end of the buffer
	// check_address(buffer);
	check_valid_buffer(buffer, size, false);
	// check_address(buffer + size - 1);

	struct file *open_file = find_file(fd);
	int count;

	if (fd == 1) {
		putbuf(buffer, size);				// In case of STDOUT, use putbuf() in lib/kernel/console.c
		count = size;
	}
	
	else if (open_file == NULL) return -1;	// In case of the fd is not valid

	else {
		if (open_file != NULL && !is_file_writable(open_file)) exit(-1);
		lock_acquire(&syscall_lock);
		count = file_write(open_file, buffer, size);
		lock_release(&syscall_lock);
	}

	return count;
}

void seek (int fd, unsigned position){		/* DONE */
	struct file *open_file = find_file(fd);
	if (open_file == NULL) return;
	file_seek(open_file, position);
}

unsigned tell (int fd){			/* DONE */
	struct file *open_file = find_file(fd);
	if (open_file == NULL) return;
	return file_tell(open_file);
}

void close (int fd){		/* DONE */
	struct file *open_file = find_file(fd);
	struct thread *cur_t = thread_current();

	if (open_file == NULL) return;

	// Free file descriptor... and set fd_index to fd for optimization of searching
	file_close(open_file);
	cur_t -> fd_array[fd] = NULL;
	cur_t -> fd_index = fd;
}

void *mmap (void *addr, size_t length, int writable, int fd, off_t offset){
	struct file *open_file = find_file(fd);
	if(open_file == NULL) return NULL;

	if(file_length(open_file) == 0) return NULL;

	if(is_kernel_vaddr(addr)) return NULL;
	if(is_kernel_vaddr(addr + length)) return NULL;
	if(addr + length == 0) return NULL;

	if(!addr || addr != pg_round_down(addr)) return NULL;

	if(spt_find_page(&(thread_current() -> spt), addr)) return NULL;

	if(length == 0) return NULL;

	if((offset % PGSIZE) != 0) return NULL;

	return do_mmap(addr, length, writable, open_file, offset);
}

void munmap (void *addr){
	do_munmap(addr);
}