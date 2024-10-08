#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/file.h"
#include "threads/synch.h"

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
void check_address(void *addr){
	if(addr == NULL || is_kernel_vaddr(addr) || pml4_get_page(thread_current()->pml4, addr) == NULL)
		exit(-1);
}

int allocate_fd(struct file *file){
	/* 현재 스레드에서 관리하는 fd table을 통해 fd를 배정해줘야 함
	   스레드의 fd_index 값부터 시작해서 가능한 fd를 탐색
	   array에서 NULL인 자리를 만날 때까지 fd++
	   만약 fd의 최대값을 넘어간다면 바로 -1 return
	   thread의 fd 관련 변수들을 최신화 해주고 fd return*/
	struct thread *cur = thread_current();
	int fd = cur -> fd_index;

	while(cur -> fd_array[fd] != NULL){
		if (fd >= FD_LIMIT)
			return -1;
		fd++;
	}

	cur -> fd_index = fd;
	cur -> fd_array[fd] = file;
	return fd;
}

struct file *find_file(int fd){
	if(fd<2){
		return NULL;
	}
	if (fd>=FD_LIMIT){
		return NULL;
	}

	struct thread *cur = thread_current();
	struct file *cur_file = cur -> fd_array[fd];
	return cur_file;
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

	lock_init(&syscall_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	int syscall_num = (f->R.rax);
	switch(syscall_num){
	 	case SYS_HALT:
	 		halt();
	 		break;
	 	case SYS_EXIT:
	 		exit(f->R.rdi);
	 		break;
	// 	case SYS_FORK:
	// 		(f->R.rax) = fork(f->R.rdi);
	// 		break;
	// 	case SYS_EXEC:
	// 		(f->R.rax) = exec(f->R.rdi);
	// 		break;
	// 	case SYS_WAIT:
	// 		(f->R.rax) = wait(f->R.rdi);
	// 		break;
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
	}
}

void halt (void){
 	power_off();
}

void exit (int status){
	/* Should implement code about returning state */
	printf ("%s: exit(%d)\n", thread_name(), status);

	thread_current() -> exit_code = status;
	thread_exit();
}

// pid_t fork (const char *thread_name){
	
// }

// int exec (const char *cmd_line){
// }

// int wait (pid_t pid){
// }

bool create (const char *file, unsigned initial_size){
	check_address(file);							//check validity of pointer
	return filesys_create(file, initial_size);
}
bool remove (const char *file){
	check_address(file);							//check validity of pointer
	return filesys_remove(file);
}

int open (const char *file){
	/* filesys_open으로 파일을 우선 open
	   만약 열린 파일이 NULL이라면 제대로 열리지 않은 것이므로 fd -1 return
	   allocate_fd를 통해 fd를 배정해줌
	   만약 fd가 -1이 배정되었다면 뭔가 문제가 생긴 것이므로 파일을 닫고 -1 return
	   이제 배정받은 fd를 return 해주면 끝! */
	check_address(file);
	struct file *open_file = filesys_open(file);

	if (open_file == NULL){
		return -1;
	}

	int fd = allocate_fd(open_file);

	if(fd == -1){
		file_close(open_file);
	}

	return fd;
}

int filesize (int fd){
	struct file *open_file = find_file(fd);			//fd값에 해당하는 file을 찾음
	if(open_file == NULL){							//찾은 게 만약 NULL이라면 뭔가 문제가 있으므로 -1 return
		return -1;
	}

	return file_length(open_file);					//file_length를 이용해 길이를 return
}

int read (int fd, void *buffer, unsigned size){
	/* fd = 0 -> stdin
	   fd = 1 -> stdout, not read! -> return -1
	   그 외 -> size만큼 읽어서 buffer에 넣어줌
	   
	   읽는 동안 다른 놈들이 건들면 안 됨
	   lock을 걸어줘야 한다*/

	check_address(buffer);
	check_address(buffer + size - 1);				//buffer 및 buffer 끝 address 확인

	char *buf = (char *)buffer;
	int count;
	struct file *open_file = find_file(fd);

	if(fd == 0){									//stdin, use input_getc in devices/input.c
		char input;
		for(int count = 0; count < size; count++){
			input = input_getc();					//input에 
			*buf = input;
			buf++;
			if (input == '\n'){
				break;
			}
		}
	}

	else if (open_file == NULL){					//fd가 1인 경우는 open_file이 널인 경우를 포함
		return -1;
	}

	else{
		lock_acquire(&syscall_lock);
		count = file_read(open_file, buffer, size);
		lock_release(&syscall_lock);
	}

	return count;
}
int write (int fd, const void *buffer, unsigned size){
	/* stdout인 경우, 그냥 buffer 값을 출력하면 됨
	   stdin인 경우, write랑 상관 x, -1 return
	   그 외 -> size만큼 읽어주기
	   
	   이번에도 읽는 동안은 lock을 걸어서 읽는 내용에 변화가 없게 해줘야 함*/

	check_address(buffer);
	check_address(buffer + size - 1);

	int count;
	struct file *open_file = find_file(fd);

	if (fd == 1){
		putbuf(buffer, size);				//use putbuf() in lib/kernel/console.c
		count = size;
	}
	
	else if (open_file == NULL){			//fd가 0인 경우는 open_file이 널인 경우를 포함
		return -1;
	}

	else{
		lock_acquire(&syscall_lock);
		count = file_write(open_file, buffer, size);
		lock_release(&syscall_lock);
	}

	return count;
}

void seek (int fd, unsigned position){
	struct file *open_file = find_file(fd);
	if(open_file == NULL){
		return;
	}
	file_seek(open_file, position);
}

unsigned tell (int fd){
	struct file *open_file = find_file(fd);
	if(open_file == NULL){
		return;
	}
	return file_tell(fd);
}

void close (int fd){
	struct thread *cur = thread_current();

	struct file *open_file = find_file(fd);
	if (open_file == NULL)
		return;

	cur -> fd_array[fd] = NULL;
	cur -> fd_index = fd;
}