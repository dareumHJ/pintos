/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "userprog/process.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;

	struct lazy_load_args *args = (page -> uninit.aux);
	file_page -> file = args -> file;
	file_page -> ofs = args -> ofs;
	file_page -> read_bytes = args -> read_bytes;
	file_page -> zero_bytes = args -> zero_bytes;

	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;

	page -> frame -> kva = kva;

	file_seek(file_page -> file, file_page -> ofs);
	file_read(file_page -> file, kva, file_page -> read_bytes);
	memset(kva + (file_page -> read_bytes), 0, file_page -> zero_bytes);
	return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;

	if(pml4_is_dirty(thread_current() -> pml4, page -> va)){
		file_write_at(file_page -> file, page -> va, file_page -> read_bytes, file_page -> ofs);
		pml4_set_dirty(thread_current() -> pml4, page -> va, false);
	}

	pml4_clear_page(thread_current() -> pml4, page -> va);

	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	if (pml4_is_dirty(thread_current() -> pml4, page -> va)){
		file_write_at(file_page -> file, page -> va, file_page -> read_bytes, file_page -> ofs);
		pml4_set_dirty(thread_current() -> pml4, page -> va, false);
	}
	pml4_clear_page(thread_current() -> pml4, page -> va);
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	// load segment와는 다르게 read byte랑 zero byte를 직접 계산해야 함
	// 근데 오 ㅐload segemnt랑 비슷한거지
	// load segment는 테케 파일을 열어서 메모리에 매핑을 해주는 건데
	// 이것도 테케 파일은 아니지만 어찌됐든 간에 파일 내용을 읽어서 메모리에 매핑을 해주는 거니까?
	uint32_t read_bytes = length;
	struct file *f = file_reopen(file);
	if(file_length(f) < read_bytes) read_bytes = file_length(f);

	uint32_t zero_bytes = PGSIZE - (read_bytes % PGSIZE);
	void *initial_addr = addr;		//addr은 아래에서 계속 변해가지고 처음 값을 보존해둬야 함

	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (addr) == 0);
	ASSERT (offset % PGSIZE == 0);

	int count = 0;
	
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		struct lazy_load_args *args = malloc(sizeof(struct lazy_load_args));
		args -> file = f;
		args -> ofs = offset;
		args -> read_bytes = page_read_bytes;
		args -> zero_bytes = page_zero_bytes;
		if (!vm_alloc_page_with_initializer (VM_FILE, addr,
					writable, lazy_load_segment, args))
			return NULL;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
		offset += page_read_bytes;

		count++;
	}
	struct page *p = spt_find_page(&(thread_current() -> spt), initial_addr);
	p -> mmap_count = count;

	return initial_addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	// addr만 가지고는 얼마나 unmap 해야할 지 모름
	// 그 정보를 전달해줄 방법이 필요함...
	// 일단 나는 inital_addr에 해당하는 page에 저장하기로 했는데 더 좋은 방법 있으면 수정좀
	struct supplemental_page_table *spt = &(thread_current() -> spt);
	struct page *p = spt_find_page(spt, addr);
	int cnt = (p -> mmap_count);
	while (cnt > 0){
		if (p != NULL) destroy(p);
		addr += PGSIZE;
		p = spt_find_page(spt, addr);
		cnt--;
	}
}
