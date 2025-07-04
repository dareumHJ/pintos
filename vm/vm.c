/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "threads/palloc.h"
#include <hash.h>
#include "threads/vaddr.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "userprog/process.h"

// frame table with list
struct list frame_table;
/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&frame_table);

}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);
hash_action_func *page_destructor(struct hash_elem *e, void *aux);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		struct page *page = NULL;
		page = malloc(sizeof(struct page));

		bool (*initializer)(struct page *, enum vm_type, void *);	
		switch (VM_TYPE(type)) {
			case VM_ANON:
				initializer = anon_initializer;
				break;
			case VM_FILE:
				initializer = file_backed_initializer;
				break;
		}

		uninit_new (page, upage, init, type, aux, initializer);
		page -> writable = writable;

		/* TODO: Insert the page into the spt. */
		return spt_insert_page(spt, page);

	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	page = malloc(sizeof(struct page));
	(page -> va) = pg_round_down(va);

	struct hash_elem *target_elem = hash_find(&(spt -> hash_spt), &(page -> page_elem));
	free(page);

	if (target_elem != NULL) return hash_entry(target_elem, struct page, page_elem);
	return NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	if (hash_insert(&(spt -> hash_spt), &(page -> page_elem)) == NULL) succ = true;
	
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	hash_delete(&(spt -> hash_spt), &(page -> page_elem));
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	for(struct list_elem *e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e)){
		victim = list_entry(e, struct frame, frame_elem);
		if(pml4_is_accessed(thread_current() -> pml4, victim -> page -> va))
			pml4_set_accessed(thread_current() -> pml4, victim -> page -> va, 0);
		else
			return victim;

	} 


	// victim = list_entry(list_pop_front(&frame_table), struct frame, frame_elem);

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	swap_out(victim -> page);

	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	void *kva = palloc_get_page(PAL_USER);
	if (kva == NULL){
		frame = vm_evict_frame();
		frame -> page = NULL;
		return frame;
	}

	frame = malloc(sizeof(struct frame));
	frame -> page = NULL;
	frame -> kva = kva;

	list_push_back (&frame_table, &(frame -> frame_elem));

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	vm_alloc_page(VM_ANON | VM_MARKER_0, addr, true);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	/* lazy load가 아닌 상황을 생각해보면
	1. not present가 false인 경우 (= memory의 physical page가 존재하는 경우)
	2. write는 1인데 실제 페이지의 writable은 0인 경우
	3. addr이 커널 주소를 가리킬 때?*/
	if (addr == NULL) return false;
	if (is_kernel_vaddr(addr)) return false;
	if (!not_present) return false;
	
	void *rsp = f -> rsp;
	if (!user) rsp = thread_current() -> rsp;
	if((addr >= (USER_STACK - (1<<20)) && addr <= USER_STACK) && (addr >= rsp || addr == (rsp - 8))){
		vm_stack_growth(pg_round_down(addr));
	}



	page = spt_find_page(spt, addr);
	if ((page == NULL) || (write && !(page -> writable))) return false;
	return vm_do_claim_page (page);

}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = spt_find_page(&(thread_current() -> spt), va);
	if (page) return vm_do_claim_page(page);

	return false;
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	pml4_set_page (thread_current() -> pml4, page -> va, frame -> kva, page -> writable);
	
	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */

uint64_t hash_func (const struct hash_elem *e, void *aux UNUSED){
	struct page *page = hash_entry(e, struct page, page_elem);
	//hash_bytes in hash.h
	return hash_bytes(&(page -> va), sizeof(page -> va));
}

bool less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED){
	struct page *page_a = hash_entry(a, struct page, page_elem);
	struct page *page_b = hash_entry(b, struct page, page_elem);
	return (page_a -> va) < (page_b -> va);
}

void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&(spt -> hash_spt), hash_func, less_func, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	struct hash_iterator i;
	hash_first(&i, &(src -> hash_spt));
	while (hash_next(&i)){
		struct page *sp = hash_entry(hash_cur(&i), struct page, page_elem);
		enum vm_type type = (sp -> operations -> type);
		void *upage = (sp -> va);
		bool writable = (sp -> writable);

		if(type == VM_UNINIT){	// No need to memcpy
			vm_initializer *init = (sp -> uninit.init);
			void *aux = (sp -> uninit.aux);
			vm_alloc_page_with_initializer(VM_ANON, upage, writable, init, aux);
		}

		else if(type == VM_ANON){
			if (!vm_alloc_page(type, upage, writable)) return false;
			if (!vm_claim_page(upage)) return false;
			struct page *dp = spt_find_page (dst, upage);
			memcpy((dp -> frame -> kva), (sp -> frame -> kva), PGSIZE);
		}

		else if(type == VM_FILE){
			struct lazy_load_args *aux = malloc(sizeof(struct lazy_load_args));
			aux -> file = sp -> file.file;
			aux -> ofs = sp -> file.ofs;
			aux -> read_bytes = sp -> file.read_bytes;
			aux -> zero_bytes = sp -> file.zero_bytes;
			if (!vm_alloc_page_with_initializer(type, upage, writable, NULL, aux)) return false;
			struct page *file_page = spt_find_page(dst, upage);
			file_backed_initializer(file_page, type, NULL);	// page -> file_page
			file_page -> frame = sp -> frame;
			pml4_set_page(thread_current() -> pml4, file_page -> va, sp -> frame -> kva, sp -> writable);
		}
	}

	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&(spt -> hash_spt), page_destructor);
}

/* destructor function for hash_clear */
hash_action_func *page_destructor(struct hash_elem *e, void *aux) {
	struct page *p = hash_entry(e, struct page, page_elem);
	vm_dealloc_page(p);
}
