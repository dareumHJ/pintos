/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include <bitmap.h>
#include "threads/vaddr.h"
#include "threads/mmu.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
struct bitmap *swap_table;			//added for swap in/out

static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

#define SECTORS_PER_PAGE PGSIZE / DISK_SECTOR_SIZE		// 자주 쓰는 값이라 define 했음

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	// swap_disk = NULL;
	swap_disk = disk_get(1, 1);			// in device/disk.c, swap이면 1,1이 인풋이어야 한다네요
	// bitmap을 만들어야 하는데, 그 사이즈는 스왑 슬롯의 개수임
	// 디스크의 사이즈가 a라고 한다면 필요한 스왑 슬롯의 개수는
	// 디스크의 크기를 디스크 한 페이지의 크기로 나눠주면 된다
	// 디스크의 크기를 알려주는 함수인 disk_size이 바이트 단위가 아닌 섹터 단위로 반환을 해주기 때문에 그것만 신경쓰면 된다
	int d_size = disk_size(swap_disk);
	int denominator = SECTORS_PER_PAGE;
	swap_table = bitmap_create( d_size / denominator );
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	anon_page -> slot_no = -1;
	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	// page에서 disk slot에 대한 정보를 가져와야 함
	// anon_page 구조체 안에 그 정보를 기록하는 게 좋겠다
	int slot_no = anon_page -> slot_no;

	if (slot_no < 0) return false;

	if (!bitmap_test(swap_table, slot_no)) return false;

	page -> frame -> kva = kva;

	bitmap_set(swap_table, slot_no, false);

	for (int i = 0; i < SECTORS_PER_PAGE; i++){
		disk_read(swap_disk, slot_no * SECTORS_PER_PAGE + i, kva + DISK_SECTOR_SIZE * i);
	}

	pml4_set_page(thread_current() -> pml4, page -> va, kva, page -> writable);

	anon_page -> slot_no = -1;

	return true;

}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	int slot_no = bitmap_scan_and_flip(swap_table, 0, 1, false);	//비트맵에서 false 상태의 슬롯 하나 찾기
	if(slot_no == BITMAP_ERROR)
		PANIC("No more free slot in swap disk\n");
	// 하나의 스왑 슬롯은 하나의 페이지 크기만큼에 대응하므로 disk에 SECTORS_PER_PAGE 만큼 써줘야함
	for (int i = 0; i < SECTORS_PER_PAGE; i++){
		disk_write(swap_disk, slot_no * SECTORS_PER_PAGE + i, (page -> frame -> kva) + DISK_SECTOR_SIZE * i);
	}

	pml4_clear_page(thread_current() -> pml4, page -> va);

	anon_page -> slot_no = slot_no;
	return true;

}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}
