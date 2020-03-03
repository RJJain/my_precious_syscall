#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/mmu_notifier.h>

#include <asm/current.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>

long checkpoint(void);
long restore(void);

/*
  my_precious syscall, provides
  - checkpointing and restoring the anonymous memory regions of a process
*/
SYSCALL_DEFINE1(my_precious, bool, x ) {
  if( x==0 ) {
    return checkpoint();
  } else if( x==1 ) {
    return restore();
  } 
  return EINVAL;
}

//--------------------------------------------------------------
// Utility functions
//--------------------------------------------------------------
void obtain_pte(struct mm_struct *mm, unsigned long addr, pte_t **pte) {
  pgd_t *pgd;
  p4d_t *p4d;
  pud_t *pud;
  pmd_t *pmd;

  if (!down_read_trylock(&mm->mmap_sem))
    return;
  pgd = pgd_offset(mm, addr);
  if( !pgd_none(*pgd)) {
    p4d = p4d_offset(pgd,addr);
    if(!p4d_none(*p4d)) {
      pud = pud_offset(p4d, addr);
      if(!pud_none(*pud)) {
	pmd = pmd_offset(pud, addr);
	if(!pmd_none(*pmd)) {
	  *pte = pte_offset_map(pmd, addr);
	}
      }
    }
  }
  up_read(&mm->mmap_sem);
  return;
}

/*
pte_t* update_pte(struct mm_struct *mm, unsigned long addr, pte_t *newPte) {
  pgd_t *pgd;
  p4d_t *p4d;
  pud_t *pud;
  pmd_t *pmd;
  pte_t *src_pte = 0;

  if (!down_read_trylock(&mm->mmap_sem))
    return src_pte;

  pgd = pgd_offset(mm, addr);
  if( !pgd_none(*pgd)) {
    p4d = p4d_offset(pgd,addr);
    if(!p4d_none(*p4d)) {
      pud = pud_offset(p4d, addr);
      if(!pud_none(*pud)) {
	pmd = pmd_offset(pud, addr);
	if(!pmd_none(*pmd)) {
	  src_pte = pte_offset_map(pmd, addr);
	  // check for the src_pte
	  // if pte does not exists but we are passing a non-zero PTE
	  // then add this new PTE
	  if( !pte_none(*src_pte) ) {
	    if(pte_none(*newPte)) {
	      set_pte(src_pte, *newPte);
	    } else {
	      set_pte(src_pte, (pte_t){ .pte = 0 });
	    }
	  } else {
	    // xxx_rajat Need to trace this scenario
	    if(!(*newPte)) {
	      set_pte(src_pte, *newPte);
	    }
	  }
	}
      }
    }
  }
  up_read(&mm->mmap_sem);
  return src_pte;
}
*/

/*--------------------------------------------------------------
  - checkpoint function
        - saves the anonymous region of the process
--------------------------------------------------------------*/
long checkpoint(void) {
  struct task_struct *taskPtr = NULL;
  struct mm_struct *mmPtr = NULL;
  struct vm_area_struct *vmaPtr = NULL;
  struct page *page = NULL;
  pte_t *pte = NULL, *save_old_pte = NULL;

  unsigned int num_of_pages_per_vma, i;
  unsigned long vma_start, vma_end;
  unsigned long virtualAddr;

  // Initialization
  taskPtr = current;
  mmPtr = taskPtr->mm;
  vmaPtr = mmPtr->mmap;

  // Iterating through the VMAs
  while( vmaPtr ) {
    
    if( vmaPtr->old_ptes ) {
      // Already checkpointing for the process been done before, raise error
      return -EINVAL;
    }

    if( vma_is_anonymous( vmaPtr ) &&
	!vma_is_stack_for_current(vmaPtr) &&
	(vmaPtr->vm_flags & VM_MAYWRITE) ) {

      vma_start = vmaPtr->vm_start;
      vma_end = vmaPtr->vm_end;
      num_of_pages_per_vma = (vma_end - vma_start)/4096;
      
      save_old_pte = kmalloc_array(num_of_pages_per_vma, sizeof(pte_t), GFP_USER);
      // Free the memory at the exit for the process
      if (!save_old_pte)
	return -ENOMEM;
      // Pointing vma_area's old_ptes to the allocated memory to save the old PTEs
      // Old PTEs are gsave_old_pteoing to be used for restoration
      vmaPtr->old_ptes = save_old_pte;

      // Iterating over the vma_area to save the reference to the existing physical frames
      // marking the PTEs for the frames as write_protected and increasing the _mapcount
      // for the physical frame. When the process tries to write to the page, page fault handler
      // is going to get triggered which then will treat the fault as COW fault and allocate a
      // new frame for the process

      // Old physical frame references are saved in each vma_area old_ptes array for restoration later
      // on call to restore version of syscall
      for( i=0; i<num_of_pages_per_vma; i++ ) {

	pte = NULL;
	virtualAddr = vma_start + i * 4096;
	obtain_pte(vmaPtr->vm_mm, virtualAddr, &pte);

	if( pte == NULL || pte_none(*pte) ) {
	  // pte does not exist
	  vmaPtr->old_ptes[i] = (pte_t){ .pte = 0 };
	} else {
	  // pte exist
	  if( pte_present(*pte) ) {
	    // Page frame in memory

	    vmaPtr->old_ptes[i] = *pte;
	    page = pte_page(*pte);
	    
	    // Increment the page reference count
	    get_page(page);
	    atomic_inc(&page->_mapcount);

	    // xxx_rajat check the following
	    //mark_page_reserved(page);
	    //mlock_vma_page(page);
	    
	    // Write_protecting the PTE
	    if( pte_write(*pte) ) {
	      ptep_set_wrprotect(mmPtr, virtualAddr, pte);
	      *pte = pte_wrprotect(*pte);
	    }

	    // We need to invalidate the secondary MMU mappings as there is a
	    // permission downgrade on the ptes
	    // Done for an entire vma region

	    // xx_rajat check the following
	    //struct mmu_notifier_range range;
	    //mmu_notifier_range_init(&range, mmPtr, virtualAddr, virtualAddr+(2<<11));
	    //mmu_notifier_invalidate_range_start(&range);
	  
	    obtain_pte(vmaPtr->vm_mm, virtualAddr, &pte);

	    flush_cache_page(vmaPtr, virtualAddr, pte_pfn(*pte));
	    flush_tlb_page(vmaPtr, virtualAddr);
	  } else {
	    // Page frame in swap area
	    //swp_entry_t entry = pte_to_swp_entry(pte);

	  }
	}
      } // for loop ended
    } // processing for a vma area ended

    // Fetching next vma_area
    vmaPtr = vmaPtr->vm_next;
  }
  return 0;
}

/*--------------------------------------------------------------
  - restore function
        - restores the anonymous region of the process
--------------------------------------------------------------*/
long restore(void) {

  /*
  struct task_struct *taskPtr = NULL;
  struct mm_struct *mmPtr = NULL;
  struct vm_area_struct *vmaPtr = NULL;
  struct page *page = NULL, *old_page = NULL;

  unsigned long virtualAddr;
  pte_t *present_pte = NULL;
  unsigned int num_of_pages_per_vma, i;
  unsigned long vma_start, vma_end;
  bool isCheckpointed = false;
  
  // Initialization
  taskPtr = current;
  mmPtr = taskPtr->mm;
  vmaPtr = mmPtr->mmap;

  // Iterating through the VMAs and processing the anonymous region  
  while( vmaPtr ) {

    if( !vmaPtr->old_ptes ) {
      // No checkpointing done for this vma

      // Fetching next vma_area
      vmaPtr = vmaPtr->vm_next;
      continue;
    }

    isCheckpointed = true;
    
    if( vma_is_anonymous( vmaPtr ) &&
	!vma_is_stack_for_current(vmaPtr) &&
	(vmaPtr->vm_flags & VM_MAYWRITE) ) {

      vma_start = vmaPtr->vm_start;
      vma_end = vmaPtr->vm_end;

      num_of_pages_per_vma = (vma_end - vma_start)/4096;

      // Old physical frame references are saved in each vma_area old_ptes array for restoration
      for( i=0; i<num_of_pages_per_vma; i++ ) {

	virtualAddr = vma_start + i * 4096;
	obtain_pte(vmaPtr->vm_mm, virtualAddr, &present_pte);

	if( pte_none(vmaPtr->old_ptes[i]) ) {
	  // If earlier at time of checkpointing the Page frame was not allocated then release the new
	  // page frame and delete the PTE as well
	  // Remember to flush the TLB entry as well
	  if( present_pte != NULL && !pte_none(*present_pte) ) { // PTE exists for the address
	    if( pte_present(*present_pte) ) {
	      // Current page frame in memory
	      page = pte_page(*present_pte);

	      // release the page
	      page_mapcount_reset( page );
	      put_page( page );
	      
	      // delete the pte
	      update_pte(vmaPtr->vm_mm, virtualAddr, ); //xxx_rajat handle it
	    
	      flush_cache_page(vmaPtr, virtualAddr, pte_pfn(*present_pte));
	      flush_tlb_page(vmaPtr, virtualAddr);

	    } else {
	      // Current page frame on swap
	      // xxx_rajat : release the swap page

	    }
	  } else {
	    // PTE does not exist
	    // do nothing for this page
	    continue;
	  }
	} else {
	  // --- PTE existed at time of checkpointing --------------------
	  // release the new page frame if different from older page frame
	  if( pte_none(*present_pte) ) {
	    // restore the old page frame and old PTE
	    update_pte(vmaPtr->vm_mm, virtualAddr, &vmaPtr->old_ptes[i]);
	  } else {
	    // PTE for the new frame exists
	    page = pte_page(*present_pte);
	    old_page = pte_page(vmaPtr->old_ptes[i]);

	    unsigned long pfn = pte_pfn(*present_pte);
	    unsigned long old_pfn = pte_pfn( vmaPtr->old_ptes[i]);

	    if( pfn != old_pfn ) {
	      // release the new page frame
	      // release the page
	      page_mapcount_reset( page );
	      put_page( page );

	      // restore the old PTE
	      update_pte(vmaPtr->vm_mm, virtualAddr, &vmaPtr->old_ptes[i]);
	    
	      flush_cache_page(vmaPtr, virtualAddr, pfn );
	      flush_tlb_page(vmaPtr, virtualAddr);
	    }
	  }
	}
      } // for loop ended
    } // processing for a vma area ended
    
    // Fetching next vma_area
    vmaPtr = vmaPtr->vm_next;
  }

  if(!isCheckpointed) {
    return -EINVAL;
  }
  */
  // Restoration successful
  return 0;
}

