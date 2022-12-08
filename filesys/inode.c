#include <debug.h>
#include <round.h>
#include <string.h>
#include <list.h>
#include <stdio.h>

#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/*allocates a sector from free_map and returns true if 
success*/
static bool allocateSect(block_sector_t *sect){
    if(free_map_allocate(1, sect)){
        static char num[BLOCK_SECTOR_SIZE];
        block_write(fs_device, *sect, num);
        return true;

    }else{
        return false;
    }
}

/*allocate x amount of sectors of indirect block in sector*/
static bool allocateIndBlock(block_sector_t *sect, size_t size){
    ASSERT((size > 0));
    ASSERT((size <= 128));
    
    bool res = false;
    struct indirect_block *block = NULL;
    block = calloc(1, sizeof *block);

    if(block != NULL){
        if(free_map_allocate(1, sect)){
            for(size_t i=0; i<128; i++){
                block->sects[i] = *sect;
            }

            res = true;

            for(size_t i=0; i<size; i++){
                res = res && allocateSect(&block->sects[i]);

                if(!res){
                    break;
                }
            }

            block_write(fs_device, *sect, block);
        }
    }
    
    free(block);
    return res;
}

/* Returns the number of sectors to allocate for an inode SIZE
 * bytes long. */
static inline size_t
bytes_to_sectors(off_t size)
{
    return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE);
}

/* Returns the block device sector that contains byte offset POS
 * within INODE.
 * Returns -1 if INODE does not contain data for a byte at offset
 * POS. */
static block_sector_t
byte_to_sector(const struct inode *inode, off_t pos)
{
    ASSERT(inode != NULL);
    block_sector_t b_sec;
    off_t num;

    num = pos/BLOCK_SECTOR_SIZE;
    
    if (num < DIRECT) {
        return inode->data.sects[num];

    } else if(num < INDIRECT_MAX){
        struct indirect_block *ind_block;
        off_t ind_bnum = (num - DIRECT) / 128;
        off_t ind_num = (num - DIRECT) % 128;
        block_sector_t ind_bsec = inode->data.sects[ind_bnum+DIRECT];
        ind_block = calloc(1, sizeof *ind_block);
        block_read(fs_device, ind_bsec, ind_block);
        b_sec = ind_block->sects[ind_num];

        free(ind_block);
        return b_sec;
        
    } 
    return -1;
}

/*file growth in case of unallocated sector */
static block_sector_t altbytetoSect(struct inode *inode, off_t pos){
  ASSERT (inode != NULL);
  block_sector_t result;
  off_t num = pos / BLOCK_SECTOR_SIZE;
  
  if (num < DIRECT) {
    if (inode->data.sects[num] == inode->sector) {
      allocateSect(&inode->data.sects[num]);
    }
    return inode->data.sects[num];

  } else if (num < INDIRECT_MAX) {
    off_t ind_bnum = (num - DIRECT) / 128;
    off_t ind_snum = (num - DIRECT) % 128;
    struct indirect_block *block;

    if (inode->data.sects[ind_bnum+DIRECT] == inode->sector) {
      allocateIndBlock(&inode->data.sects[ind_bnum+DIRECT], 1);
    }

    block_sector_t ind_sect = inode->data.sects[ind_bnum+DIRECT];
    block = calloc (1, sizeof *block);
    block_read (fs_device, ind_sect, block);

    if (block->sects[ind_snum] == ind_sect) {
      allocateSect(&block->sects[ind_snum]);
      block_write (fs_device, ind_sect, block);
    }
    
    result = block->sects[ind_snum];
    free (block);
    return result;
  } 
  return -1;
}

/* List of open inodes, so that opening a single inode twice
 * returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init(void)
{
    list_init(&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
 * writes the new inode to sector SECTOR on the file system
 * device.
 * Returns true if successful.
 * Returns false if memory or disk allocation fails. */
bool
inode_create(block_sector_t sector, off_t length, bool directory)
{
    struct inode_disk *disk_inode = NULL;
    bool success = false;

    ASSERT(length >= 0);

    /* If this assertion fails, the inode structure is not exactly
     * one sector in size, and you should fix that. */
    ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);
    ASSERT(sizeof (struct indirect_block) == BLOCK_SECTOR_SIZE);
    ASSERT(sizeof (struct indirect_block_array) == BLOCK_SECTOR_SIZE);
    
    disk_inode = calloc(1, sizeof *disk_inode);
    if (disk_inode != NULL) {
        size_t sectors = bytes_to_sectors(length);
        disk_inode->length = length;
        disk_inode->magic = INODE_MAGIC;
        disk_inode->directory = directory;

        for(size_t i=0; i<125; i++){
            disk_inode->sects[i] = sector;
        }
        if (sectors > 0) {
            size_t s;

            if(sectors > DIRECT){
                s = DIRECT;

            }else{
                s = sectors;
            }

            for(size_t i=0; i<s; i++){
                allocateSect(&disk_inode->sects[i]);
            }
            
            sectors = sectors - s;
            size_t ind_b;
            size_t ind_s = (sectors > INDIRECT*128) ? INDIRECT*128 : sectors;

            if(ind_s%128 == 0){
                ind_b = ind_s / 128;

            }else{
                ind_b = (ind_s / 128) + 1;
            }

            for(size_t i=0; i<ind_b; i++){
                if(ind_s >= 128){
                    allocateIndBlock(&disk_inode->sects[i+DIRECT], 128);
                    ind_s = ind_s - 128;

                }else{
                    allocateIndBlock(&disk_inode->sects[i+DIRECT], ind_s);
                }
            }
            sectors = sectors - ind_s;
        }

        block_write(fs_device, sector, disk_inode);
        success = (sectors == 0);
        free(disk_inode);
    }
    return success;
}

/* Reads an inode from SECTOR
 * and returns a `struct inode' that contains it.
 * Returns a null pointer if memory allocation fails. */
struct inode *
inode_open(block_sector_t sector)
{
    struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&inode->lock);
  block_read (fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen(struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Closes INODE and writes it to disk.
 * If this was the last reference to INODE, frees its memory.
 * If INODE was also a removed inode, frees its blocks. */
void
inode_close(struct inode *inode)
{
   /* Ignore null pointer. */
  if (inode == NULL){
    return;
  }

  lock_acquire(&inode->lock);
  block_write (fs_device, inode->sector, &inode->data);

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Change this to free sectors one at a time based on
        the on the disk_inode's allocated blocks */
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
          off_t i, j;

          for (i = 0; i < DIRECT; i++) {
            if (inode->data.sects[i] == inode->sector){
              break;
            }
            free_map_release (inode->data.sects[i], 1);
          }

          for (i = 0; i < INDIRECT; i++) {
            if (inode->data.sects[i+DIRECT] == inode->sector){
              break;
            }

            block_sector_t ind_sect = inode->data.sects[i+DIRECT];
            struct indirect_block *block;
            block = calloc (1, sizeof *block);
            block_read (fs_device, ind_sect, block);

            for (j = 0; j < 128; j++) {
              if (block->sects[j] == ind_sect){
                break;
              }
              
              free_map_release (block->sects[j], 1);
            }
            free (block);
            free_map_release (inode->data.sects[i+DIRECT], 1);
          }
        }
      lock_release(&inode->lock);
      free (inode); 
    } else {
      lock_release(&inode->lock);
    }

}

/* Marks INODE to be deleted when it is closed by the last caller who
 * has it open. */
void
inode_remove(struct inode *inode)
{
    ASSERT(inode != NULL);
    inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
 * Returns the number of bytes actually read, which may be less
 * than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at(struct inode *inode, void *buffer_, off_t size, off_t offset)
{
  ASSERT(inode != NULL);
  lock_acquire(&inode->lock);
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          block_read (fs_device, sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  lock_release(&inode->lock);
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
 * Returns the number of bytes actually written, which may be
 * less than SIZE if end of file is reached or an error occurs.
 * (Normally a write at end of file would extend the inode, but
 * growth is not yet implemented.) */
off_t
inode_write_at(struct inode *inode, const void *buffer_, off_t size,
               off_t offset)
{
   
  ASSERT(inode != NULL);
  lock_acquire(&inode->lock);
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt) {
    lock_release(&inode->lock);
    return 0;
  }

  /* Fill space between EOF and start of this write
     with zeros */
  if (offset >= inode_length (inode)) {
    off_t i;
    for (i = inode_length(inode); i < offset; i+=BLOCK_SECTOR_SIZE) {
      altbytetoSect(inode, i);
    }
  }

  /* Update the inode's length if necessary */
  if (inode->data.length < (offset + size)) {
    inode->data.length = offset + size;
  }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = altbytetoSect (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          block_write (fs_device, sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  lock_release(&inode->lock);
  return bytes_written;
}

/* Disables writes to INODE.
 * May be called at most once per inode opener. */
void
inode_deny_write(struct inode *inode)
{
    inode->deny_write_cnt++;
    ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

int
inode_open_cnt (const struct inode *inode)
{
  return (int) inode->open_cnt;
}

/* Re-enables writes to INODE.
 * Must be called once by each inode opener who has called
 * inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write(struct inode *inode)
{
    ASSERT(inode->deny_write_cnt > 0);
    ASSERT(inode->deny_write_cnt <= inode->open_cnt);
    inode->deny_write_cnt--;
}


/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length(const struct inode *inode)
{
    return inode->data.length;
}