#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <list.h>
#include <stdbool.h>

#include "devices/block.h"
#include "filesys/off_t.h"
#include "threads/synch.h"

#define DIRECT 98
#define INDIRECT 26
#define INDIRECT_MAX (INDIRECT*128 + DIRECT)

struct bitmap;

/* On-disk inode.
 * Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
    block_sector_t sects[125];  /* Sectors */
    off_t          length;      /* File size in bytes. */
    unsigned       magic;       /* Magic number. */
    bool           directory;       /* Differentiates files and directories*/
};

/* In-memory inode. */
struct inode {
    struct list_elem  elem;           /* Element in inode list. */
    block_sector_t    sector;         /* Sector number of disk location. */
    int               open_cnt;       /* Number of openers. */
    bool              removed;        /* True if deleted, false otherwise. */
    int               deny_write_cnt; /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;           /* Inode content. */
    struct lock       lock;           /* Lock for synchronization */
};

struct indirect_block {
    block_sector_t sects[128];       /* Array of Sectors */
};

struct indirect_block_array {
    block_sector_t sects[128];       /* Array of indirect blocks */
};
int inode_open_cnt (const struct inode *inode);
void inode_init(void);
bool inode_create(block_sector_t, off_t, bool);
struct inode *inode_open(block_sector_t);
struct inode *inode_reopen(struct inode *);
block_sector_t inode_get_inumber(const struct inode *);
void inode_close(struct inode *);
void inode_remove(struct inode *);
off_t inode_read_at(struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at(struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write(struct inode *);
void inode_allow_write(struct inode *);
bool inode_isdir(const struct inode *);
int inode_getNum(const struct inode *);
off_t inode_length(const struct inode *);

#endif /* filesys/inode.h */