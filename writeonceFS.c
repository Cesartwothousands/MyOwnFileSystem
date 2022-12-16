// File:	writeonceFS.c
// List all group members' names: Zihan Chen(zc366), Jiayi Zhang(jz998)
// iLab machine tested on:  ilab1

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <stdarg.h>

/*
 * errno value       Error
 * 1             Directory not exists
 * 2             Create error, no such file or directory
 * 3             Out of memory
 * 4             Illegal name
 * 5             Operation not permitted
 * 6             Disk broken
 */

#define WOF_DIRECTORY (0)
#define WOF_FILE (1)
#define WOF_BLOCK_SIZE (1024)
#define WOF_BLOCK_DATA_SIZE (30)

#define WO_RDONLY 0x01
#define WO_WRONLY 0x02
#define WO_RDWR 0x04
#define WO_CREAT 0x08
int Errno = 0;

// 128 bytes
typedef struct
{
    short type;
    short size;
    int flags;
    unsigned int blocks[WOF_BLOCK_DATA_SIZE];
} wof_inode_t;

// 32 bytes
#define WOF_NAME_MAX 27
typedef struct
{
    char name[WOF_NAME_MAX + 1];
    int inode;
} wof_dir_t;

// fs block unit
// 4M -- 4096 blocks(1block 1K/1024)
// super block + inode bitmap + data bitmap + inode table + data block
// 1           + 1            + 1           + 128         + 3965
typedef struct
{
    int inode_bitmap_addr; // 1
    int data_bitmap_addr;  // 2

    int inode_region_addr; // 3
    int inode_region_len;  // 128  (inode all: 128 * 8 = 1024 inodes)

    int data_region_addr; // 131
    int data_region_len;  // 3965
} wof_super_t;

typedef struct
{
    char filename[WOF_NAME_MAX + 1];
    int fd;
    int mode;
    int inode;
    int offset;
} wof_file_t;

#define WOF_BITMAP_LEN (WOF_BLOCK_SIZE / sizeof(unsigned int))
typedef struct
{
    unsigned int bits[WOF_BITMAP_LEN];
} bitmap_t;

#define WOF_BLOCK_DIRS 32 // 1024/32
typedef struct
{
    wof_dir_t entries[WOF_BLOCK_DIRS];
} dir_block_t;

#define WOF_INODES_LEN (WOF_BLOCK_SIZE / sizeof(wof_inode_t))
typedef struct
{
    wof_inode_t inodes[WOF_INODES_LEN];
} inode_block;

#define WOF_SUPPORT_FILE_MAX (WOF_BLOCK_SIZE * 60)
int file_fd;
wof_super_t g_wof_super;
wof_file_t g_wof_file_table[WOF_SUPPORT_FILE_MAX];
int g_image_size;
char g_image_filename[128];

#define IMAGE_USE_ADDR 1
char *g_image_addr;
bitmap_t g_file_bitmap;
int g_root_dir_inode = 0;

static inline void __wof_read(int fd, int offset, void *buf, int size)
{
#ifndef IMAGE_USE_ADDR
    lseek(fd, offset, SEEK_SET);
    read(fd, buf, size);
#else
    if (buf && g_image_addr)
    {
        memcpy(buf, g_image_addr + offset, size);
    }
#endif
}

static inline void __wof_write(int fd, int offset, void *buf, int size)
{
#ifndef IMAGE_USE_ADDR
    lseek(fd, offset, SEEK_SET);
    write(fd, buf, size);
#else
    if (buf && g_image_addr)
    {
        memcpy(g_image_addr + offset, buf, size);
    }
#endif
}

static inline void wof_get_super_data(int fd, wof_super_t *s)
{
    __wof_read(fd, 0, s, sizeof(wof_super_t));
}

int bitmap_is_set(bitmap_t *bitmap, int bit)
{
    int index = bit / 32;
    int offset = bit % 32;

    if (bitmap->bits[index] & (1 << offset))
    {
        return 1;
    }

    return 0;
}

void bitmap_set(bitmap_t *bitmap, int bit)
{
    int index = bit / 32;
    int offset = bit % 32;

    bitmap->bits[index] |= (1 << offset);
    return;
}

void bitmap_clear(bitmap_t *bitmap, int bit)
{
    int index = bit / 32;
    int offset = bit % 32;

    bitmap->bits[index] &= ~(1 << offset);
    return;
}

int wof_get_file_fd(void)
{
    int j, k, bit;
    {
        for (j = 0; j < WOF_BITMAP_LEN; j++)
        {
            if (g_file_bitmap.bits[j] == 0xFFFFFFFF)
            {
                continue;
            }

            for (k = 0; k < 32; k++)
            {
                if (g_file_bitmap.bits[j] & (1 << k))
                {
                    continue;
                }

                g_file_bitmap.bits[j] |= (1 << k);
                bit = j * 32 + k;
                return bit;
            }
        }
    }

    return -1;
}

void wof_put_file_fd(int fd)
{
    wof_file_t *file = &g_wof_file_table[fd];
    memset(file, 0x00, sizeof(wof_file_t));
    file->fd = 0;
    file->inode = 0;
    bitmap_clear(&g_file_bitmap, fd);
}

void get_block_data(int bid, void *block)
{
    memset(block, 0x00, WOF_BLOCK_SIZE);
    __wof_read(file_fd, WOF_BLOCK_SIZE * bid, block, WOF_BLOCK_SIZE);
}

void set_block_data(int bid, void *block)
{
    __wof_write(file_fd, WOF_BLOCK_SIZE * bid, block, WOF_BLOCK_SIZE);
}

void get_inode(int inode_id, wof_inode_t *inode)
{
    int i = inode_id / WOF_INODES_LEN;
    int j = inode_id % WOF_INODES_LEN;

    int offset = WOF_BLOCK_SIZE * (g_wof_super.inode_region_addr + i);
    offset += j * sizeof(wof_inode_t);

    memset(inode, 0x00, sizeof(wof_inode_t));
    __wof_read(file_fd, offset, inode, sizeof(wof_inode_t));

    return;
}

void set_inode(int inode_id, wof_inode_t *inode)
{
    int i = inode_id / WOF_INODES_LEN;
    int j = inode_id % WOF_INODES_LEN;

    int offset = WOF_BLOCK_SIZE * (g_wof_super.inode_region_addr + i);
    offset += j * sizeof(wof_inode_t);

    __wof_write(file_fd, offset, inode, sizeof(wof_inode_t));

    return;
}

static wof_dir_t *wof_find_dir_sub_file_by_name(wof_inode_t *dir_inode, char *name, int *bid)
{
    int i, j;
    dir_block_t dir_block;
    wof_dir_t *dir, *find_dir;
    int find_name = 0;

    find_dir = NULL;
    for (i = 0; i < WOF_BLOCK_DATA_SIZE; i++)
    {
        if (dir_inode->blocks[i] == -1)
        {
            continue;
        }
        get_block_data(dir_inode->blocks[i], &dir_block);
        for (j = 0; j < WOF_BLOCK_DIRS; j++)
        {
            dir = &dir_block.entries[j];
            if (dir->inode == -1)
            {
                continue;
            }
            if (strcmp(dir->name, name) == 0)
            {
                find_dir = dir;
                find_name = 1;
                break;
            }
        }
        if (find_name == 1)
        {
            if (bid)
                *bid = dir_inode->blocks[i];
            return find_dir;
        }
    }

    return NULL;
}

int wof_find_free_bit(int addr)
{
    int j, k, offset;
    bitmap_t bit_map;
    int bit;

    offset = WOF_BLOCK_SIZE * addr;
    __wof_read(file_fd, offset, &bit_map, WOF_BLOCK_SIZE);

    for (j = 0; j < WOF_BITMAP_LEN; j++)
    {
        if (bit_map.bits[j] == 0xFFFFFFFF)
        {
            continue;
        }

        for (k = 0; k < 32; k++)
        {
            if (bit_map.bits[j] & (1 << k))
            {
                continue;
            }

            bit_map.bits[j] |= (1 << k);
            __wof_write(file_fd, offset, &bit_map, WOF_BLOCK_SIZE);
            bit = j * 32 + k;
            return bit;
        }
    }

    return -1;
}

int fdepth = 0;
struct file_dep
{
    char name[WOF_NAME_MAX + 1];
};

struct file_dep *g_file_dep;

void file_add_recu(char *name)
{
    struct file_dep *dep;

    if (fdepth == 0)
    {
        g_file_dep = malloc(sizeof(struct file_dep));
        dep = g_file_dep;
    }
    else
    {
        g_file_dep = realloc(g_file_dep, sizeof(struct file_dep) * (fdepth + 1));
        dep = g_file_dep + fdepth;
    }

    memset(dep, 0x00, sizeof(struct file_dep));
    strncpy(dep->name, name, WOF_NAME_MAX);

    fdepth++;
}

void file_free_recu(void)
{
    if (g_file_dep)
    {
        free(g_file_dep);
    }
    fdepth = 0;
}

static int wof_lookup_dir_sub_name(int inode_id, char *name)
{
    wof_inode_t inode;

    if (inode_id < 0)
    {
        return -1;
    }

    get_inode(inode_id, &inode);
    if (inode.type != WOF_DIRECTORY)
    {
        printf("inode %d not directory\n", inode_id);
        return -1;
    }

    wof_dir_t *find_ent = wof_find_dir_sub_file_by_name(&inode, name, NULL);
    if (find_ent == NULL)
    {
        printf("inode %d not find name %s\n", inode_id, name);
        return -1;
    }

    return find_ent->inode;
}

static int wo_creat_dir(int pinode)
{
    int bid, i;
    wof_inode_t inode;
    dir_block_t dir_block;
    int new_inode;

    new_inode = wof_find_free_bit(g_wof_super.inode_bitmap_addr);
    if (new_inode == -1)
    {
        return -1;
    }
    get_inode(new_inode, &inode);

    bid = wof_find_free_bit(g_wof_super.data_bitmap_addr);
    if (bid == -1)
    {
        return -1;
    }
    bid += g_wof_super.data_region_addr;
    inode.type = WOF_DIRECTORY;
    inode.size = 2 * sizeof(wof_dir_t);
    inode.blocks[0] = bid;
    for (i = 1; i < WOF_BLOCK_DATA_SIZE; i++)
    {
        inode.blocks[i] = -1;
    }
    set_inode(new_inode, &inode);

    get_block_data(bid, &dir_block);

    strcpy(dir_block.entries[0].name, ".");
    dir_block.entries[0].inode = new_inode;

    strcpy(dir_block.entries[1].name, "..");
    dir_block.entries[1].inode = pinode;

    for (i = 2; i < WOF_BLOCK_DIRS; i++)
        dir_block.entries[i].inode = -1;

    set_block_data(bid, &dir_block);

    return new_inode;
}

static int wo_creat_file(void)
{
    int bid, i;
    wof_inode_t inode;
    int new_inode;

    new_inode = wof_find_free_bit(g_wof_super.inode_bitmap_addr);
    if (new_inode == -1)
    {
        return -1;
    }
    get_inode(new_inode, &inode);

    bid = wof_find_free_bit(g_wof_super.data_bitmap_addr);
    if (bid == -1)
    {
        return -1;
    }
    bid += g_wof_super.data_region_addr;
    inode.type = WOF_FILE;
    inode.size = 0;
    inode.blocks[0] = bid;
    for (i = 1; i < WOF_BLOCK_DATA_SIZE; i++)
    {
        inode.blocks[i] = -1;
    }
    set_inode(new_inode, &inode);

    return new_inode;
}

static int wo_creat_dir_file(int inode_id, int type, char *name)
{
    wof_inode_t pdir_inode;
    int i, j;
    int bid;

    get_inode(inode_id, &pdir_inode);
    if (pdir_inode.type != WOF_DIRECTORY)
    {
        Errno = 1;
        printf("Errno value %d: inode %d not directory\n", Errno, inode_id);
        return -1;
    }

    wof_dir_t *find_ent = wof_find_dir_sub_file_by_name(&pdir_inode, name, NULL);
    if (find_ent != NULL)
    {
        return find_ent->inode;
    }

    int new_inode;
    if (type == WOF_DIRECTORY)
    {
        new_inode = wo_creat_dir(inode_id);
    }
    else
    {
        new_inode = wo_creat_file();
    }
    if (new_inode == -1)
    {
        Errno = 2;
        printf("Errno value %d: inode %d creat dir or file error\n", Errno, inode_id);
        return -1;
    }

    dir_block_t dir_block;
    for (i = 0; i < WOF_BLOCK_DATA_SIZE; i++)
    {
        if (pdir_inode.blocks[i] == -1)
        {
            continue;
        }

        bid = pdir_inode.blocks[i];
        get_block_data(bid, &dir_block);
        for (j = 2; j < WOF_BLOCK_DIRS; j++)
        {
            if (dir_block.entries[j].inode != -1)
            {
                continue;
            }
            strncpy(dir_block.entries[j].name, name, WOF_NAME_MAX);
            dir_block.entries[j].inode = new_inode;
            break;
        }

        pdir_inode.size += sizeof(wof_dir_t);
        set_inode(inode_id, &pdir_inode);
        set_block_data(bid, &dir_block);
        break;
    }

    return new_inode;
}

int wo_open_file(char *filename, int inode, int mode)
{
    int fd = wof_get_file_fd();
    if (fd == -1)
    {   
        Errno = 3;
        printf("Errno value %d: not free fd\n",Errno);
        return -1;
    }

    if (fd > WOF_SUPPORT_FILE_MAX)
    {   
        Errno = 3;
        printf("Errno value %d: file is full\n",Errno);
        bitmap_clear(&g_file_bitmap, fd);
        return -1;
    }

    wof_file_t *file = &g_wof_file_table[fd];
    strncpy(file->filename, filename, WOF_NAME_MAX);
    file->fd = fd;
    file->inode = inode;
    file->mode = mode;
    file->offset = 0;

    return fd;
}

int wo_open(char *filename, int flags, ...)
{
    int mode = 0777, i;
    va_list ap;
    char tmp_filename[WOF_NAME_MAX + 1] = {0};

    strncpy(tmp_filename, filename, WOF_NAME_MAX);
    printf("open %s\n", tmp_filename);

    if (filename[0] != '/')
    {   
        Errno = 4;
        printf("Errno value %d: only support /xx/xx/aa.txt",Errno);
        return -1;
    }

    if (filename[0] == '/' && strlen(filename) == 1)
    {
        Errno = 4;
        printf("Errno value %d: cant open / dir\n",Errno);
        return -1;
    }

    if (flags & WO_CREAT)
    {
        va_start(ap, flags);
        mode = va_arg(ap, int);
    }

    file_free_recu();

    char *token = strtok(tmp_filename, "/");
    while (token)
    {
        // printf("[%s]\n", token);
        file_add_recu(token);
        token = strtok(NULL, "/");
    }

    int parent_inode = g_root_dir_inode;
    struct file_dep *dep;
    int new_inode, fd, look_inode;
    for (i = 0; i < fdepth; i++)
    {
        dep = g_file_dep + i;
        look_inode = wof_lookup_dir_sub_name(parent_inode, dep->name);
        if (look_inode != -1)
        {
            if (i == fdepth - 1)
            {
                // creat open file struct
                fd = wo_open_file(dep->name, look_inode, mode);
                printf("file %s exist, inode is %d, open fd %d\n", dep->name, look_inode, fd);
                return fd;
            }
            parent_inode = look_inode;
            continue;
        }

        if (i != fdepth - 1)
        {
            if (flags & WO_CREAT)
            {
                new_inode = wo_creat_dir_file(parent_inode, WOF_DIRECTORY, dep->name);
                if (new_inode == -1)
                {
                    return -1;
                }
                printf("inode %d, creat dir %s, inode %d\n", parent_inode, dep->name, new_inode);
                parent_inode = new_inode;
                continue;
            }
            else
            {
                printf("dir %s not exist\n", dep->name);
                return -1;
            }
        }

        new_inode = wo_creat_dir_file(parent_inode, WOF_FILE, dep->name);
        if (new_inode == -1)
        {
            return -1;
        }

        // creat open file struct
        fd = wo_open_file(dep->name, new_inode, mode);
        printf("inode %d, creat new file %s, inode %d, fd %d\n", parent_inode, dep->name, new_inode, fd);
        return fd;
    }

    return -1;
}

int wo_read(int fd, void *buffer, int bytes)
{
    wof_inode_t inode;
    int i, read_len, read_index;
    char data[WOF_BLOCK_SIZE];

    if (fd <= 0 || fd > WOF_SUPPORT_FILE_MAX)
    {   
        Errno = 3;
        printf("Errno value %d: fd %d error\n",Errno, fd);
        return -1;
    }
    wof_file_t *file = &g_wof_file_table[fd];
    if (file->inode <= 0)
    {   
        Errno = 6;
        printf("Errno value %d: fd %d error\n",Errno, fd);
        return -1;
    }
    if ((file->mode & (WO_RDONLY | WO_RDWR)) == 0)
    {   
        Errno = 5;
        printf("Errno value %d: not read permission\n",Errno);
        return -1;
    }

    get_inode(file->inode, &inode);
    // read data
    int readn = bytes;
    int read_offset = 0;
    read_index = 0;

    for (i = 0; i < WOF_BLOCK_DATA_SIZE; i++)
    {
        if (readn <= 0)
        {
            break;
        }
        if (inode.blocks[i] == -1)
        {
            continue;
        }
        if (readn > WOF_BLOCK_SIZE)
        {
            read_len = WOF_BLOCK_SIZE;
        }
        else
        {
            read_len = readn;
        }
        if (read_offset < file->offset)
        {
            if (read_offset + read_len < file->offset)
            {
                read_offset += read_len;
                continue;
            }
            else
            {
                read_len = (read_offset + read_len) - file->offset;
            }
        }
        get_block_data(inode.blocks[i], data);
        memcpy(buffer + read_index, data, read_len);
        file->offset += read_len;
        read_index += read_len;
        readn -= read_len;
    }

    return read_index;
}

static int write_get_block_id(wof_inode_t *inode, int data_bid)
{
    int bid, dindex;

    if (inode->size == 0)
    {
        bid = inode->blocks[0];
        return bid;
    }

    if (inode->size > 0 && ((inode->size % WOF_BLOCK_SIZE) == 0))
    {
        dindex = inode->size / WOF_BLOCK_SIZE;
        data_bid = wof_find_free_bit(g_wof_super.data_bitmap_addr);
        if (data_bid == -1)
        {
            return -1;
        }

        data_bid += g_wof_super.data_region_addr;
        inode->blocks[dindex] = data_bid;
    }

    return data_bid;
}

static int write_do_skip_offset(int offset, wof_inode_t *inode)
{
    int woffset = offset;
    int data_bid = inode->blocks[0];
    int write_len;

    while (1)
    {
        if (woffset <= 0)
        {
            break;
        }

        data_bid = write_get_block_id(inode, data_bid);
        if (data_bid == -1)
        {
            return -1;
        }
        if (woffset > WOF_BLOCK_SIZE)
        {
            write_len = WOF_BLOCK_SIZE;
        }
        else
        {
            write_len = woffset;
        }
        if (inode->size < offset)
        {
            inode->size += write_len;
        }
        woffset -= write_len;
    }

    return 0;
}

int wo_write(int fd, void *buffer, int bytes)
{
    wof_inode_t inode;
    char data[WOF_BLOCK_SIZE];

    if (fd <= 0 || fd > WOF_SUPPORT_FILE_MAX)
    {
        Errno = 3;
        printf("Errno value %d: fd %d error\n",Errno, fd);
        return -1;
    }

    wof_file_t *file = &g_wof_file_table[fd];
    if (file->inode <= 0)
    {
        Errno = 3;
        printf("Errno value %d: fd %d error\n",Errno, fd);
        return -1;
    }

    if ((file->mode & (WO_WRONLY | WO_RDWR)) == 0)
    {
        Errno = 5;
        printf("Errno value %d: not read permission\n",Errno);
        return -1;
    }

    get_inode(file->inode, &inode);
    int bid_index;
    int writen = bytes;
    int write_len, write_index;
    int data_bid = -1;

    if (write_do_skip_offset(file->offset, &inode) != 0)
    {
        return -1;
    }

    bid_index = inode.size / WOF_BLOCK_SIZE;
    int write_size, left_size;

    left_size = 0;
    write_index = 0;
    write_size = inode.size % WOF_BLOCK_SIZE;
    if (write_size > 0)
    {
        left_size = WOF_BLOCK_SIZE - write_size;
    }
    data_bid = inode.blocks[bid_index];

    if (left_size > 0)
    {
        get_block_data(data_bid, data);
        memcpy(data + write_size, buffer + write_index, left_size);
        set_block_data(data_bid, data);

        write_index += left_size;
        file->offset += left_size;
        writen -= left_size;

        inode.size += left_size;
    }

    while (1)
    {
        if (writen <= 0)
        {
            break;
        }
        data_bid = write_get_block_id(&inode, data_bid);
        if (data_bid == -1)
        {
            return -1;
        }
        if (writen > WOF_BLOCK_SIZE)
        {
            write_len = WOF_BLOCK_SIZE;
        }
        else
        {
            write_len = writen;
        }

        get_block_data(data_bid, data);
        memcpy(data, buffer + write_index, write_len);
        set_block_data(data_bid, data);

        write_index += write_len;
        file->offset += write_len;
        inode.size += write_len;
        writen -= write_len;
    }
    set_inode(file->inode, &inode);

    return write_index;
}

int wo_close(int fd)
{
    if (fd <= 0 || fd > WOF_SUPPORT_FILE_MAX)
    {
        Errno = 3;
        printf("Errno value %d: fd %d error\n",Errno, fd);
        return -1;
    }

    wof_put_file_fd(fd);

    return 0;
}

int wo_mount(char *filename, void *image_addr)
{
    int num_inodes = 1024;
    int num_data = 3965;
    unsigned char *empty_buffer;
    int total_blocks;

#ifdef IMAGE_USE_ADDR
    struct stat stat;
#endif

    bitmap_set(&g_file_bitmap, 0);

    memset(g_image_filename, 0x00, 128);
    strncpy(g_image_filename, filename, 127);
    file_fd = open(g_image_filename, O_RDONLY);
    if (file_fd > 0)
    {
#ifdef IMAGE_USE_ADDR
    fstat(file_fd, &stat);
    g_image_size = stat.st_size;
    printf("read exist %s size %d\n", g_image_filename, g_image_size);
    close(file_fd);

    file_fd = open(g_image_filename, O_RDONLY);
    read(file_fd, image_addr, g_image_size);
    close(file_fd);
#endif
    wof_get_super_data(file_fd, &g_wof_super);
    total_blocks = 1 + 1 + 1 + g_wof_super.inode_region_len + g_wof_super.data_region_len;
    printf("  total blocks      %d, size %d\n", total_blocks, total_blocks * WOF_BLOCK_SIZE);
    printf("  inodes nums       %d [size of each: %lu]\n", num_inodes, sizeof(wof_inode_t));
    printf("  data blocks       %d\n", num_data);
    printf("  inode bitmap address %d\n", g_wof_super.inode_bitmap_addr);
    printf("  data bitmap address %d\n", g_wof_super.data_bitmap_addr);
    return 0;
    }

    empty_buffer = malloc(WOF_BLOCK_SIZE);
    memset(empty_buffer, 0x00, WOF_BLOCK_SIZE);
    file_fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (file_fd < 0)
    {
        perror("open");
        exit(1);
    }

    // init fs images
    wof_super_t s;
    s.inode_bitmap_addr = 1;
    s.data_bitmap_addr = s.inode_bitmap_addr + 1;

    // inode table
    s.inode_region_addr = s.data_bitmap_addr + 1;
    int total_inode_bytes = num_inodes * sizeof(wof_inode_t);
    s.inode_region_len = total_inode_bytes / WOF_BLOCK_SIZE;

    // data blocks
    s.data_region_addr = s.inode_region_addr + s.inode_region_len;
    s.data_region_len = num_data;

    total_blocks = 1 + 1 + 1 + s.inode_region_len + s.data_region_len;
    // write super block
    pwrite(file_fd, &s, sizeof(wof_super_t), 0);

    int i;
    for (i = 1; i < total_blocks; i++)
    {
        pwrite(file_fd, empty_buffer, WOF_BLOCK_SIZE, i * WOF_BLOCK_SIZE);
    }

    // init root dir
    bitmap_t b;
    for (i = 0; i < WOF_BITMAP_LEN; i++)
    {
        b.bits[i] = 0;
    }
    // root dir inode 0
    b.bits[0] |= 1 << 0;
    pwrite(file_fd, &b, WOF_BLOCK_SIZE, s.inode_bitmap_addr * WOF_BLOCK_SIZE);

    // root data block bitmap 0
    pwrite(file_fd, &b, WOF_BLOCK_SIZE, s.data_bitmap_addr * WOF_BLOCK_SIZE);

    // root inode
    inode_block itable;
    itable.inodes[0].type = WOF_DIRECTORY;
    itable.inodes[0].size = 2 * sizeof(wof_dir_t);
    itable.inodes[0].blocks[0] = s.data_region_addr;
    for (i = 1; i < WOF_BLOCK_DATA_SIZE; i++)
    {
        itable.inodes[0].blocks[i] = -1;
    }
    pwrite(file_fd, &itable, WOF_BLOCK_SIZE, s.inode_region_addr * WOF_BLOCK_SIZE);

    // init root subdir . && ..
    dir_block_t root;
    strcpy(root.entries[0].name, ".");
    root.entries[0].inode = 0;
    strcpy(root.entries[1].name, "..");
    root.entries[1].inode = 0;
    for (i = 2; i < WOF_BLOCK_DIRS; i++)
    {
        root.entries[i].inode = -1;
    }
    pwrite(file_fd, &root, WOF_BLOCK_SIZE, s.data_region_addr * WOF_BLOCK_SIZE);
    fsync(file_fd);

#ifdef IMAGE_USE_ADDR
    fstat(file_fd, &stat);
    g_image_size = stat.st_size;
    printf("creat new %s size %d\n", g_image_filename, g_image_size);
    close(file_fd);

    file_fd = open(g_image_filename, O_RDONLY);
    read(file_fd, image_addr, g_image_size);
    close(file_fd);
#endif
    wof_get_super_data(file_fd, &g_wof_super);
    total_blocks = 1 + 1 + 1 + g_wof_super.inode_region_len + g_wof_super.data_region_len;
    printf("  total blocks      %d, size %d\n", total_blocks, total_blocks * WOF_BLOCK_SIZE);
    printf("  inodes nums       %d [size of each: %lu]\n", num_inodes, sizeof(wof_inode_t));
    printf("  data blocks       %d\n", num_data);
    printf("  inode bitmap address %d\n", g_wof_super.inode_bitmap_addr);
    printf("  data bitmap address %d\n", g_wof_super.data_bitmap_addr);

    free(empty_buffer);

    return 0;
}

int wo_unmount(void *image_addr)
{
    int fd;
#ifdef IMAGE_USE_ADDR
    fd = open(g_image_filename, O_WRONLY);
    if (fd < 0)
    {
        printf("open %s error\n", g_image_filename);
        return -1;
    }
    write(fd, image_addr, g_image_size);
#else
    fd = file_fd;
#endif
    fsync(fd);
    close(fd);

    return 0;
}

#ifndef WOF_LIB
#define MOUTN_AMAGE_LEN (4 * 1024 * 1024) // 4M
int main(int argc, char *argv[])
{
    g_image_addr = malloc(MOUTN_AMAGE_LEN);

    wo_mount("wof.disk", g_image_addr);

    int fd = wo_open("/aa/bb//test.txt", WO_WRONLY | WO_CREAT, 0777);
    if (fd == -1)
    {
        printf("open error");
        goto __unmount;
    }
    printf("write test.txt:[hello] successfully\n");
    wo_write(fd, "hello", 5);
    wo_close(fd);

    char buf[16] = {0};
    fd = wo_open("/aa/bb//test.txt", WO_RDONLY);
    if (fd == -1)
    {
        printf("open error");
        goto __unmount;
    }
    wo_read(fd, buf, 5);
    printf("read test.txt:[%s] successfully\n", buf);
    wo_close(fd);

__unmount:
    wo_unmount(g_image_addr);

    return 0;
}
#endif
