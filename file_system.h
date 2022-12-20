
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