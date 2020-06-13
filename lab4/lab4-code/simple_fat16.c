#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>

#define FUSE_USE_VERSION 26
#include <fuse.h>

#include "fat16.h"
#include "bench.h"
char *FAT_FILE_NAME = "fat16.img";

/* 将扇区号为secnum的扇区读到buffer中 */

void sector_read(FILE *fd, unsigned int secnum, void *buffer)
{
    fseek(fd, BYTES_PER_SECTOR * secnum, SEEK_SET);
    fread(buffer, BYTES_PER_SECTOR, 1, fd);
}

/** TODO:
 * 将输入路径按“/”分割成多个字符串，并按照FAT文件名格式转换字符串
 * 输入: pathInput: char*, 输入的文件路径名, 如/home/user/m.c
 * 输出: pathDepth_ret, 文件层次深度, 如 3
 * 返回: 按FAT格式转换后的文件名字符串.
 * 
 * Hint1:假设pathInput为“/dir1/dir2/file.txt”，则将其分割成“dir1”，“dir2”，“file.txt”，
 *      每个字符串转换成长度为11的FAT格式的文件名，如“file.txt”转换成“FILE    TXT”，
 *      返回转换后的字符串数组，并将*pathDepth_ret设置为3, 转换格式在文档中有说明.
 * Hint2:可能会出现过长的字符串输入，如“/.Trash-1000”，需要自行截断字符串
 * Hint3:需要考虑.和..的情况(. 和 .. 的输入应当为 /.和/..)
 **/

char **path_split(char *pathInput, int *pathDepth_ret)
{
    int i = 0;
    int pathDepth = 0;
    int cur_Depth = 0;

    for (; pathInput[i] != '\0'; i++)
    {
        if (pathInput[i] == '/')
            pathDepth++;
    }
    *pathDepth_ret = pathDepth;
    char **paths = malloc(pathDepth * sizeof(char *));

    for (i = 0; i < pathDepth; i++)
    {
        path[i] = malloc(11 * sizeof(char));
    }

    int k = 0; /* k 用于记录当前目录/文件名的长度 */

    if (strcmp(pathInput, "/.") == 0)
    {
        strcmp(paths[0], ".          ");
        return(paths);
    }

    else if (strcmp(pathInput, "/..") == 0)
    {
        strcmp(paths[0], "..         ");
        return(paths);
    }

    for (i = 1; pathInput[i] != '\0'; i++)
    {

        if (pathInput[i] == '/')
        {
            while (k < 11)
            {
                paths[cur_Depth][k] = ' ';
                k++;
            }
            cur_Depth++;
            k = 0;
        }

        else if (pathInput[i] == '.')
        {
            while (k < 11)
            {
                paths[cur_Depth][k] = ' ';
                k++;
            }
        }

        else
        {
            if (k < 11) /* 大于 11 后，直接截断。FAT16 不支持长文件名 */
            {
                if (pathInput[i] >= 'a' && pathInput[i] <= 'z') /* 英文字母统一按大写存储 */
                    paths[cur_Depth][k] = pathInput[i] - 32;
                else
                    paths[cur_Depth][k] = pathInput[i];
            }
            k++;
        }
    }

    return paths;
}

/** 
 * 将FAT文件名格式解码成原始的文件名
 * 
 * 假设path是“FILE    TXT”，则返回"file.txt"
 **/
BYTE *path_decode(BYTE *path)
{
    int i, j;
    BYTE *pathDecoded = malloc(MAX_SHORT_NAME_LEN * sizeof(BYTE));

    /* If the name consists of "." or "..", return them as the decoded path */
    if (path[0] == '.' && path[1] == '.' && path[2] == ' ')
    {
        pathDecoded[0] = '.';
        pathDecoded[1] = '.';
        pathDecoded[2] = '\0';
        return pathDecoded;
    }
    if (path[0] == '.' && path[1] == ' ')
    {
        pathDecoded[0] = '.';
        pathDecoded[1] = '\0';
        return pathDecoded;
    }

    /* Decoding from uppercase letters to lowercase letters, removing spaces,
     * inserting 'dots' in between them and verifying if they are legal */
    for (i = 0, j = 0; i < 11; i++)
    {
        if (path[i] != ' ')
        {
            if (i == 8)
                pathDecoded[j++] = '.';

            if (path[i] >= 'A' && path[i] <= 'Z')
                pathDecoded[j++] = path[i] - 'A' + 'a';
            else
                pathDecoded[j++] = path[i];
        }
    }
    pathDecoded[j] = '\0';
    return pathDecoded;
}

FAT16 *pre_init_fat16(void)
{
    /* Opening the FAT16 image file */
    FILE *fd;
    FAT16 *fat16_ins;
    BYTE buffer[BYTES_PER_SECTOR];

    fd = fopen(FAT_FILE_NAME, "rb");

    if (fd == NULL)
    {
        fprintf(stderr, "Missing FAT16 image file!\n");
        exit(EXIT_FAILURE);
    }

    fat16_ins = malloc(sizeof(FAT16));
    fat16_ins->fd = fd;

    /** TODO: 
    * 初始化fat16_ins的其余成员变量, 该struct定义在fat16.c的第65行
    * 其余成员变量如下:
    *  FirstRootDirSecNum->第一个根目录的扇区偏移.
    *  FirstDataSector->第一个数据区的扇区偏移
    *  Bpb->Bpb结构
    * Hint1: 使用sector_read读出fat16_ins中Bpb项的内容, 这个函数定义在本文件的第18行.
    * Hint2: 可以使用BPB中的参数完成其他变量的初始化, 该struct定义在fat16.c的第23行
    * Hint3: root directory的大小与Bpb.BPB_RootEntCnt有关，并且是扇区对齐的
    **/

    sector_read(fd, 0, buffer);

   
    memcpy(&fat16->Bpb.BS_jmpBoot, buffer, 3);
    memcpy(&fat16->Bpb.BS_OEMName, buffer + 3, 8);
    memcpy(&fat16_ins->Bpb.BPB_BytsPerSec, buffer + 11, 2);
    memcpy(&fat16_ins->Bpb.BPB_SecPerClus, buffer + 13, 1);
    memcpy(&fat16_ins->Bpb.BPB_RsvdSecCnt, buffer + 14, 2);
    memcpy(&fat16_ins->Bpb.BPB_NumFATS, buffer + 16, 1);
    memcpy(&fat16_ins->Bpb.BPB_RootEntCnt, buffer + 17, 2);
    memcpy(&fat16_ins->Bpb.BPB_TotSec16, buffer + 19, 2);
    memcpy(&fat16_ins->Bpb.BPB_Media, buffer + 21, 1);
    memcpy(&fat16_ins->Bpb.BPB_FATSz16, buffer + 22, 2);
    memcpy(&fat16_ins->Bpb.BPB_SecPerTrk, buffer + 24, 2);
    memcpy(&fat16_ins->Bpb.BPB_NumHeads, buffer + 26, 2);
    memcpy(&fat16_ins->Bpb.BPB_HiddSec, buffer + 28, 4);
    memcpy(&fat16_ins->Bpb.BPB_TotSec32, buffer + 32, 4);
    memcpy(&fat16_ins->Bpb.BS_DrvNum, buffer + 0x24, 1);
    memcpy(&fat16_ins->Bpb.BS_Reserved1, buffer + 0x25, 1);
    memcpy(&fat16_ins->Bpb.BS_BootSig, buffer + 0x26, 1);
    memcpy(&fat16_ins->Bpb.BS_VollID, buffer + 0x27, 4);
    memcpy(fat16_ins->Bpb.BS_VollLab, buffer + 0x2b, 11);
    memcpy(fat16_ins->Bpb.BS_FilSysType, buffer + 0x36, 8);
    memcpy(fat16_ins->Bpb.Reserved2, buffer + 0x3e, 448);
    memcpy(&fat16_ins->Bpb.Signature_word, buffer + 0x01fe, 2);

    

    /* 根目录偏移 = FAT1 的偏移 + 所有 FAT 表的长度 */
    fat16_ins->FirstRootDirSecNum = fat16_ins->Bpb.BPB_RsvdSecCnt + fat16_ins->Bpb.BPB_NumFATS * fat16_ins->Bpb.BPB_FATSz16;

    /* 数据区偏移：在根目录的基础上进行计算 */
    fat16_ins->FirstDataSector = fat16_ins->FirstRootDirSecNum + fat16_ins->Bpb.BPB_RootEntCnt * 32 / fat16_ins->Bpb.BPB_BytsPerSec;

    return fat16_ins;
}

/** TODO:
 * 返回簇号为ClusterN对应的FAT表项
 **/
WORD fat_entry_by_cluster(FAT16 *fat16_ins, WORD ClusterN)
{
    BYTE sector_buffer[BYTES_PER_SECTOR];
    WORD offset_by_byte, SEC_offset;
    WORD Sec_Num, FatClusEntryVal;

    offset_by_byte = 2 * ClusterN;

    Sec_Num = offset_by_byte / fat16_ins->Bpb.BPB_BytsPerSec;
    SEC_offset = offset_by_byte % fat16_ins->Bpb.BPB_BytsPerSec;

    sector_read(fat16_ins->fd, fat16_ins->Bpb.BPB_RsvdSecCnt + Sec_Num, sector_buffer);

    FatClusEntryVal = *((WORD*)&sector_buffer[SEC_offset];
    return 0xffff;
}

/**
 * 根据簇号ClusterN，获取其对应的第一个扇区的扇区号和数据，以及对应的FAT表项
 **/
void first_sector_by_cluster(FAT16 *fat16_ins, WORD ClusterN, WORD *FatClusEntryVal, WORD *FirstSectorofCluster, BYTE *buffer)
{
    *FatClusEntryVal = fat_entry_by_cluster(fat16_ins, ClusterN);
    *FirstSectorofCluster = ((ClusterN - 2) * fat16_ins->Bpb.BPB_SecPerClus) + fat16_ins->FirstDataSector;

    sector_read(fat16_ins->fd, *FirstSectorofCluster, buffer);
}

/**
 * 从root directory开始，查找path对应的文件或目录，找到返回0，没找到返回1，并将Dir填充为查找到的对应目录项
 * 
 * Hint: 假设path是“/dir1/dir2/file”，则先在root directory中查找名为dir1的目录，
 *       然后在dir1中查找名为dir2的目录，最后在dir2中查找名为file的文件，找到则返回0，并且将file的目录项数据写入到参数Dir对应的DIR_ENTRY中
 **/
int find_root(FAT16 *fat16_ins, DIR_ENTRY *Root, const char *path)
{
    int pathDepth;
    char **paths = path_split((char *)path, &pathDepth);

    /* 先读取root directory */
    int i, j;
    int RootDirCnt = 1; /* 用于统计已读取的扇区数 */
    int is_eq;
    BYTE buffer[BYTES_PER_SECTOR];

    sector_read(fat16_ins->fd, fat16_ins->FirstRootDirSecNum, buffer);

    /** 
     * 查找名字为paths[0]的目录项，
     * 如果找到目录，则根据pathDepth判断是否需要调用find_subdir继续查找，
     * 
     * !!注意root directory可能包含多个扇区
     **/
    for (i = 1; i <= fat16_ins->Bpb.BPB_RootEntCnt; i++)
    {
        memcpy(Root, &buffer[((i - 1) * BYTES_PER_DIR) % BYTES_PER_SECTOR], BYTES_PER_DIR);

        /* If the directory entry is free, all the next directory entries are also
         * free. So this file/directory could not be found */
        if (Root->DIR_Name[0] == 0x00)
        {
            return 1;
        }

        /* Comparing strings character by character */
        is_eq = strncmp(Root->DIR_Name, paths[0], 11) == 0 ? 1 : 0;

        /* If the path is only one file (ATTR_ARCHIVE) and it is located in the
         * root directory, stop searching */
        if (is_eq && Root->DIR_Attr == ATTR_ARCHIVE)
        {
            return 0;
        }

        /* If the path is only one directory (ATTR_DIRECTORY) and it is located in
         * the root directory, stop searching */
        if (is_eq && Root->DIR_Attr == ATTR_DIRECTORY && pathDepth == 1)
        {
            return 0;
        }

        /* If the first level of the path is a directory, continue searching
         * in the root's sub-directories */
        if (is_eq && Root->DIR_Attr == ATTR_DIRECTORY)
        {
            return find_subdir(fat16_ins, Root, paths, pathDepth, 1);
        }

        /* End of bytes for this sector (1 sector == 512 bytes == 16 DIR entries)
         * Read next sector */
        if (i % 16 == 0 && i != fat16_ins->Bpb.BPB_RootEntCnt)
        {
            sector_read(fat16_ins->fd, fat16_ins->FirstRootDirSecNum + RootDirCnt, buffer);
            RootDirCnt++;
        }
    }

    return 1;
}

/** TODO:
 * 从子目录开始查找path对应的文件或目录，找到返回0，没找到返回1，并将Dir填充为查找到的对应目录项
 * 
 * Hint1: 在find_subdir入口处，Dir应该是要查找的这一级目录的表项，需要根据其中的簇号，读取这级目录对应的扇区数据
 * Hint2: 目录的大小是未知的，可能跨越多个扇区或跨越多个簇；当查找到某表项以0x00开头就可以停止查找
 * Hint3: 需要查找名字为paths[curDepth]的文件或目录，同样需要根据pathDepth判断是否继续调用find_subdir函数
 **/

int find_subdir(FAT16 *fat16_ins, DIR_ENTRY *Dir, char **paths, int pathDepth, int curDepth)
{
    int i, j;
    int DirSecCnt = 1; /* 用于统计已读取的扇区数 */
    BYTE buffer[BYTES_PER_SECTOR];

    WORD ClusterN, FatClusEntryVal, FirstSectorofCluster;

    int Dir_per_sec = fat16_ins->Bpb.BPB_BytsPerSec / BYTES_PER_DIR;
    first_sector_by_cluster(fat16_ins, Dir->DIR_FstClusLO, &FatClusEntryVal, &FirstSectorofCluster, buffer);

    i = 0;

    while(true)
    {
        if(i % Dir_per_sec == 0 && i !=0 )
        {
            DirSecCnt++;
            sector_read(fat16_ins->fd, FirstSectorofCluster + (DirSecCnt - 1) % fat16_ins->Bpb.BPB_SecPerClus, buffer);

        }

        if(i % (Dir_per_sec * fat16_ins->Bpb.BPB_SecPerClus) == 0 && i != 0)
        {
            DirSecCnt = 1;
            ClusterN = FatClusEntryVal;
            first_sector_by_cluster(fat16_ins, ClusterN, &FatClusEntryVal, &FirstSectorofCluster, buffer);
        }

        if(FatClusEntryVal == 0x00)
        {
            break;
        }  

        if(strncmp(paths[curDepth],  buffer + i % Dir_per_sec * BYTES_PER_DIR, 11) == 0)
        {
            memcpy(Dir, buffer + i % Dir_per_sec * BYTES_PER_DIR, BYTES_PER_DIR);
            if(curDepth = pathDepth - 1)
            {
                return 0;
            }
            else
            {
                return(find_subdir(fat16_ins, Dir, paths, pathDepth, curDepth + 1);)
            }
        }

        i++;
    }

    return 1;
}










/** TODO:
 * 从path对应的文件(一定不为根目录"/")的offset字节处开始读取size字节的数据到buffer中，并返回实际读取的字节数
 * Hint: 以扇区为单位读入，需要考虑读到当前簇结尾时切换到下一个簇，并更新要读的扇区号等信息
 * Hint: 文件大小属性是Dir.DIR_FileSize；当offset超过文件大小时，应该返回0
 * 此函数会作为读文件的函数实现被fuse文件系统使用，见fat16_read函数
 * 所以实现正确时的效果为实验文档中的测试二中可以正常访问文件
**/

int read_path(FAT16 *fat16_ins, const char *path, size_t size, off_t offset, char *buffer)
{
    int i, j;
    int malloc_size = (size + offset) > BYTES_PER_SECTOR ? (size + offset) : BYTES_PER_SECTOR;
    BYTE *sector_buffer = malloc(malloc_size * sizeof(BYTE));

    /*  文件对应目录项，簇号，簇对应FAT表项的内容，簇的第一个扇区号  */
    DIR_ENTRY Dir;
    WORD ClusterN, FatClusEntryVal, FirstSectorofCluster;

    if(find_root(fat16_ins, &Dir, path) == 1 || Dir.DIR_FileSize <= offset)
    {
        return 0;
    }

    ClusterN = Dir.DIR_FstClusLO;
    first_sector_by_cluster(fat16_ins, ClusterN, &FatClusEntryVal, &FirstSectorofCluster, buffer);

    for (i = 0, j = 0; i < size + offset; i += BYTES_PER_SECTOR, j++)
    {
        sector_read(fat16_ins->fd, FirstSectorofCluster + j, sector_buffer + i);
        if ((j + 1) % fat16_ins->Bpb.BPB_SecPerClus == 0)
        {
            ClusterN = FatClusEntryVal;
            first_sector_by_cluster(fat16_ins, ClusterN, &FatClusEntryVal, &FirstSectorofCluster, buffer);
            j = -1;
        }
    }


    memcpy(buffer, sector_buffer + offset, size);
    free(sector_buffer);


    return size;

}

/**
 * ------------------------------------------------------------------------------
 * FUSE相关的函数实现
 **/

void *fat16_init(struct fuse_conn_info *conn)
{
    struct fuse_context *context;
    context = fuse_get_context();

    return context->private_data;
}

void fat16_destroy(void *data)
{
    free(data);
}

int fat16_getattr(const char *path, struct stat *stbuf)
{
    FAT16 *fat16_ins;

    struct fuse_context *context;
    context = fuse_get_context();
    fat16_ins = (FAT16 *)context->private_data;

    memset(stbuf, 0, sizeof(struct stat));
    stbuf->st_dev = fat16_ins->Bpb.BS_VollID;
    stbuf->st_blksize = BYTES_PER_SECTOR * fat16_ins->Bpb.BPB_SecPerClus;
    stbuf->st_uid = getuid();
    stbuf->st_gid = getgid();

    if (strcmp(path, "/") == 0)
    {
        stbuf->st_mode = S_IFDIR | S_IRWXU;
        stbuf->st_size = 0;
        stbuf->st_blocks = 0;
        stbuf->st_ctime = stbuf->st_atime = stbuf->st_mtime = 0;
    }
    else
    {
        DIR_ENTRY Dir;

        int res = find_root(fat16_ins, &Dir, path);

        if (res == 0)
        {
            if (Dir.DIR_Attr == ATTR_DIRECTORY)
            {
                stbuf->st_mode = S_IFDIR | 0755;
            }
            else
            {
                stbuf->st_mode = S_IFREG | 0755;
            }
            stbuf->st_size = Dir.DIR_FileSize;

            if (stbuf->st_size % stbuf->st_blksize != 0)
            {
                stbuf->st_blocks = (int)(stbuf->st_size / stbuf->st_blksize) + 1;
            }
            else
            {
                stbuf->st_blocks = (int)(stbuf->st_size / stbuf->st_blksize);
            }

            struct tm t;
            memset((char *)&t, 0, sizeof(struct tm));
            t.tm_sec = Dir.DIR_WrtTime & ((1 << 5) - 1);
            t.tm_min = (Dir.DIR_WrtTime >> 5) & ((1 << 6) - 1);
            t.tm_hour = Dir.DIR_WrtTime >> 11;
            t.tm_mday = (Dir.DIR_WrtDate & ((1 << 5) - 1));
            t.tm_mon = (Dir.DIR_WrtDate >> 5) & ((1 << 4) - 1);
            t.tm_year = 80 + (Dir.DIR_WrtDate >> 9);
            stbuf->st_ctime = stbuf->st_atime = stbuf->st_mtime = mktime(&t);
        }
    }
    return 0;
}

int fat16_readdir(const char *path, void *buffer, fuse_fill_dir_t filler,
                  off_t offset, struct fuse_file_info *fi)
{
    FAT16 *fat16_ins;
    BYTE sector_buffer[BYTES_PER_SECTOR];
    int RootDirCnt = 1, DirSecCnt = 1, i;

    /* Gets volume data supplied in the context during the fat16_init function */
    struct fuse_context *context;
    context = fuse_get_context();
    fat16_ins = (FAT16 *)context->private_data;

    sector_read(fat16_ins->fd, fat16_ins->FirstRootDirSecNum, sector_buffer);

    if (strcmp(path, "/") == 0)
    {
        DIR_ENTRY Root;

        /* Starts filling the requested directory entries into the buffer */
        for (i = 1; i <= fat16_ins->Bpb.BPB_RootEntCnt; i++)
        {
            memcpy(&Root, &sector_buffer[((i - 1) * BYTES_PER_DIR) % BYTES_PER_SECTOR], BYTES_PER_DIR);

            /* No more files to fill */
            if (Root.DIR_Name[0] == 0x00)
            {
                return 0;
            }

            /* If we find a file or a directory, fill it into the buffer */
            if (Root.DIR_Attr == ATTR_ARCHIVE || Root.DIR_Attr == ATTR_DIRECTORY)
            {
                const char *filename = (const char *)path_decode(Root.DIR_Name);
                filler(buffer, filename, NULL, 0);
            }

            /* End of bytes for this sector (1 sector == 512 bytes == 16 DIR entries)
             * Read next sector */
            if (i % 16 == 0 && i != fat16_ins->Bpb.BPB_RootEntCnt)
            {
                sector_read(fat16_ins->fd, fat16_ins->FirstRootDirSecNum + RootDirCnt, sector_buffer);
                RootDirCnt++;
            }
        }
    }
    else
    {
        DIR_ENTRY Dir;

        /* Finds the first corresponding directory entry in the root directory and
         * store the result in the directory entry Dir */
        find_root(fat16_ins, &Dir, path);

        /* Calculating the first cluster sector for the given path */
        WORD ClusterN, FatClusEntryVal, FirstSectorofCluster;

        ClusterN = Dir.DIR_FstClusLO;

        first_sector_by_cluster(fat16_ins, ClusterN, &FatClusEntryVal, &FirstSectorofCluster, sector_buffer);

        /* Start searching the root's sub-directories starting from Dir */
        for (i = 1; Dir.DIR_Name[0] != 0x00; i++)
        {
            memcpy(&Dir, &sector_buffer[((i - 1) * BYTES_PER_DIR) % BYTES_PER_SECTOR], BYTES_PER_DIR);

            /* If the last file of the path is located in this directory, stop
             * searching */
            if (Dir.DIR_Attr == ATTR_ARCHIVE || Dir.DIR_Attr == ATTR_DIRECTORY)
            {
                const char *filename = (const char *)path_decode(Dir.DIR_Name);
                filler(buffer, filename, NULL, 0);
            }

            /* End of bytes for this sector (1 sector == 512 bytes == 16 DIR entries) */
            if (i % 16 == 0)
            {
                /* If there are still sector to be read in the cluster, read the next sector. */
                if (DirSecCnt < fat16_ins->Bpb.BPB_SecPerClus)
                {
                    sector_read(fat16_ins->fd, FirstSectorofCluster + DirSecCnt, sector_buffer);
                    DirSecCnt++;

                    /* Else, read the next sector */
                }
                else
                {
                    /* Not strictly necessary, but here we reach the end of the clusters
                     * of this directory entry. */
                    if (FatClusEntryVal == 0xffff)
                    {
                        return 0;
                    }

                    /* Next cluster */
                    ClusterN = FatClusEntryVal;

                    first_sector_by_cluster(fat16_ins, ClusterN, &FatClusEntryVal, &FirstSectorofCluster, sector_buffer);

                    i = 0;
                    DirSecCnt = 1;
                }
            }
        }
    }

    /* No more files */
    return 0;
}

/* 读文件接口，直接调用read_path实现 */
int fat16_read(const char *path, char *buffer, size_t size, off_t offset,
               struct fuse_file_info *fi)
{
    FAT16 *fat16_ins;
    struct fuse_context *context;
    context = fuse_get_context();
    fat16_ins = (FAT16 *)context->private_data;

    return read_path(fat16_ins, path, size, offset, buffer);
}

/* read_path()调试思路参考，不作为计分标准 */
void test_read_path()
{
    char *buffer;
    /* 这里使用的文件镜像是fat16_test.img */
    FAT_FILE_NAME = "fat16_test.img";
    FAT16 *fat16_ins = pre_init_fat16();

    /* 测试用的文件、读取大小、位移和应该读出的文本 */
    char path[][32] = {"/Makefile", "/log.c", "/dir1/dir2/dir3/test.c"};
    int size[] = {32, 9, 9};
    int offset[] = {8, 9, 9};
    char texts[][32] = {"(shell pkg-config fuse --cflags)", "<errno.h>", "<errno.h>"};

    int i;
    for (i = 0; i < sizeof(path) / sizeof(path[0]); i++)
    {
        DIR_ENTRY Dir;
        buffer = malloc(size[i] * sizeof(char));
        /* 读文件 */
        read_path(fat16_ins, path[i], size[i], offset[i], buffer);
        /* 比较读出的结果 */
        assert(strncmp(buffer, texts[i], size[i]) == 0);
        free(buffer);
        printf("test case %d: OK\n", i + 1);
    }

    fclose(fat16_ins->fd);
    free(fat16_ins);
}

struct fuse_operations fat16_oper = {
    .init = fat16_init,
    .destroy = fat16_destroy,
    .getattr = fat16_getattr,
    .readdir = fat16_readdir,
    .read = fat16_read};

int main(int argc, char *argv[])
{
    int ret;

    if (strcmp(argv[1], "--debug") == 0)
    {
        // 将你自己的Debug用的语句写在这里.
        // 通过 ./simple_fat16 --debug 执行这里的语句.

        return 0;
    }

    if (strcmp(argv[1], "--test") == 0)
    {
        printf("--------------\nrunning test\n--------------\n");
        FAT_FILE_NAME = "fat16_test.img";
        test_path_split();
        test_pre_init_fat16();
        test_fat_entry_by_cluster();
        test_find_subdir();

        // 以下内容作为参考
        /* test_path_decode(); */
        /* test_find_root(); */
        exit(EXIT_SUCCESS);
    }

    FAT16 *fat16_ins = pre_init_fat16();

    ret = fuse_main(argc, argv, &fat16_oper, fat16_ins);

    return ret;
}
