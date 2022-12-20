# My own file system

We designed and implemented a write-once file system, which has directory function and have ability to support more than 50 files and 2MB of user data as requested. 

After make all, the 4MB wo.disk is paged with 1KB chunks. writeonce file will run the test function. You can use run.sh to try our code.

## Contributors: Zihan Chen and Jiayi Zhang

## Academic Integrity Policy

In order to respect our university's academic integrity policy, we have decided not to show specific requirements of this file system.

## Test

We use int Errno to represent errno number, they are listed below:

```C
/*
 * Errno value       Error
 * 1             Directory not exists
 * 2             Create error, no such file or directory
 * 3             Out of memory
 * 4             Illegal name
 * 5             Operation not permitted
 * 6             disk broken
 */
```

Everytimes we mount the system, we will print the detail information about our storage, which include:

```C
/*
 * Total blocks
 * Inodes numbers
 * Data blocks
 * Inode bitmap address
 * Data bitmap address
*/
```

To test our implementation, we create a **aa/bb//test.txt** file and did some read and write operations.

## Output

It passed all our test, the output listed below:


```terminal
rm -rf writeonceFS libwriteonceFS *.o libwriteonceFS.so wof.disk writeonceFS
gcc -g -Wall writeonceFS.c -o writeonceFS
gcc -g -Wall -DWOF_LIB -fPIC -shared writeonceFS.c -o libwriteonceFS.so
creat new wof.disk size 4194304
  total blocks      4096, size 4194304
  inodes nums       1024 [size of each: 128]
  data blocks       3965
  inode bitmap address 1
  data bitmap address 2
open /aa/bb//test.txt
inode 0 not find name aa
inode 0, creat dir aa, inode 1
inode 1 not find name bb
inode 1, creat dir bb, inode 2
inode 2 not find name test.txt
inode 2, creat new file test.txt, inode 3, fd 1
write test.txt:[hello] successfully
open /aa/bb//test.txt
file test.txt exist, inode is 3, open fd 1
read test.txt:[hello] successfully
```