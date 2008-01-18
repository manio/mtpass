/*
    mtpass.c
    This program simply decode admin password from user file
    i don't have time to figure out the user.dat structure so
    this program only show the admin password (offset 140).
    If you know where the other user password start you can
    change it to fit your needs :)

    license: GPL v2.0
    (c) by Mariusz "Manio" Bialonczyk; manio@skyboo.net
    v0.1 [2007-01-03]: initial release
*/

#include <stdio.h>
#include <fcntl.h>
#define PWLENGTH     17
#define START_OFFSET 0x8c

int main(int argc, char **argv)
{
    char key[PWLENGTH] = {0x48, 0xbf, 0xde, 0x06, 0x49, 0x5a, 0x0e, 0x2d, 0x09, 0xd5, 0xfb, 0x27, 0xb1, 0x44, 0xec, 0x93, 0x01};
    char pass[PWLENGTH] = {0};
    int fd, i;

    if (argc <= 1)
    {
	fprintf(stderr, "usage: %s input_file\n", argv[0]);
	fprintf(stderr, "input_file: RouterOS userdata file from /nova/store/user.dat");
	return -1;
    }

    fd = open(argv[1], O_RDONLY);
    if (fd < 0)
    {
	fprintf(stderr, "Error: could not open file: %s\n", argv[1]);
	return -1;
    }

    lseek(fd, START_OFFSET, SEEK_SET);

    if (read(fd, &pass, PWLENGTH) != 0)
    {
	for (i=0; i<PWLENGTH; i++)
	    fprintf(stdout, "%c", pass[i]^key[i]);
	fprintf(stdout, "\n");
    }

    close(fd);
    return 0;
}
