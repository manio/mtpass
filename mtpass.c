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
#include <stdlib.h>
#define PWLENGTH     16
#define START_OFFSET1 0x2e
//#define START_OFFSET2 0x8c
#define START_OFFSET2 0x79
#define START_OFFSET3 0xd4
#define START_OFFSET4 0x11c
#define START_OFFSET5 0x11c

int main(int argc, char **argv)
{
    char key[10][PWLENGTH] = {
	{0x02, 0x6d, 0xb5, 0x70, 0x66, 0xa6, 0x3d, 0x2a, 0xb7, 0xcd, 0xec, 0x68, 0xe2, 0x6e, 0x44, 0x0e},
        {0x48, 0xbf, 0xde, 0x06, 0x49, 0x5a, 0x0e, 0x2d, 0x09, 0xd5, 0xfb, 0x27, 0xb1, 0x44, 0xec, 0x93},
        {0xe8, 0x61, 0xb0, 0xa8, 0x2f, 0xbb, 0x68, 0x29, 0xe2, 0x53, 0xce, 0xeb, 0x1e, 0x3e, 0x61, 0x5a},
        {0x98, 0x40, 0x20, 0xa0, 0x8c, 0xb9, 0xba, 0x55, 0xb9, 0xb6, 0xf2, 0x48, 0x0c, 0xd5, 0x2b, 0x80},
        {0xe3, 0x33, 0x29, 0x1d, 0x2e, 0xc8, 0x9a, 0xfc, 0xf2, 0xd2, 0xc5, 0x8c, 0xe5, 0xfd, 0xff, 0x36},
        {0x06, 0xa4, 0x6c, 0x65, 0x97, 0x5b, 0x79, 0x7c, 0x74, 0xf6, 0xbd, 0x94, 0x43, 0x00, 0x23, 0x41},
        {0x79, 0x37, 0x7c, 0x26, 0xdc, 0x38, 0xbf, 0xda, 0xf2, 0x23, 0xd4, 0x57, 0x83, 0xa9, 0x84, 0xdb},
        {0x3f, 0xea, 0xb5, 0x12, 0x11, 0xab, 0x30, 0x17, 0xbe, 0x71, 0x86, 0xae, 0x65, 0xde, 0x96, 0x60},
        {0xa2, 0xdb, 0xb1, 0x5d, 0x27, 0x72, 0x44, 0x6f, 0xa9, 0x1c, 0xa2, 0x38, 0xb0, 0xfc, 0xc2, 0x29},
        {0x26, 0xa0, 0x52, 0x14, 0x80, 0x0e, 0xa2, 0x6b, 0xbd, 0x5f, 0x7c, 0x53, 0x6f, 0xde, 0x08, 0x71}
    };
    //char pass[PWLENGTH] = {0};
    char *buff;
    int fd, i, j, k, pass;
    int bytes;

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
    bytes = lseek(fd, 0, SEEK_END);
    fprintf(stdout, "Reading file %s, %d bytes long\n", argv[1], bytes);
    buff = (char*) malloc(bytes * sizeof(char));
    if (buff==NULL)
    {
	fprintf(stderr, "Error: cannot allocate buffer\n");
	return -1;
    }

    lseek(fd, 0, SEEK_SET);
    if (read(fd, buff, bytes) == bytes)
    {
	pass=1;
	for (i=0; i<bytes; i++)
	{
	    if ((buff[i]==0x21) && (buff[i+1]==0x10))
	    {
		i+=2;
		printf("Found pass #%d at offset 0x%.5x:\t",pass,i);
		switch(i)
		{
		    case 0x02e: pass=1;break;
		    case 0x079: pass=2;break;
		    case 0x08c: pass=1;break;
		    case 0x0d4: pass=9;break;
		    case 0x11c: pass=3;break;
		    case 0x164: pass=4;break;
		    case 0x1ac: pass=5;break;
		    case 0x1e1: pass=6;break;
		    case 0x229: pass=7;break;
		    case 0x271: pass=8;break;
		}
//		for (j=0; j<6; j++)
//		{
		    fprintf(stdout, "^ [%d]%X ^ ", pass, buff[i-24]-1);
		    for (k=0; k<PWLENGTH; k++)
			fprintf(stdout, "%c", buff[i+k]^key[buff[i-24]-1][k]);
//		    fprintf(stdout, "\n");
//		}
		i+=PWLENGTH+4;
		fprintf(stdout, " (");
		for (k=0; k<=buff[i]; k++)
    		    fprintf(stdout, "%c", buff[i+k]);
		fprintf(stdout, ")\n");
		pass++;
    	    }
	}
	free(buff);
    }
    else
    {
	fprintf(stderr, "Error: can't read file\n");
        return -2;
    }

    /*lseek(fd, START_OFFSET1, SEEK_SET);
    if (read(fd, &pass, PWLENGTH) != 0)
    {
	fprintf(stdout, "0#: ");
	for (i=0; i<PWLENGTH; i++)
	    fprintf(stdout, "%c", pass[i]^key1[i]);
	fprintf(stdout, "\n");
    }

    lseek(fd, START_OFFSET2, SEEK_SET);
    if (read(fd, &pass, PWLENGTH) != 0)
    {
	fprintf(stdout, "1#: ");
	for (i=0; i<PWLENGTH; i++)
	    fprintf(stdout, "%c", pass[i]^key2[i]);
	fprintf(stdout, "\n");
    }*/

/*    while (read(fd, &pass, 1) != 0)
    {
//	if (pass[0]==21)
//	    a++;
	if (pass[0]==10)
	for (j=0;j<6;j++)
        {
    	lseek(fd, START_OFFSET5, SEEK_SET);
            if (read(fd, &pass, PWLENGTH) != 0)
            {
        	fprintf(stdout, "%d#: ",j);
        	for (i=0; i<PWLENGTH; i++)
        	    fprintf(stdout, "%c", pass[i] ^ key[j][i]);
        	fprintf(stdout, "\n");
            }
        }
    }
*/
    /*lseek(fd, START_OFFSET4, SEEK_SET);
    if (read(fd, &pass, PWLENGTH) != 0)
    {
	fprintf(stdout, "1#: ");
	for (i=0; i<PWLENGTH; i++)
	    fprintf(stdout, "%c", pass[i]^key5[i]);
	fprintf(stdout, "\n");
    }*/

    close(fd);
    return 0;
}
