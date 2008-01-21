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

#include <list>
#include <iostream>
#include <fcntl.h>

using namespace std;

const int KeySize = 16;
const char key[][KeySize] = {
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

class cUserRecord
{
  private:
    bool bDisabled;
    int iRecNumber;
    char szCryptedPass[KeySize];
    char* szUserName;
    char* szComment;
    int iPrefKey;
  public:
    cUserRecord()
    {
	cout << "const" << endl;
	szUserName=NULL;
	szComment=NULL;
	bDisabled=false;
	iRecNumber=-1;
	bzero(szCryptedPass,KeySize);
    }
    cUserRecord(const cUserRecord &t)
    {
	cout << "kopiujacy"  << endl;
	bDisabled=t.bDisabled;
	iRecNumber=t.iRecNumber;
	memcpy(szCryptedPass, t.szCryptedPass, KeySize);

	if (t.szUserName==NULL)
	    szUserName=NULL;
	else
	{
    	    szUserName=new char[strlen(t.szUserName)+1];
	    strcpy(szUserName,t.szUserName);
	}

	if (t.szComment==NULL)
	    szComment=NULL;
	else
	{
	    szComment=new char[strlen(t.szComment)+1];
	    strcpy(szComment,t.szComment);
	}
    }
    ~cUserRecord()
    {
	cout << "destructing" << endl;
	if (szUserName) delete []szUserName;
	if (szComment) delete []szComment;
    }
    void SetCryptedPass(char* pPass)
    {
	memcpy(szCryptedPass,pPass,KeySize);
    }
    void SetDisableFlag(bool bFlag)
    {
	bDisabled=bFlag;
    }
    void SetRecNumber(int iRecNo)
    {
	iRecNumber=iRecNo;
    }
    void SetUserName(char* NewUserName)
    {
	if (szUserName) delete []szUserName;
	szUserName=new char[strlen(NewUserName)+1];
	strcpy(szUserName,NewUserName);
    }
    void SetComment(char* NewComment)
    {
	if (szComment) delete []szComment;
	szComment=new char[strlen(NewComment)+1];
	strcpy(szComment,NewComment);
    }
    void compute(int keys)
    {
	/*
	    i don't know the key selection algorithn - so above are the keys that i collected so far
	    and this function is simply trying to predict the correct key based on number of printable
	    characters in output
	*/
	int maxpts, pts;
	maxpts=0;
	char c;
	for (int i=0; i<keys; i++)
	{
	    pts=0;
	    for (int j=0; j<KeySize; j++)
	    {
		c=szCryptedPass[j]^key[i][j];
		if (c==0x00 || (c>=32 && c<=126))
		    pts++;
	    }
	    if (pts>maxpts)
	    {
		iPrefKey=i;
		maxpts=pts;
	    }
	}
    }
    void show(int in)
    {
	cout << iRecNumber << " " << flush;
	if (szUserName)
	    cout << szUserName << "\t" << flush;
	if (bDisabled)
	    cout << "[DISABLED] " << flush;
	if (szComment)
	    cout << szComment << "\t" << flush;
//	for (int i=0; i<KeySize; i++)
//	    printf("%.2X",(unsigned char)szCryptedPass[i]);
	cout << " pass: " << flush;
	for (int i=0; i<KeySize; i++)
	    fprintf(stdout, "%c", szCryptedPass[i] ^ key[iPrefKey][i]);
	cout << endl;
    }
};

int main(int argc, char **argv)
{
    char *buff;
    int fd;
    int a;
    list<cUserRecord> tabUser;

    int i, j, k, pass;
    int bytes, iKeys;

    if (argc <= 1)
    {
	fprintf(stderr, "usage: %s input_file\n", argv[0]);
	fprintf(stderr, "input_file: RouterOS userdata file from /nova/store/user.dat\n");
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
    buff = new char[bytes];
    if (buff==NULL)
    {
	fprintf(stderr, "Error: cannot allocate buffer\n");
	return -1;
    }

    cUserRecord *ptr=NULL;
    lseek(fd, 0, SEEK_SET);
    if (read(fd, buff, bytes) == bytes)
    {
	pass=1;
	for (i=0; i<bytes; i++)
	{
	    //searching for StartOfRecord
	    if ((buff[i]==0x4d) && (buff[i+1]==0x32) && (buff[i+2]==0x0a))
	    {
		ptr=new cUserRecord;
		printf("Found user record at offset 0x%.5x\n",i);

		//5 bytes ahead is enable/disable flag
		i+=5;
		ptr->SetDisableFlag(bool(buff[i]));
		cout << (int)buff[i] << endl;

		i+=15;
		ptr->SetRecNumber(buff[i]);

		i+=18;
		//is there a comment?
		if (buff[i]!=0x00)
		{
		    char *tmp=new char[buff[i]+1];
		    memcpy(tmp,(void*)&buff[i+1],buff[i]);
		    //terminating the string
		    tmp[buff[i]]=0;
		    cout << tmp << endl;
		    ptr->SetComment(tmp);
		    delete tmp;
		    i+=buff[i];
		}
		//searching for StartOfPassword
		while (!((buff[i]==0x11) && (buff[i+3]==0x21) && (buff[i+4]==0x10))) i++;
		//(buff[i+1]==0x00) && (buff[i+2]==0x00) && 
		i+=5;

		//copying pass
		ptr->SetCryptedPass(&buff[i]);

		i+=buff[KeySize];

		//searching for StartOfUsername
		while (!((buff[i]==0x01) && (buff[i+3]==0x21))) i++;
		//(buff[i+1]==0x00) && (buff[i+2]==0x00) && 
		i+=4;
		if (buff[i]!=0x00)
		{
		    char *tmp=new char[buff[i]+1];
		    memcpy(tmp,(void*)&buff[i+1],buff[i]);
		    //terminating the string
		    tmp[buff[i]]=0;
		    ptr->SetUserName(tmp);
		    delete tmp;
		    i+=buff[i];
		}

		tabUser.push_back(*ptr);
    	    }
	    //clean if we need to
	    if (ptr)
	    {
		delete ptr;
		ptr=NULL;
	    }
	}
	delete buff;
    }
    else
    {
	fprintf(stderr, "Error: can't read file\n");
        return -2;
    }
    close(fd);
    
    iKeys=sizeof(key)/KeySize;

    //show the results
    list<cUserRecord>::iterator iter1;
    list<cUserRecord>::iterator iter2;
    iter1 = tabUser.begin();
    iter2 = tabUser.end();

    for (int a=1; iter1!=iter2; ++iter1,a++)
    {
	iter1->compute(iKeys);
	iter1->show(a);
    }

    return 0;
}
