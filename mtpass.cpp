/*
    mtpass.cpp
    This tool decodes user passwords from MikroTik RouterOS user.dat file

    license: GPL v2.0
    (c) by Mariusz "Manio" Bialonczyk; manio@skyboo.net
    v0.1 [2008-01-03]: initial release
    v0.2 [2008-01-23]: rewritten in C++
                       ability to show other users besides admin
                       added decrypt keys and key prediction
*/

#include <iostream>
#include <list>
#include <fcntl.h>

using namespace std;

const char* szVerInfo = "mtpass v0.2 - MikroTik RouterOS password recovery tool, (c) 2008 by Manio";
const char* szFormatHdr = "%-6s | %-15s | %-18s | %-14s | %-35s";
const char* szFormatData = "%-3d / %-2d    | %-15s | %-18s | %-14s | %-35s";
const int iFormatLineLength = 92;
const int KeyLength = 16;
const char key[][KeyLength] = {
    {0x02, 0x6d, 0xb5, 0x70, 0x66, 0xa6, 0x3d, 0x2a, 0xb7, 0xcd, 0xec, 0x68, 0xe2, 0x6e, 0x44, 0x0e},
    {0x48, 0xbf, 0xde, 0x06, 0x49, 0x5a, 0x0e, 0x2d, 0x09, 0xd5, 0xfb, 0x27, 0xb1, 0x44, 0xec, 0x93},
    {0xe8, 0x61, 0xb0, 0xa8, 0x2f, 0xbb, 0x68, 0x29, 0xe2, 0x53, 0xce, 0xeb, 0x1e, 0x3e, 0x61, 0x5a},
    {0x98, 0x40, 0x20, 0xa0, 0x8c, 0xb9, 0xba, 0x55, 0xb9, 0xb6, 0xf2, 0x48, 0x0c, 0xd5, 0x2b, 0x80},
    {0xe3, 0x33, 0x29, 0x1d, 0x2e, 0xc8, 0x9a, 0xfc, 0xf2, 0xd2, 0xc5, 0x8c, 0xe5, 0xfd, 0xff, 0x36},
    {0x06, 0xa4, 0x6c, 0x65, 0x97, 0x5b, 0x79, 0x7c, 0x74, 0xf6, 0xbd, 0x94, 0x43, 0x00, 0x23, 0x41},
    {0x79, 0x37, 0x7c, 0x26, 0xdc, 0x38, 0xbf, 0xda, 0xf2, 0x23, 0xd4, 0x57, 0x83, 0xa9, 0x84, 0xdb},
    {0x3f, 0xea, 0xb5, 0x12, 0x11, 0xab, 0x30, 0x17, 0xbe, 0x71, 0x86, 0xae, 0x65, 0xde, 0x96, 0x60},
    {0xa2, 0xdb, 0xb1, 0x5d, 0x27, 0x72, 0x44, 0x6f, 0xa9, 0x1c, 0xa2, 0x38, 0xb0, 0xfc, 0xc2, 0x29},
    {0x26, 0xa0, 0x52, 0x14, 0x80, 0x0e, 0xa2, 0x6b, 0xbd, 0x5f, 0x7c, 0x53, 0x6f, 0xde, 0x08, 0x71},

/* mustafa? */
{0x96, 0x04, 0x20, 0xda, 0x4e, 0x57, 0xe2, 0x65, 0x6b, 0x49, 0x83, 0x2c, 0x27, 0xaf, 0xf2, 0xa2},
{0x00, 0x98, 0xa9, 0x10, 0xdb, 0x20, 0x57, 0x61, 0x4e, 0x12, 0xff, 0xea, 0xfe, 0x96, 0xd1, 0xb0},
{0xc8, 0x61, 0x54, 0xb1, 0x3b, 0x25, 0xd3, 0x4b, 0x6b, 0x49, 0x83, 0x2c, 0x27, 0xaf, 0xf2, 0xa2},
{0x5f, 0x1f, 0xd7, 0x65, 0x27, 0xac, 0x71, 0xbc, 0xb0, 0xcc, 0xe0, 0xb5, 0x51, 0x07, 0xee, 0x8b},

/* vlad */
{0xfa, 0xb8, 0xa8, 0x11, 0x49, 0xe4, 0xa6, 0x3c, 0x09, 0xe7, 0x57, 0x9c, 0x0b, 0x28, 0x52, 0x3e},
{0x74, 0xab, 0x67, 0xb3, 0xc6, 0x1e, 0x56, 0xc2, 0x99, 0x22, 0xf8, 0x33, 0xe1, 0x2e, 0x74, 0xcd},
{0xd8, 0x6d, 0x8b, 0xa1, 0xaf, 0x52, 0x12, 0xed, 0xe1, 0xb8, 0xe3, 0x47, 0xfa, 0xd2, 0x18, 0xca},

/* wsgtrsys1 */
/*{0x43, 0x00, 0xd8, 0xea, 0xcf, 0x07, 0xa2, 0xc1, 0x1b, 0x0d, 0x91, 0x20, 0x37, 0x2c, 0x22, 0x54},
{0xdd, 0xfa, 0x62, 0xb8, 0x84, 0x5c, 0xf7, 0xab, 0x18, 0x9b, 0x72, 0xf3, 0x63, 0x05, 0x08, 0x2c}*/

/* petr */
{0xc8, 0x96, 0x9b, 0x30, 0x3a, 0xf4, 0xcc, 0xc6, 0xe4, 0x9f, 0x1c, 0x9a, 0xa2, 0x7e, 0xeb, 0xd7},
{0x16, 0xd6, 0xb3, 0x62, 0x28, 0x5a, 0x0e, 0x2d, 0x09, 0xd5, 0xfb, 0x27, 0xb1, 0x44, 0xec, 0x93},
{0x75, 0x18, 0xa4, 0x14, 0xcf, 0x25, 0x84, 0x2f, 0xa6, 0xb0, 0x33, 0x54, 0x7c, 0xe0, 0x12, 0x50},
{0x36, 0x4f, 0x2b, 0x2e, 0x87, 0x50, 0x88, 0x7a, 0x61, 0x90, 0xdd, 0x0b, 0x57, 0x00, 0x70, 0x0d}
};

class cUserRecord
{
  private:
    bool bDisabled;
    int iRecNumber;
    char szCryptedPass[KeyLength];
    char* szUserName;
    char* szComment;
    int iPrefKey;
  public:
    cUserRecord()
    {
	szUserName=NULL;
	szComment=NULL;
	bDisabled=false;
	iRecNumber=-1;
	bzero(szCryptedPass, KeyLength);
    }
    cUserRecord(const cUserRecord &t)
    {
	bDisabled=t.bDisabled;
	iRecNumber=t.iRecNumber;
	memcpy(szCryptedPass, t.szCryptedPass, KeyLength);

	if (t.szUserName==NULL)
	    szUserName=NULL;
	else
	{
    	    szUserName=new char[strlen(t.szUserName)+1];
	    strcpy(szUserName, t.szUserName);
	}

	if (t.szComment==NULL)
	    szComment=NULL;
	else
	{
	    szComment=new char[strlen(t.szComment)+1];
	    strcpy(szComment, t.szComment);
	}
    }
    ~cUserRecord()
    {
	if (szUserName) delete []szUserName;
	if (szComment) delete []szComment;
    }
    void SetCryptedPass(char* pPass)
    {
	memcpy(szCryptedPass, pPass, KeyLength);
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
	strcpy(szUserName, NewUserName);
    }
    void SetComment(char* NewComment)
    {
	if (szComment) delete []szComment;
	szComment=new char[strlen(NewComment)+1];
	strcpy(szComment, NewComment);
    }
    void compute(int keys)
    {
	/*
	    i don't know the key selection algorithn - so above are the keys that i collected so far
	    and this function is simply trying to predict the correct key based on number of printable
	    characters in output
	*/
	int maxpts, pts, k;
	maxpts=0;
	char c;
	for (int i=0; i<keys; i++)
	{
	    pts=0;
	    k=0;
	    for (int j=0; j<KeyLength; j++)
	    {
		c=szCryptedPass[j]^key[i][j];
		if (c==0x00 || (c>=32 && c<=126))
		    pts++;
		//checking if password if set
		if (szCryptedPass[j]==0x00) k++;
	    }
	    if (k==KeyLength)
	    {
		iPrefKey=-1;
		break;
	    }
	    if (pts>maxpts)
	    {
		iPrefKey=i;
		maxpts=pts;
	    }
	}
    }
    void show(int iNo)
    {
	char szPass[17]={0};
	if (iPrefKey>=0)	//checking for empty pass
	{
	    for (int i=0; i<KeyLength; i++)
		sprintf(szPass+i, "%c", szCryptedPass[i] ^ key[iPrefKey][i]);
	}
	else
	    sprintf(szPass, "<EMPTY PASSWORD>");
	//fprintf(stdout, szFormatData, iRecNumber, szUserName, szPass, bDisabled?"USER DISABLED":"", szComment==NULL?"":szComment);
	fprintf(stdout, szFormatData, iNo, iPrefKey, szUserName, szPass, bDisabled?"USER DISABLED":"", szComment==NULL?"":szComment);
	fprintf(stdout, "\n");
    }
};

int main(int argc, char **argv)
{
    char *buff;
    int fd;
    list<cUserRecord> tabUser;

    int i, bytes, iKeys;

    fprintf(stdout, "%s\n\n", szVerInfo);
    if (argc <= 1)
    {
	fprintf(stdout, "usage: %s input_file\n", argv[0]);
	fprintf(stdout, "input_file: RouterOS userdata file from /nova/store/user.dat\n");
	return -1;
    }

    fd = open(argv[1], O_RDONLY);
    if (fd < 0)
    {
	fprintf(stderr, "Error: could not open file: %s\n", argv[1]);
	return -2;
    }
    bytes = lseek(fd, 0, SEEK_END);
    fprintf(stdout, "Reading file %s, %d bytes long\n", argv[1], bytes);
    buff = new char[bytes];
    if (buff==NULL)
    {
	fprintf(stderr, "Error: cannot allocate buffer\n");
	return -3;
    }

    cUserRecord *ptr=NULL;
    lseek(fd, 0, SEEK_SET);
    if (read(fd, buff, bytes) == bytes)
    {
	for (i=0; i<bytes; i++)
	{
	    //searching for StartOfRecord
	    if ((buff[i]==0x4d) && (buff[i+1]==0x32) && (buff[i+2]==0x0a))
	    {
		ptr=new cUserRecord;
		//fprintf(stdout, "Found user record at offset 0x%.5x\n",i);

		//5 bytes ahead is enable/disable flag
		i+=5;
		ptr->SetDisableFlag(bool(buff[i]));
		//cout << (int)buff[i] << endl;
		//searching for StartOfRecNumber
		while (!((buff[i]==0x01) && (buff[i+1]==0x00) && (buff[i+3]==0x09))) i++;
		i+=4;

		//cout << (int)buff[i] << endl;
		ptr->SetRecNumber(buff[i]);

		i+=18;
		//is there a comment?
		if (buff[i]!=0x00)
		{
		    char *tmp=new char[buff[i]+1];
		    memcpy(tmp,(void*)&buff[i+1],buff[i]);
		    //terminating the string
		    tmp[buff[i]]=0;
		    ptr->SetComment(tmp);
		//cout <<tmp<<endl;
		    delete tmp;
		    i+=buff[i];
		}

		//searching for StartOfPassword
		while (!((buff[i]==0x11) && (buff[i+3]==0x21) && ((buff[i+4]==0x10)||(buff[i+4]==0x00)) )) i++;
		i+=5;

		if (buff[i-1]!=0x00)
		{
		    //copying pass
		    ptr->SetCryptedPass(&buff[i]);

		    i+=buff[KeyLength];
		}

		//searching for StartOfUsername
		while (!((buff[i]==0x01) && (buff[i+3]==0x21))) i++;
		i+=4;
		if (buff[i]!=0x00)
		{
		    char *tmp=new char[buff[i]+1];
		    memcpy(tmp,(void*)&buff[i+1],buff[i]);
		    //terminating the string
		    tmp[buff[i]]=0;
		//cout <<tmp<<endl;
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
        return -4;
    }
    close(fd);

    iKeys=sizeof(key)/KeyLength;

    //show the results
    list<cUserRecord>::iterator iter1;
    list<cUserRecord>::iterator iter2;
    iter1 = tabUser.begin();
    iter2 = tabUser.end();

    //print header
    fprintf(stdout, "\n");
    fprintf(stdout, szFormatHdr, "Rec# / Key#", "Username", "Password", "Disable flag", "User comment");
    fprintf(stdout, "\n");
    for (int i=0; i<iFormatLineLength; i++) fprintf(stdout, "-");
    fprintf(stdout, "\n");

    //print data
    for (int i=1; iter1!=iter2; ++iter1, ++i)
    {
	iter1->compute(iKeys);
	iter1->show(i);
    }

    fprintf(stdout, "\n");
    return 0;
}
