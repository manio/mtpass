/*
    mtpass.cpp
    This tool decodes user passwords from MikroTik RouterOS user.dat file

    license: GPL v2.0
    (c) by Mariusz 'manio' Bialonczyk; manio@skyboo.net
    v0.1 [2008-01-03]: initial release
    v0.2 [2008-01-23]: rewritten in C++
                       ability to show other users besides admin
                       added decrypt keys and key prediction
    v0.3 [2008-12-08]: figured out xor key generation algorithm, so no more collecting keys
                       and all users passwords should be decrypted ok :)
*/

#include <iostream>
#include <list>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <openssl/md5.h>

using namespace std;

const char* szVerInfo = "mtpass v0.3 - MikroTik RouterOS password recovery tool, (c) 2008 by manio";
const char* szFormatHdr = "%-4s | %-15s | %-18s | %-14s | %-35s";
const char* szFormatData = "%-4d | %-15s | %-18s | %-14s | %-35s";
const int iFormatLineLength = 92;
int iDebug = 0;
int iBackup = 0;

void debug(const char *fmt, ...)
{
    if (iDebug == 0)
	return;

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
}

class cUserRecord
{
  private:
    bool bDisabled;
    int iRecNumber;
    char szPass[MD5_DIGEST_LENGTH+1];
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
	for (int i=0;i<sizeof(szPass);i++)
	  szPass[i]=0;
    }
    cUserRecord(const cUserRecord &t)
    {
	bDisabled=t.bDisabled;
	iRecNumber=t.iRecNumber;
	memcpy(szPass, t.szPass, sizeof(szPass));

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
    void SetPass(char* pPass)
    {
	memcpy(szPass, pPass, sizeof(szPass));
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
    void DecryptAndShowRecord()
    {
	static const char magic_string [] = "283i4jfkai3389";	// :)
	unsigned char key[MD5_DIGEST_LENGTH];
	char user_magic[200];
	strcpy(user_magic, szUserName);
	strcat(user_magic, magic_string);
	MD5((unsigned char*)user_magic, strlen(user_magic), key);

	//checking if we have an empty pass:
	int iSum = 0;
	for (int i=0; i<MD5_DIGEST_LENGTH; i++)
	    iSum += szPass[i];

	if (iSum == 0)
	    sprintf(szPass, "<BLANK PASSWORD>");
	else for (int i=0; i<MD5_DIGEST_LENGTH; i++)
	    szPass[i] = szPass[i] ^ key[i];	//decoding (xor)

	fprintf(stdout, szFormatData, iRecNumber, szUserName, szPass, bDisabled ? "USER DISABLED" : "", szComment==NULL ? "" : szComment);
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
	fprintf(stdout, "usage: %s [-d] input_file\n", argv[0]);
	fprintf(stdout, "input_file: RouterOS userdata file from /nova/store/user.dat\n");
	return -1;
    }

    if (strcmp(argv[1],"-b")==0)
	iBackup = 1;

    if (strcmp(argv[1+iBackup],"-d")==0)
	iDebug = 1;

    fd = open(argv[1+iDebug+iBackup], O_RDONLY);
    if (fd < 0)
    {
	fprintf(stderr, "Error: could not open file: %s\n", argv[1+iDebug+iBackup]);
	return -2;
    }
    bytes = lseek(fd, 0, SEEK_END);
    fprintf(stdout, "Reading file %s, %d bytes long\n", argv[1+iDebug+iBackup], bytes);
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
	printf("ostatni bajt = %X\n",buff[bytes-1]);
	i=0;
	if (iBackup==1)
	{
	    for (i=0; i<bytes; i++)
	    {
		if (buff[i] == 'u')
		{
		    if (buff[i+1]=='s' && buff[i+2]=='e' && buff[i+3]=='r' && buff[i+4]=='$')
		    {
			i+=48;
			fprintf(stdout, "Found user.dat at offset 0x%.5x\n",i);
			break;
		    }
		}
		i++;
	    }
	    if (i == bytes+1)
	    {
		fprintf(stderr, "Error: not found user.dat in backup\n");
		return -5;
	    }
	}

	for (; i<bytes; i++)
	{
	    //searching for StartOfRecord
	    if (i+2>=bytes) break;
	    if ((buff[i]==0x4d) && (buff[i+1]==0x32) && (buff[i+2]==0x0a))
	    {
		ptr=new cUserRecord;
		debug("Found user record at offset 0x%.5x\n",i);

		//5 bytes ahead is enable/disable flag
		i+=5;
		if (i>=bytes) break;
		ptr->SetDisableFlag(bool(buff[i]));
		//cout << (int)buff[i] << endl;
		//searching for StartOfRecNumber
		while (!( (buff[i]==0x01) && ((buff[i+1]==0x00)||(buff[i+1]==0x20)) && (buff[i+3]==0x09)))
		{
			i++;
			if (i>=bytes) break;
		}
		i+=4;
		if (i>=bytes) break;
		debug("SORn: 0x%X\n", i);

		//cout << (int)buff[i] << endl;
		ptr->SetRecNumber(buff[i]);

		//is there a comment?
		i+=18;
		if (i>=bytes) break;
		if (buff[i-5]==0x03 && (buff[i]!=0x00)) //there is comment
		{
		    if ((i+1)+buff[i]>=bytes) break;
		    char *tmp=new char[buff[i]+1];
		    memcpy(tmp,(void*)&buff[i+1],buff[i]);
		    //terminating the string
		    tmp[buff[i]]=0;
		    ptr->SetComment(tmp);
		    debug("SOC: 0x%X %s\n", i+1,tmp);
		    //cout <<tmp<<endl;
		    delete tmp;
		    i+=buff[i];
		}

		//searching for StartOfPassword
		if (i+4>=bytes) break;
		while (!((buff[i]==0x11) && (buff[i+3]==0x21) && ((buff[i+4]==0x10)||(buff[i+4]==0x00)) ))
		{
			i++;
			if (i>=bytes) break;
		}

		i+=5;
		if (i>=bytes) break;
		debug("SOP: 0x%X\n", i);

		if (buff[i-1]!=0x00)
		{
		    //copying pass
		    ptr->SetPass(&buff[i]);

		    i+=MD5_DIGEST_LENGTH;
		    if (i>=bytes) break;
		}

		//searching for StartOfUsername
		if (i+3>=bytes) break;
		while (!((buff[i]==0x01) && (buff[i+3]==0x21)))
		{
			i++;
			if (i>=bytes) break;
		}
		i+=4;
		if (i>=bytes) break;
		if (buff[i]!=0x00)
		{
		    if ((i+1)+buff[i]>=bytes) break;
		    char *tmp=new char[buff[i]+1];
		    memcpy(tmp,(void*)&buff[i+1],buff[i]);
		    //terminating the string
		    tmp[buff[i]]=0;
		    //cout <<tmp<<endl;
		    ptr->SetUserName(tmp);
			debug("SOU: 0x%X %s\n", i, tmp);
		    delete tmp;
		    i+=buff[i];
		    if (i>=bytes) break;
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

    //show the results
    list<cUserRecord>::iterator iter1;
    list<cUserRecord>::iterator iter2;
    iter1 = tabUser.begin();
    iter2 = tabUser.end();

    //print header
    fprintf(stdout, "\n");
    fprintf(stdout, szFormatHdr, "Rec#", "Username", "Password", "Disable flag", "User comment");
    fprintf(stdout, "\n");
    for (int i=0; i<iFormatLineLength; i++) fprintf(stdout, "-");
    fprintf(stdout, "\n");

    //print data
    for (; iter1!=iter2; ++iter1)
	iter1->DecryptAndShowRecord();

    fprintf(stdout, "\n");
    return 0;
}
