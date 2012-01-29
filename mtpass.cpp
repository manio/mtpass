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
    v0.4 [2009-03-17]: a lot of fixes
                       able to decrypt passwords from mikrotik backup files and full flash-dump files
    v0.5 [2009-03-26]: fixed decrypting passwords longer then 16 chars
    v0.6 [2010-10-12]: fixed compilation problems with newer g++
    v0.7 [2011-08-15]: kocour_easy: fix for decoding files from RouterOS 5.5
    v0.8 [2012-01-29]: another fixes for decoding new RouterOS files (thanks to NetworkPro)
*/

#include <iostream>
#include <cstdio>
#include <list>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <openssl/md5.h>

using namespace std;

const char* szVerInfo = "mtpass v0.8 - MikroTik RouterOS password recovery tool, (c) 2008-2012 by manio";
const char* szURLInfo = "http://manio.skyboo.net/mikrotik/";
const char* szFormatHdr = "%-4s | %-15s | %-18s | %-14s | %-35s";
const char* szFormatData = "%-4d | %-15s | %-18s | %-14s | %-35s";
const int iFormatLineLength = 92;
int iDebug = 0;
int gRecNumber = 1;

void debug(const char *fmt, ...)
{
    if (iDebug == 0)
	return;

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fflush(stdout);
}

void ASCIIonly(char *text)
{
    for (int i=0; i<strlen(text); i++)
    {
	if ((unsigned char)text[i]<32 || (unsigned char)text[i]>126)	//not printable ASCII
	{
	    //terminating the string
	    text[i] = 0;
	    break;
	}
    }
}

class cUserRecord
{
  private:
    bool bDisabled;
    int iRecNumber;
    int iPassLen;
    char* szPass;
    char* szUserName;
    char* szComment;
    int iPrefKey;
  public:
    cUserRecord()
    {
	iPassLen=0;
	szPass=NULL;
	szUserName=NULL;
	szComment=NULL;
	bDisabled=false;
	iRecNumber=-1;
    }
    cUserRecord(const cUserRecord &t)
    {
	bDisabled=t.bDisabled;
	iRecNumber=t.iRecNumber;

	if (t.szPass==NULL)
	    szPass=NULL;
	else
	{
	    szPass=new char[t.iPassLen];
	    iPassLen = t.iPassLen;
	    memcpy(szPass, t.szPass, t.iPassLen);
	}

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
	if (szPass) delete []szPass;
	if (szUserName) delete []szUserName;
	if (szComment) delete []szComment;
    }
    void SetPass(unsigned char* pPass)
    {
	iPassLen=pPass[0]+1;
	szPass=new char[iPassLen];
	memcpy(szPass, pPass+1, iPassLen-1);
	szPass[iPassLen-1]=0;	//terminating
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
	ASCIIonly(szUserName);
	if (strcmp(szUserName,"")==0)
	{
	    delete szUserName;
	    szUserName=NULL;
	}
    }
    void SetComment(char* NewComment)
    {
	if (szComment) delete []szComment;
	szComment=new char[strlen(NewComment)+1];
	strcpy(szComment, NewComment);
	ASCIIonly(szComment);
    }
    void DecryptAndShowRecord()
    {
	if (szUserName==NULL)
	    return;
	static const char magic_string [] = "283i4jfkai3389";	// :)
	unsigned char key[MD5_DIGEST_LENGTH];
	char user_magic[200];
	strncpy(user_magic, szUserName, 199-strlen(magic_string));
	strcat(user_magic, magic_string);
	MD5((unsigned char*)user_magic, strlen(user_magic), key);

	if (szPass != NULL)
	{
	    for (int i=0; i<(iPassLen-1); i++)
		szPass[i] = szPass[i] ^ key[i%MD5_DIGEST_LENGTH];	//decoding (xor)
	    ASCIIonly(szPass);
	}

	fprintf(stdout, szFormatData, gRecNumber++, szUserName, szPass==NULL ? "<BLANK PASSWORD>" : szPass, bDisabled ? "USER DISABLED" : "", szComment==NULL ? "" : szComment);
	fprintf(stdout, "\n");
    }
};

int main(int argc, char **argv)
{
    unsigned char *buff;
    int fd;
    list<cUserRecord> tabUser;

    int i, bytes, iKeys;

    fprintf(stdout, "%s\n%s\n\n", szVerInfo, szURLInfo);
    if (argc <= 1)
    {
	fprintf(stdout, "usage: %s [-d] input_file\n", argv[0]);
	fprintf(stdout, "input_file: RouterOS userdata file from /nova/store/user.dat\n");
	return -1;
    }

    if (strcmp(argv[1],"-d")==0)
	iDebug = 1;

    fd = open(argv[1+iDebug], O_RDONLY);
    if (fd < 0)
    {
	fprintf(stderr, "Error: could not open file: %s\n", argv[1+iDebug]);
	return -2;
    }
    bytes = lseek(fd, 0, SEEK_END);
    fprintf(stdout, "Reading file %s, %d bytes long\n", argv[1+iDebug], bytes);
    buff = new unsigned char[bytes];
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
	    if (i+2>=bytes) break;
	    if ((buff[i]==0x4d) && (buff[i+1]==0x32) && (buff[i+2]==0x0a || buff[i+2]==0x10))
	    {
		debug("Probably user record at offset 0x%.5x\n",i);
		ptr=new cUserRecord;

		//some bytes ahead is enable/disable flag
		i += (buff[i+2] - 5);
		if (i>=bytes) break;
		if (buff[i-1] == 0xfe)
			ptr->SetDisableFlag(bool(buff[i]));
		//cout << (int)buff[i] << endl;
		//searching for StartOfRecNumber
		if (i+3>=bytes) break;
		while (!( (buff[i]==0x01) && ((buff[i+1]==0x00)||(buff[i+1]==0x20)) && (buff[i+3]==0x09||buff[i+3]==0x20)))
		{
			i++;
			if (i+3>=bytes) break;
		}
		i+=4;
		if (i>=bytes) break;
		debug("SORn: 0x%X\n", i);

		//cout << (int)buff[i] << endl;
		ptr->SetRecNumber(buff[i]);

		//is there a comment?
		i+=18;
		if ((i+4)>=bytes) break;
		if ((!((buff[i+1]==0x11) && (buff[i+2]==0x20) && (buff[i+3]==0x20) && (buff[i+4]==0x21))) && (buff[i-5]==0x03 && (buff[i]!=0x00))) //there is comment
		{
		    if ((i+1)+buff[i]>=bytes) break;
		    debug("SOC: 0x%X\n", i+1);
		    char *tmp=new char[buff[i]+1];
		    memcpy(tmp,(void*)&buff[i+1],buff[i]);
		    //terminating the string
		    tmp[buff[i]]=0;
		    ptr->SetComment(tmp);
		    //cout <<tmp<<endl;
		    delete tmp;
		    i+=buff[i];
		}
		else	//there is no comment
		    i-=18;

		//searching for StartOfPassword
		if (i+4>=bytes) break;
		while (!((buff[i]==0x11) && (buff[i+3]==0x21) && ((buff[i+4] % MD5_DIGEST_LENGTH)==0)))
		{
			i++;
			if (i+4>=bytes) break;
		}

		i+=5;
		if ((i+3)>=bytes) break;
		debug("SOP: 0x%X\n", i);

		if ((buff[i-1]!=0x00) && !((buff[i]==0x01) && ((buff[i+1]==0x20 && buff[i+2]==0x20)||(buff[i+1]==0x00 && buff[i+2]==0x00)) && (buff[i+3]==0x21)))
		{
		    //copying pass
		    ptr->SetPass(&buff[i-1]);
		    i+=buff[i-1];
		}

		//searching for StartOfUsername
		if (i+3>=bytes) break;
		while (!((buff[i]==0x01) && (buff[i+3]==0x21)))
		{
			i++;
			if (i+3>=bytes) break;
		}

		i+=4;
		if (i>=bytes) break;
		if (buff[i]!=0x00)
		{
		    if (i+buff[i]>=bytes) break;
		    debug("SOU: 0x%X\n", i);
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

    if (gRecNumber == 1)
	fprintf(stdout, "Sorry - no passwords were found in the file\n");
    fprintf(stdout, "\n");
    return 0;
}
