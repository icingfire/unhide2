/*
Copyright © 2010-2024 Yago Jesus & Patrick Gouin
Copyright © 2025 icingfire

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Complie:
gcc -Wall -Wextra -O2 --static -pthread unhide.c -o unhide
*/

// Needed for unistd.h to declare getpgid() and others
#define _XOPEN_SOURCE 500

// Needed for sched.h to declare sched_getaffinity()
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wait.h>
#include <sys/resource.h>
#include <errno.h>
#include <dirent.h>
#include <sched.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <ctype.h>
#include <time.h>
#include <getopt.h>
#include <stdarg.h>
#ifdef __linux__
   #include <linux/limits.h>
#else
   #include <limits.h>
#endif
#include <sys/socket.h>
#include <netinet/in.h>


// we are looking only for real process not thread and only one by one
#define COMMAND "ps --no-header -p %i o pid"
// we are looking for session ID one by one
#define SESSION "ps --no-header -s %i o sess"
// We are looking for group ID one by one
// but ps can't select by pgid
#define PGID "ps --no-header -eL o pgid"
// We are looking for all processes even threads
#define THREADS "ps --no-header -eL o lwp"
// for sysinfo scanning, fall back to old command, as --no-header seems to create
// an extra process/thread
// #define SYS_COMMAND "ps -eL o lwp"
#define SYS_COMMAND "ps --no-header -eL o lwp"
// an extra process/thread
#define REVERSE "ps --no-header -eL o lwp,cmd"

// Avoid buffering stdout when piped.
#define NO_BUF_PIPE "stdbuf -i0 -o0 -e0 "

// Masks for the checks to do in checkps
// =====================================
#define PS_PROC         0x00000001
#define PS_THREAD       0x00000002
#define PS_MORE         0x00000004

// boolean values
// ==============
#define FALSE        0
#define TRUE         1

enum Proto
{
       TCP = 0,
       UDP = 1
};


// header
const char header[] =
   "Unhide 20250902\n"
   "Orig author: Yago Jesus & Patrick Gouin, Modified by icingfire\n"
   "License GPLv3+ : GNU GPL version 3 or later\n";

const char version[] = "unhide v2.0";

// defauly sysctl kernel.pid_max
# define MAX_PID 8388608
int maxpid = MAX_PID;

// Threads id for sync
int tid ;

// our own PID
pid_t mypid;

// options
int verbose = 0 ;
int bruteflag = FALSE ;
int humanfriendly = FALSE ;

// Found hidden proccess flag
int found_HP = 0;

// For logging to file
int logtofile;
FILE *unlog;

// Temporary string for output
char used_options[1000];

// Temporary string for output
char scratch[1000];


extern int checkps(int tmppid, int checks);
extern void printbadpid (int tmppid);


//######################### log methods #########################

/*
 * Print a message to a file stream (and log the message if necessary).
 */
void vfmsg(FILE * unlog, FILE* fp, const char* fmt, va_list ap)
{
   char buf[BUFSIZ];

   vsnprintf(buf, BUFSIZ, fmt, ap);
   fputs(buf, fp);
   fflush(fp) ;
   // fputs(buf, stderr);

   if (NULL != unlog)
      fputs(buf, unlog);
}


/*
 * Print a message to a stdout (and log the message if necessary), appending \n.
 */
void msgln(FILE * unlog, int indent, const char* fmt, ...)
{
   char buf[BUFSIZ];
   va_list ap;

   if(1 == indent)
   {
      strncpy(buf, "\t", BUFSIZ-1);
      strncat(buf, fmt, BUFSIZ-strlen(buf)-1);
   }
   else
   {
      strncpy(buf, fmt, BUFSIZ-1);
   }
   buf[BUFSIZ-1] = 0 ;
   strncat(buf, "\n", BUFSIZ-1-strlen(buf));

   va_start(ap, fmt);
   vfmsg(unlog, stdout, buf, ap);
   va_end(ap);
}


/*
 * Print a warning message to a stderr (and log the message if necessary),
 * appending \n, only if in verbose mode.
 *
 * If errno is not 0, then information about the last error is printed too.
 */
void warnln(int verbose, FILE * unlog, const char* fmt, ...)
{
   char buf[BUFSIZ];
   va_list ap;
   int e = errno; /* save it in case some other function fails */

   if (!verbose)
   {
      return;
   }

   strncpy(buf, "Warning : ", BUFSIZ);
   strncat(buf, fmt, BUFSIZ-1-strlen(buf));
   if (e != 0)
   {
      strncat(buf, " [", BUFSIZ-1-strlen(buf));
      strncat(buf, strerror(e), BUFSIZ-1-strlen(buf));
      strncat(buf, "]", BUFSIZ-1-strlen(buf));
   }
   strncat(buf, "\n", BUFSIZ-1-strlen(buf));

   va_start(ap, fmt);
   vfmsg(unlog, stderr, buf, ap);
   va_end(ap);
}


/*
 * Print an error to stderr and exit with code 1.
 *
 * If errno is not 0, then information about the last error is printed too.
 */
void die(FILE * unlog, const char* fmt, ...)
{
   va_list ap;
   char buf[BUFSIZ];
   int e = errno; /* save it in case some other function fails */

   strncpy(buf, "Error : ", BUFSIZ);
   strncat(buf, fmt, BUFSIZ-1-strlen(buf));
   if (e != 0) 
   {
      strncat(buf, " [", BUFSIZ-1-strlen(buf));
      strncat(buf, strerror(e), BUFSIZ-1-strlen(buf));
      strncat(buf, "]", BUFSIZ-1-strlen(buf));
   }
   strncat(buf, "\n", BUFSIZ-1-strlen(buf));

   va_start(ap, fmt);
   vfmsg(unlog, stderr, buf, ap);
   va_end(ap);

   exit(1);
}

/*
 * Initialize and write a header to the log file. 
 */
FILE *init_log(int logtofile, const char *header, const char *basename, int hfriend)
{
   FILE *fh ;
   char filename[PATH_MAX] ;
   time_t scantime;
   struct tm *tmPtr;
   char cad[80];
   
   if (0 == logtofile)
   {
      return(NULL);
   }

   scantime = time(NULL);
   tmPtr = localtime(&scantime);
   sprintf(filename, "%s_%4d-%02d-%02d_%02dh%02dm%02ds.%s", basename, tmPtr->tm_year+1900, tmPtr->tm_mon + 1, tmPtr->tm_mday, tmPtr->tm_hour, tmPtr->tm_min, tmPtr->tm_sec, "log"  );

   fh = fopen(filename, "w");
   if (NULL == fh)
   {
      logtofile = 0; // inhibit write to log file
      warnln(1, NULL, "Unable to open log file (%s)!", filename) ;
      return(NULL) ;
   }

   fputs(header, fh);
   strftime( cad, 80, "%H:%M:%S, %F", tmPtr );
   fprintf(fh, "\n%s scan starting at: %s\n", basename, cad) ;
   if (hfriend != 0)
   {
      printf("\n%s scan starting at: %s\n", basename, cad) ;
   }
   fflush(stdout) ;
   return(fh);
}

/* Write a footer and close the log file. */
void close_log(FILE *fh, const char *basename, int hfriend)
{

   if (NULL == fh)
   {
      return ;
   }

   time_t scantime;
   char cad[80];
   struct tm *tmPtr;

   scantime = time(NULL);
   tmPtr = localtime(&scantime);
   strftime( cad, 80, "%H:%M:%S, %F", tmPtr );

   fprintf(fh, "%s scan ending at: %s\n", basename, cad );
   if (hfriend != 0)
   {
      printf("%s scan ending at: %s\n", basename, cad );
   }
   fflush(stdout) ;
   fclose(fh);
}

//######################### log methods end #########################


//######################### tcp/udp check methods #########################
// options
int use_fuser = 0;
int use_lsof = 0;

#ifdef __linux__
   int use_ss = 1;   // on Linux use ss by default
#else
   int use_ss = 0;   // else don't use ss by default
#endif
int use_quick = 0;

char checker[10] = "ss" ;

// Temporary string for output
char scratch[1000];

// Temporary string for output
char used_options[1000] = "";

// For logging to file
int logtofile = 0;
FILE *unlog;

// Global hidden port counter, used only to set the exit code of the program
int hidden_found;


/* thx aramosf@unsec.net for the nice regexp! */

// Default commands for Linux, needs iproute2
char tcpcommand2[]= "ss -tan sport = :%d | sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'" ;
char udpcommand2[]= "ss -uan sport = :%d | sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'" ;

// fuser commands
// for FreeBSD, use sockstat as fuser equivalent.
#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
   // FreeBSD
   char fuserTCPcommand[]= "sockstat -46 -p %d -P tcp" ;
   char fuserUDPcommand[]= "sockstat -46 -p %d -P udp" ;
#else
   char fuserTCPcommand[]= "fuser -v -n tcp %d 2>&1" ;
   char fuserUDPcommand[]= "fuser -v -n udp %d 2>&1" ;
#endif

// lsof commands
char lsofTCPcommand[]= "lsof +c 0 -iTCP:%d" ;
char lsofUDPcommand[]= "lsof +c 0 -iUDP:%d" ;

#ifdef __OpenBSD__
   // OpenBSD
   char tcpcommand1[]= "netstat -an -p tcp | sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'" ;
   char udpcommand1[]= "netstat -an -p udp| sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'" ;
#elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
   // FreeBSD
   char tcpcommand1[]= "netstat -an -p tcp | sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'" ;
   char udpcommand1[]= "netstat -an -p udp| sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'" ;
#elif (defined(sun) || defined(__sun)) && (defined(__SVR4) || defined(__svr4__))
   // Solaris
   char tcpcommand1[]= "netstat -an -P tcp | sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'" ;
   char udpcommand1[]= "netstat -an -P udp| sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'" ;
#else
   // Linux / default
   char tcpcommand1[]= "netstat -tan | sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'" ;
   char udpcommand1[]= "netstat -uan | sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'" ;
#endif


/*
 *  Run a command to get more information about a port. 
 */
static void print_info(const char *prog_name, const char *command_fmt, int port)
{
   char buffer[1000];
   FILE* fp;

   sprintf(buffer, command_fmt, port);
   fp = popen(buffer, "r") ;

   if (NULL == fp)
   {
      warnln(verbose, unlog, "Couldn't run command: %s", buffer) ;
      return ;
   }

   msgln(unlog, 1, "%s reports :", prog_name) ;

   while (NULL != fgets(buffer, 1000, fp))
   {
      msgln(unlog, 1, buffer) ;
   }

   pclose(fp);
}

/* Print a port, optionally querying info about it via lsof or fuser. */
void print_port(enum Proto proto, int port)
{
      msgln(unlog, 0, "\nFound Hidden port that not appears in %s: %i", checker, port) ;
      if (1 == use_fuser)
      {
         if (TCP == proto)
         {
#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
            print_info("sockstat", fuserTCPcommand, port);
#else
            print_info("fuser", fuserTCPcommand, port);
#endif
         }
         else
         {
#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
            print_info("sockstat", fuserUDPcommand, port);
#else
            print_info("fuser", fuserUDPcommand, port);
#endif
         }
      }
      if (1 == use_lsof)
      {
         if (TCP == proto)
         {
            print_info("lsof", lsofTCPcommand, port);
         }
         else
         {
            print_info("lsof", lsofUDPcommand, port);
         }
      }
}



static char netstat_ports[65536];
static char hidden_ports[65536];
static char check_ports[65536];

/* Fill netstat_ports with the ports netstat see as used for protocol proto. */
static void get_netstat_ports(enum Proto proto)
{
   FILE *fp;
   int port;

   if (TCP == proto)
   {
      fp=popen (tcpcommand1, "r");
   }
   else
   {
      fp=popen (udpcommand1, "r");
   }

   if (fp == NULL)
   {
      die(unlog, "popen failed to open netstat to get the ports list");
   }

   memset(netstat_ports, 0, sizeof(netstat_ports));

   errno = 0;
   while (!feof(fp))
   {
      if (fscanf(fp, "%i\n", &port) == EOF && errno != 0)
      {
         die(unlog, "fscanf failed to parse int");
      }

      netstat_ports[port] = 1;
   }

   pclose(fp);
}


/*
 * Check a list of ports against what netstat report as used ports.
 *
 * All ports that are not reported as used by netstat are opened, binded and
 * put in listen state (for the TCP proto). If any of that operations fail with
 * an EADDRINUSE, it's reported as a port hidden to netstat.
 */
static void check(enum Proto proto)
{
   int i;
   int protocol;

   if (proto == TCP)
      protocol = SOCK_STREAM;
   else if (proto == UDP)
      protocol = SOCK_DGRAM;
   else
      abort();

   memset(hidden_ports, 0, sizeof(hidden_ports));
   hidden_found = 0;

   get_netstat_ports(proto);
   for (i = 0; i < 65536; i++)
   {
      int fd;
      int reuseaddr;
      struct sockaddr_in addr;

      /*
      * skip if is not a port to check or is already visible to
      * netstat
      */
      if (!check_ports[i] || netstat_ports[i])
      {
         continue;
      }

      fd = socket(AF_INET, protocol, 0);
      if (fd == -1)
      {
         die(unlog, "socket creation failed");
      }

      reuseaddr = 1;
      if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr,
                     sizeof(reuseaddr)) != 0)
      {
         die(unlog, "setsockopt can't set SO_REUSEADDR");
      }

      addr.sin_family = AF_INET;
      addr.sin_addr.s_addr = INADDR_ANY;
      addr.sin_port = htons(i);

      /*
       * if we can't bind or listen because the address is used, the
       * port is asumed to be used and added to the hidden_ports list
       * because we only check for ports not visible by netstat.
       * If we can bind them, we remove them from the check_ports
       * list so we don't try to check them again if a new pass is
       * performed in the future.
       */
      errno = 0;
      if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0 ||
                      (proto == TCP && listen(fd, 1) != 0))
      {
         if (errno == EADDRINUSE)
         {
            hidden_ports[i] = 1;
            hidden_found++;
         }
         else 
         {
            warnln(verbose, unlog, "bind failed, maybe you are not root?");
            check_ports[i] = 0;
         }
      }
      else
      {
         check_ports[i] = 0;
      }

      close(fd);
   }
}


/*
 * Print ports not visible to netstat but that are being used.
 *
 * The check for hidden ports is retried to minimize false positives, see
 * comments inside the function for details.
 */
void print_hidden_ports(enum Proto proto)
{
   /* reset the list of ports to check (we start wanting to check all of
    * them) and the list of hidden ports (none is hidden until we prove
    * otherwise)
    */
   memset(check_ports, 1, sizeof(check_ports));
   memset(hidden_ports, 0, sizeof(hidden_ports));

   /*
    * Double-check to minimize false positives.
    *
    * For very short lived connections we have a race condition between
    * getting the output from netstat and trying to open the port
    * ourselves. To minize this problem we check again the ports reported
    * as hidden. If in the next run of netstat those ports are not present
    * anymore, is fairly safe to asume they were false positives.
    */
   check(proto);
   if (hidden_found)
   {
      memcpy(check_ports, hidden_ports, sizeof(hidden_ports));
      check(proto);
   }

   if (hidden_found)
   {
      int i;
      for (i = 0; i < 65536; i++)
      {
         if (hidden_ports[i])
         {
            print_port(proto, i);
         }
      }
   }
}

//######################### tcp/udp check methods end #########################

//######################### pid bruteforce methods #########################

/*
 *  Minimalist thread function for brute test.
 *  Set tid with the pid of the created thread. 
 */
void *functionThread (__attribute__ ((unused)) void *parametro) 
{

   tid = (pid_t) syscall (SYS_gettid);
   return(&tid) ;
};

/*
 *  Brute force the pid space via vfork and 
 *  pthread_create/pthread_join. All pid which
 *  can't be obtained are check against ps output
 */
int* allpids ;
int* allpids2 ;

void brute(void) 
{
   volatile int i = 0;
   int x;
   int y;
   int z;

   msgln(unlog, 0, "[*]Starting scanning using brute force against PIDS with fork()\n") ;

   if ( NULL == (allpids = (int *)malloc(sizeof(int) * maxpid)))
   {
      die(unlog, "Error: Cannot allocate pid arrays ! Exiting.");
   }

    if ( NULL == (allpids2 = (int *)malloc(sizeof(int) * maxpid)))
    {
        die(unlog, "Error: Cannot allocate pid arrays ! Exiting.");
    }

    // PID under 301 are reserved for kernel
    for(x=0; x < 301; x++) 
    {
        allpids[x] = 0 ;
        allpids2[x] = 0 ;
    }

    for(z=301; z < maxpid; z++) 
    {
        allpids[z] = z ;
        allpids2[z] = z ;
    }


   // printf("Maxpid : %06d\n", maxpid);
   for (i=301; i < maxpid; i++) 
   {
      int vpid;
      int status;
      errno= 0 ;

      if ( ( vpid =  vfork() ) == 0) 
      {
         _exit(0);
      }

      if (0 == errno) 
      {
         allpids[vpid] =  0;
         waitpid(vpid, &status, 0);
      }
   }

    for (i=301; i < maxpid; i++) 
    {
        int vpid;
        int status;
        errno= 0 ;

        if ((vpid = vfork()) == 0) 
        {
            _exit(0);
        }

        if (0 == errno) 
        {
            allpids2[vpid] =  0;
            waitpid(vpid, &status, 0);
        }
    }

   /* processes that quit at this point in time create false positives */
   for(y=0; y < maxpid; y++) 
   {
      if ((allpids[y] != 0) && (allpids2[y] != 0)) 
      {
//       printf("Check PID : %d\n", y);
         if(!checkps(allpids[y],PS_PROC | PS_THREAD | PS_MORE) ) 
         {
            printbadpid(allpids[y]);
         }
      }
   }

   msgln(unlog, 0, "[*]Starting scanning using brute force against PIDS with pthread functions\n") ;
    // PID under 301 are reserved for kernel
    for(x=0; x < 301; x++) 
    {
        allpids[x] = 0 ;
        allpids2[x] = 0 ;
    }

    for(z=301; z < maxpid; z++) 
    {
        allpids[z] = z ;
        allpids2[z] = z ;
    }

   for (i=301; i < maxpid ; i++) 
   {
      void *status;
      errno= 0 ;
      pthread_t idHilo;
      int error;

      error = pthread_create (&idHilo, NULL, functionThread, NULL);
      if (error != 0)
      {
         die(unlog, "Error: Cannot create thread ! Exiting.");
      }

      error = pthread_join(idHilo, &status);
      if (error != 0)
      {
         die(unlog, "Error : Cannot join thread ! Exiting.");
      }
      allpids[tid] =  0;
   }

    for (i=301; i < maxpid ; i++) {
        void *status;
        errno= 0 ;
        pthread_t idHilo;
        int error;

        error = pthread_create (&idHilo, NULL, functionThread, NULL);
        if (error != 0)
        {
        die(unlog, "Error: Cannot create thread ! Exiting.");
        }

        error = pthread_join(idHilo, &status);
        if (error != 0)
        {
        die(unlog, "Error : Cannot join thread ! Exiting.");
        }
        allpids2[tid] =  0;
    }

   /* processes that quit at this point in time create false positives */
   for(y=0; y < maxpid; y++) 
   {
      if ((allpids[y] != 0) && (allpids2[y] != 0)) 
      {
         if(!checkps(allpids[y],PS_PROC | PS_THREAD | PS_MORE) ) 
         {
            printbadpid(allpids[y]);
         }
      }
   }
   
   if ( NULL != allpids)
      free((void *)allpids) ;
      
   if ( NULL != allpids2)
      free((void *)allpids2) ;
}

//######################### pid bruteforce methods end #########################


/*
 *  Compare the various system calls against each other,
 *  and with fs function in /proc, finally check ps output
 */
void checkallquick(void) 
{

   int ret;
   int syspids;
   struct timespec tp;
   struct sched_param param;
   cpu_set_t mask;
   int test_number = 0 ;
   int found=0;
   int hidenflag = 0;
   int found_killbefore=0;
   int found_killafter=0;
   char directory[100];
   struct stat buffer;
   int statusproc, statusdir ;
   char curdir[PATH_MAX] ;
   DIR *dir_fd;

   msgln(unlog, 0, "[*]Searching for Hidden processes through  comparison of results of system calls, proc, dir and ps") ;

   // get the path where Unhide is ran from.
   if (NULL == getcwd(curdir, PATH_MAX))
   {
      warnln(verbose, unlog, "Can't get current directory, test aborted.") ;
      return;
    }

   sprintf(directory,"/proc/");

   for ( syspids = 1; syspids <= maxpid; syspids++ ) 
   {
      // avoid ourselves
      if (syspids == mypid) 
      {
         continue;
      }

      found=0;
      found_killbefore=0;
      found_killafter=0;
      test_number = 0 ;

      errno=0;
      ret = kill(syspids, 0);
      if (errno == 0) found_killbefore=1;

      errno= 0 ;
      test_number += 1 ;
      ret = getpriority(PRIO_PROCESS, syspids);
      if (errno == 0) found++;

      errno= 0 ;
      test_number += 1 ;
      ret = getpgid(syspids);
      if (errno == 0) found++;

      errno= 0 ;
      test_number += 1 ;
      ret = getsid(syspids);
      if (errno == 0) found++;

      errno= 0 ;
      test_number += 1 ;
      ret = sched_getaffinity(syspids, sizeof(cpu_set_t), &mask);
      if (ret == 0) found++;

      errno= 0 ;
      test_number += 1 ;
      ret = sched_getparam(syspids, &param);
      if (errno == 0) found++;

      errno= 0 ;
      test_number += 1 ;
      ret = sched_getscheduler(syspids);
      if (errno == 0) found++;

      errno=0;
      test_number += 1 ;
      ret = sched_rr_get_interval(syspids, &tp);
      if (errno == 0) found++;

      sprintf(&directory[6],"%d",syspids);

      test_number += 1 ;
      statusproc = stat(directory, &buffer) ;
      if (statusproc == 0) 
      {
         found++;
      }

      test_number += 1 ;
      statusdir = chdir(directory) ;
      if (statusdir == 0) 
      {
         found++;
         if (-1 ==  chdir(curdir))
         {
            warnln(verbose, unlog, "Can't go back to unhide directory, test aborted.") ;
            return;
         }
      }

      test_number += 1 ;
      dir_fd = opendir(directory) ;
      if (NULL != dir_fd) 
      {
         found++;
         closedir(dir_fd);
      }

      // Avoid checkps call if nobody sees anything
      if ((0 != found) || (0 != found_killbefore)) 
      {
         test_number += 1 ;
         if(checkps(syspids,PS_PROC | PS_THREAD)) 
         {
            found++;
         }
      }

      errno=0;
      ret = kill(syspids, 0);
      if (errno == 0) found_killafter=1;


      /* these should all agree, except if a process went or came in the middle */
      if (found_killbefore == found_killafter) 
      {
         if ( ! ((found_killbefore == 0 && found == 0) ||
                 (found_killbefore == 1 && found == test_number)) ) 
         {
            printbadpid(syspids);
            hidenflag = 1 ;

         }
      } /* else: unreliable */
      else 
      {
         errno = 0 ;
         warnln(verbose, unlog, "syscall comparison test skipped for PID %d.", syspids) ;
      }
   }
   if (humanfriendly == TRUE)
   {
      if (hidenflag == 0)
      {
         msgln(unlog, 0, "No hidden PID found\n") ;
      }
      else
      {
         msgln(unlog, 0, "") ;
      }
   }
}

/*
 *  Check that all processes seen by ps are also seen by
 *  fs function in /proc and by syscall
 */
void checkallreverse(void) 
{
   int ret;
   long int syspids = 0;
   struct timespec tp;
   struct sched_param param;
   cpu_set_t mask;
   int not_seen = 0;
   int hidenflag = 0;
   int found_killbefore = 0;
   int found_killafter = 0;
   FILE *fich_tmp;
   char command[50];
   // char read_line[1024];
   char *read_line = NULL;
   size_t length = 0 ;
   ssize_t rlen ;
   char lwp[11];  // extended to 11 char for 32 bit PID
   int  index;
   char directory[100];
   struct stat buffer;
   // int statusproc, statusdir, backtodir;
   int statusproc, statusdir;
   char curdir[PATH_MAX] ;
   DIR *dir_fd;

   msgln(unlog, 0, "[*]Searching for Fake processes by verifying that all threads seen by ps are also seen by others") ;

   sprintf(command,REVERSE) ;

   fich_tmp=popen (command, "r") ;
   if (fich_tmp == NULL) 
   {
      warnln(verbose, unlog, "Couldn't run command: %s, test aborted", command) ;
      return;
   }
   // get the path where Unhide is ran from.
   if (NULL == getcwd(curdir, PATH_MAX))
   {
      warnln(verbose, unlog, "Can't get current directory, test aborted") ;
      return;
   }

   strcpy(directory,"/proc/");

   // while (NULL != fgets(read_line, 1024, fich_tmp)) 
   while ((rlen = getline(&read_line, &length, fich_tmp)) != -1)
   {
      char* curline = read_line;


      read_line[rlen] = 0;

      while( *curline == ' ' && curline <= read_line+rlen) 
      {
         curline++;
      }

      // get LWP
      index=0;
      while( isdigit(*curline) && curline <= read_line+rlen) 
      {
         lwp[index++] = *curline;
         curline++;
     }
      lwp[index] = 0; // terminate string

      syspids = atol(lwp);

      if (0 == syspids) 
      {
          errno = 0 ; // this warning should not display previous old error.
          warnln(verbose, unlog, "No numeric pid found on ps output line, skip line") ;
          continue ; // something went wrong
      }

      // avoid ourselves
      if (syspids == mypid) 
      {
         continue;
      }

      not_seen=0;
      found_killbefore=0;
      found_killafter=0;

      errno=0;
      ret = kill(syspids, 0);
      if (errno == 0) found_killbefore=1;

      strcpy(&directory[6],lwp);

      statusproc = stat(directory, &buffer) ;
      if (statusproc != 0) 
      {
         not_seen++;
      }

      statusdir = chdir(directory) ;
      if (statusdir != 0) 
      {
         not_seen++;
      }
      else 
      {
         if (-1 == chdir(curdir))
         {
            warnln(verbose, unlog, "Can't go back to unhide directory, test aborted") ;
            return;
         }
      }

      dir_fd = opendir(directory) ;
      if (NULL == dir_fd) 
      {
         not_seen++;
      }
      else 
      {
         closedir(dir_fd);
      }

      errno= 0 ;
      ret = getpriority(PRIO_PROCESS, syspids);
      if (errno != 0) not_seen++;

      errno= 0 ;
      ret = getpgid(syspids);
      if (errno != 0) not_seen++;

      errno= 0 ;
      ret = getsid(syspids);
      if (errno != 0) not_seen++;

      errno= 0 ;
      ret = sched_getaffinity(syspids, sizeof(cpu_set_t), &mask);
      if (ret != 0) not_seen++;

      errno= 0 ;
      ret = sched_getparam(syspids, &param);
      if (errno != 0) not_seen++;

      errno= 0 ;
      ret = sched_getscheduler(syspids);
      if (errno != 0) not_seen++;

      errno=0;
      ret = sched_rr_get_interval(syspids, &tp);
      if (errno != 0) not_seen++;

      errno=0;
      ret = kill(syspids, 0);
      if (errno == 0) found_killafter=1;

      // printf("FK_bef = %d FK_aft = %d not_seen = %d\n",found_killbefore, found_killafter, not_seen);  //DEBUG
      /* these should all agree, except if a process went or came in the middle */
      if (found_killbefore == found_killafter) 
      {
         if (found_killafter == 1) 
         {
            if (0 != not_seen) 
            {
               if (NULL == strstr(curline, REVERSE)) // avoid our spawn ps
               {  
                  // printbadpid should NOT be used here : we are looking for faked process
                  msgln(unlog, 0, "Found FAKE PID: %i\tCommand = %s not seen by %d system function(s)", syspids, curline, not_seen) ;
                  found_HP = 1;
                  hidenflag = 1 ;
               }
            }
         }
         else // even kill() doesn't see this process.
         {
            if (NULL == strstr(curline, REVERSE))  // avoid our spawned ps
            {  
               // printbadpid should NOT be used here : we are looking for faked process
               msgln(unlog, 0, "Found FAKE PID: %i\tCommand = %s not seen by %d system function(s)", syspids, curline, not_seen + 2) ;
               found_HP = 1;
               hidenflag = 1 ;
            }
         }
      } /* else: unreliable */
      else
      {
         errno = 0 ;
         warnln(verbose, unlog, "reverse test skipped for PID %d", syspids) ;
      }
   }
    free(read_line) ;

   if (rlen == -1)
      warnln(verbose, unlog, "Something went wrong with getline reading pipe, reverse test stopped at PID %ld\n", syspids) ;
   
   if (humanfriendly == TRUE)
   {
      if (hidenflag == 0)
      {
         msgln(unlog, 0, "No FAKE PID found\n") ;
      }
      else
      {
         msgln(unlog, 0, "") ;
      }
   }

   if (fich_tmp != NULL)
      pclose(fich_tmp);
}


/*
 *  Get the maximum number of process on this system. 
 */
void get_max_pid(int* newmaxpid) 
{
   char path[]= "/proc/sys/kernel/pid_max";
   pid_t tmppid = 0;
   FILE* fd= fopen(path,"r");
   if(!fd) 
   {
      warnln(1, unlog, "Cannot read current maximum PID. Using default value %d", * newmaxpid) ;
   }
   else if((fscanf(fd, "%d", &tmppid) != 1) || tmppid < 1) 
   {
      msgln(unlog, 0, "Warning : Cannot get current maximum PID, error parsing %s format. Using default value %d", path, * newmaxpid) ;
   } 
   else 
   {
      *newmaxpid = tmppid;
   }
   if (fd) {
       fclose(fd);
   }
}

/*
 *  Verify if ps see a given pid. 
 */
int checkps(int tmppid, int checks) 
{
   int ok = 0;
   char pids[30];
   char compare[100];
   char command[60];

   // The compare string is the same for all test
   sprintf(compare,"%i\n",tmppid);

   if (PS_PROC == (checks & PS_PROC)) 
   {
      FILE *fich_tmp ;
      sprintf(command,COMMAND,tmppid) ;
      fich_tmp=popen (command, "r") ;
      if (fich_tmp == NULL) 
      {
         warnln(verbose, unlog, "Couldn't run command: %s while ps checking pid %d", command, tmppid) ;
         return(0);
      }

        char* tmp_pids = pids;

        if (NULL != fgets(pids, 30, fich_tmp)) 
        {
            pids[29] = 0;
            while( *tmp_pids == ' ' && tmp_pids <= pids+29) 
            {
                tmp_pids++;
            }

            if (strncmp(tmp_pids, compare, 30) == 0) {ok = 1;}
        }


      if (NULL != fich_tmp)
         pclose(fich_tmp);

      if (1 == ok) return(ok) ;   // pid is found, no need to go further
   }

   if (PS_THREAD == (checks & PS_THREAD)) 
   {
      FILE *fich_thread ;
      fich_thread=popen (THREADS, "r") ;
      if (NULL == fich_thread) 
      {
         warnln(verbose, unlog, "Couldn't run command: %s while ps checking pid %d", THREADS, tmppid) ;
         return(0);
      }

      while ((NULL != fgets(pids, 30, fich_thread)) && ok == 0) 
      {
         char* tmp_pids = pids;
         pids[29] = 0;

         while( *tmp_pids == ' ' && tmp_pids <= pids+29) 
         {
            tmp_pids++;
         }

         if (strncmp(tmp_pids, compare, 30) == 0) {ok = 1;}
      }
      if (fich_thread != NULL)
         pclose(fich_thread);

      if (1 == ok) return(ok) ;   // thread is found, no need to go further
   }

   if (PS_MORE == (checks & PS_MORE)) 
   {
      FILE *fich_session ;
      sprintf(command,SESSION,tmppid) ;
      fich_session=popen (command, "r") ;
      if (fich_session == NULL) 
      {
         warnln(verbose, unlog, "Couldn't run command: %s while ps checking pid %d", command, tmppid) ;
         return(0);
      }

      while ((NULL != fgets(pids, 30, fich_session)) && ok == 0) 
      {
         char* tmp_pids = pids;
         pids[29] = 0;

         while( *tmp_pids == ' ' && tmp_pids <= pids+29) 
         {
            tmp_pids++;
         }

         if (strncmp(tmp_pids, compare, 30) == 0) 
         {
            ok = 1;
         }
      }

      pclose(fich_session);

      if (1 == ok) 
         return(ok) ;   // session is found, no need to go further

      FILE *fich_pgid ;

      fich_pgid=popen (PGID, "r") ;
      if (NULL == fich_pgid) 
      {
         warnln(verbose, unlog, "Couldn't run command: %s while ps checking pid %d", PGID, tmppid) ;
         return(0);
      }

      while ((NULL != fgets(pids, 30, fich_pgid)) && ok == 0) 
      {
         char* tmp_pids = pids;
         pids[29] = 0;

         while( *tmp_pids == ' ' && tmp_pids <= pids+29) 
         {
            tmp_pids++;
         }

         if (strncmp(tmp_pids, compare, 30) == 0) 
         {
            ok = 1;
         }
      }

      pclose(fich_pgid);

   }
   return ok;
}

/*
 *  Display hidden process and possibly some information on it. 
 */
void printbadpid (int tmppid) 
{
   int statuscmd ;
   char cmd[100] ;
   struct stat buffer;
   FILE *cmdfile ;
   char *cmdcont = NULL, fmtstart[128];
   size_t cmdlen = 0 ;
   ssize_t readl ;
   char linkcont[2000];
   int cmdok = 0 ;

   found_HP = 1;
   sprintf(fmtstart,"Found HIDDEN PID: %i", tmppid) ;
   msgln(unlog, 0, "%s", fmtstart) ;

   sprintf(cmd,"/proc/%i/cmdline",tmppid);
   statuscmd = stat(cmd, &buffer);

   if (statuscmd == 0) 
   {
      cmdfile=fopen (cmd, "r") ;
      if (cmdfile != NULL) 
      {
         ssize_t ret ;
         while ((-1 != (ret = getline (&cmdcont, &cmdlen, cmdfile))) && 0 == cmdok)
         {
            cmdok++ ;
            msgln(unlog, 0, "\tCmdline: \"%s\"", cmdcont) ;
         }

         free(cmdcont) ;
         cmdcont = NULL;
         cmdlen = 0 ;

         if (ret == -1)
            warnln(verbose, unlog, "Something went wrong with getline reading pipe") ;

         fclose(cmdfile);
      }
   }
   if (0 == cmdok) 
   {
      msgln(unlog, 0, "\tCmdline: \"<none>\"") ;
   }
   
   {  // try to readlink the exe

      sprintf(cmd,"/proc/%i/exe",tmppid);
      statuscmd = lstat(cmd, &buffer);
      // printf("%s",cmd) ; //DEBUG
      // printf("\tstatuscmd : %d\n",statuscmd) ; //DEBUG
      if (statuscmd == 0) 
      {
         ssize_t length ;

         length = readlink(cmd, linkcont, 2000) ;
         // printf("\tLength : %0d\n",(int)length) ; //DEBUG
         if (-1 != length) 
         {
            linkcont[length] = 0;   // terminate the string
            cmdok++;
            msgln(unlog, 0, "\tExecutable: \"%s\"", linkcont) ;
         }
         else
         {
            msgln(unlog, 0, "\tExecutable: \"<nonexistant>\"") ;

         }
      }
      else
      {
         msgln(unlog, 0, "\tExecutable: \"<no link>\"") ;
      }
   }
   {       // read internal command name
      sprintf(cmd,"/proc/%i/comm",tmppid);
      statuscmd = stat(cmd, &buffer);
      if (statuscmd == 0) 
      {
         cmdfile=fopen (cmd, "r") ;
         if (cmdfile != NULL) 
         {
            int cmdok2 = 0 ;

            // printf("\tCmdFile : %s\n",cmd) ; //DEBUG
            while ((-1 != (readl = getline (&cmdcont, &cmdlen, cmdfile))) && 0 == cmdok2) 
            {
               // EXPLAIN-ME : why do we use a while and then read only one line ?
               cmdok2++; 
               
               // printf("\tLastChar : %x\n",cmdcont[strlen(cmdcont)]) ; //DEBUG
               if (cmdcont[readl-1] == '\n')
               {
                  cmdcont[readl-1] = 0 ;  // get rid of newline
               }
               if (0 == cmdok) // it is a kthread (no cmdline, no link): add brackets
               {
                  msgln(unlog, 0, "\tCommand: \"[%s]\"", cmdcont) ;
               }
               else
               {
                  msgln(unlog, 0, "\tCommand: \"%s\"", cmdcont) ;
               }
              
            }

            free(cmdcont) ;
            cmdcont = NULL;
            cmdlen = 0 ;

            fclose(cmdfile);
         }
         else
         {
            msgln(unlog, 0, "\tCommand: \"can't read file\"") ;
         }
      }
      else 
      {
         msgln(unlog, 0, "\t\"<No comm file>\"  ... maybe a transitory process\"") ;
      }
   }
   // try to print some useful info about the hidden process
   // does not work well for kernel processes/threads and deamons
   {

      sprintf(cmd,"/proc/%i/environ",tmppid);
      statuscmd = stat(cmd, &buffer);
      if (statuscmd == 0) 
      {
         FILE *fich_tmp ;

         sprintf(cmd,"cat /proc/%i/environ | tr \"\\0\" \"\\n\" | grep -w 'USER'",tmppid) ;
         // printf(cmd) ;
         fich_tmp=popen (cmd, "r") ;
         if (fich_tmp == NULL) 
         {
            warnln(verbose, unlog, "\tCouldn't read USER for pid %d", tmppid) ;
         }

         if (-1 != (readl = getline (&cmdcont, &cmdlen, fich_tmp)))
         {
            cmdcont[readl-1] = 0 ;  // get rid of newline
            msgln(unlog, 0, "\t$%s", cmdcont) ;
         }
         else
         {
            // msgln(unlog, 0, "\t$USER=<undefined>", cmdcont) ;
            msgln(unlog, 0, "\t$USER=<undefined>") ;
         }
         free(cmdcont) ;
         cmdcont = NULL ;
         cmdlen = 0 ;
         pclose(fich_tmp) ;

         sprintf(cmd,"cat /proc/%i/environ | tr \"\\0\" \"\\n\" | grep -w 'PWD'",tmppid) ;
         // printf(cmd) ;
         fich_tmp=popen (cmd, "r") ;
         if (fich_tmp == NULL) 
         {
            warnln(verbose, unlog, "\tCouldn't read PWD for pid %d", tmppid) ;
         }

         if (-1 != (readl = getline (&cmdcont, &cmdlen, fich_tmp))) 
         {
            cmdcont[readl-1] = 0 ;  // get rid of newline
            msgln(unlog, 0, "\t$%s", cmdcont) ;
         }
         else
         {
            // msgln(unlog, 0, "\t$PWD=<undefined>", cmdcont) ;
            msgln(unlog, 0, "\t$PWD=<undefined>") ;
         }
         free(cmdcont) ;
         cmdcont = NULL;
         cmdlen = 0 ;
         pclose(fich_tmp);
      }
   }
   printf("\n");
}


/*
 *  Display short help 
 */
void usage(char * command) 
{
   printf("Usage: %s [options] [brute]\n\n", command);
   printf("Option :\n");
   printf("   -V          Show version and exit\n");
   printf("   -v          verbose\n");
   printf("   -h          display this help\n");
   printf("   -f          log result into unhide-linux.log file\n");
   printf("   brute       bruteforce thread/process ids, it will take 3-5 minutes\n");
   fflush(stdout) ;
}

/*
 * Parse command line arguments (exiting if requested by any option).
 */
void parse_args(int argc, char **argv) 
{
   int c = 0;
   int index = 0;
   
   static struct option long_options[] =
   {
   /* These options set a flag. */
      {"fork bruteforce",  no_argument,      &bruteflag,   0},
      {"log",                no_argument,      &logtofile,          1},
      {"verbose",            no_argument,      0,                 'v'},
      {"help",               no_argument,      0,                 'h'},
      {"version",            no_argument,      0,                 'V'},
      {0, 0, 0, 0}
   };

   for(;;)  // until there's no more option
   {
      /* getopt_long stores the option index here. */
      int option_index = 0;

      c = getopt_long (argc, argv, "dformhvVHu",
                        long_options, &option_index);

      /* Detect the end of the options. */
      if (c == -1)
         break;

      switch(c)
      {
        case 0 :   // flag long options
            if (long_options[option_index].flag != 0) //if this option set a flag
            {
                break;  // nothing to do
            }
            printf ("option %s", long_options[option_index].name);
            if (optarg) // if there's an argument
            {
                printf (" with arg %s", optarg);
            }
            printf ("\n");
            break ;
        case 'h' :
            usage(argv[0]) ;
            exit (0) ;
            break ;
        case 'f' :
            logtofile = 1;
            break;
        case 'v' :
            verbose++ ; ;
            break ;
        case 'V' :
            printf("%s\n", version);
            exit (0) ;
            break ;
        case 'H' :
            humanfriendly = TRUE ;
            break ;
        case '?' :     // invalid option
            exit (2) ;
            break ;
        default :      // something very nasty happened
            exit(-1) ;
            break ;
      }
     
   }
   
   // generate options string for logging
   strncpy(used_options, "Used options: ", 1000);
   if (verbose)
      strncat(used_options, "verbose ", 1000-1-strlen(used_options));
   if (bruteflag)
      strncat(used_options, "bruteflag ", 1000-1-strlen(used_options));
   if (logtofile)
      strncat(used_options, "logtofile ", 1000-1-strlen(used_options));
      
   // Process list of tests to do
   for (index = optind; index < argc; index++)
   {
      if ((strcmp(argv[index], "brute") == 0) ||
               (strcmp(argv[index], "checkbrute") == 0)) 
      {
        bruteflag = TRUE;
      }
      else 
      { 
         printf("Unknown argument: %s\n", argv[index]) ; usage(argv[0]); exit(0);
         fflush(stdout) ;
      }
   }
}


int main (int argc, char *argv[]) 
{
   if(getuid() != 0){
      die(unlog, "You must be root to run %s !", argv[0]) ;
   }

   // get the number max of processes on the system.
   // ---------------------------------------------
   get_max_pid(&maxpid);

   // analyze command line args
   // -------------------------
   used_options[0] = 0 ;
   parse_args(argc, argv) ;
   
   if (logtofile == 1) 
   {
      unlog = init_log(logtofile, header, "unhide-linux", humanfriendly) ;
   }
   msgln(unlog, 0, used_options) ;

   setpriority(PRIO_PROCESS,0,-20);  /* reduce risk from intermittent processes - may fail, dont care */

   mypid = getpid();

   // Execute required tests.
   // ----------------------
   checkallquick();
   checkallreverse();
   if (bruteflag == TRUE) {
      brute();
   }

   msgln(unlog, 0, "[*]Starting TCP checking") ;
   print_hidden_ports(TCP);
   msgln(unlog, 0, "[*]Starting UDP checking") ;
   print_hidden_ports(UDP);


   if (logtofile == 1) {
      close_log(unlog, "unhide-linux", humanfriendly) ;
   }
   fflush(stdout) ;
   return found_HP;
}
