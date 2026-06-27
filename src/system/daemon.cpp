#include "system.h"
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <cstring>
#include <cstdio>

#define LOCK_FILE "/run/laced/laced.pid"

void laced::sys::clear_lock_file()
{
    int desc = open(LOCK_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if(desc != -1 ) close(desc);
}

static void lock()
{
    int lock_desc = open(LOCK_FILE, O_RDWR | O_CREAT, 0640);
    if(lock_desc < 0) 
    {
        syslog(LOG_ERR, "Failed open lock file");
        exit(EXIT_FAILURE);
    }
    if(lockf(lock_desc, F_TLOCK, 0) < 0)
    {
        syslog(LOG_ERR, "running");
        close(lock_desc);
        exit(EXIT_SUCCESS);
    }

    char pidb[16] = {0 };
    snprintf(pidb, sizeof(pidb), "%d\n", getpid());
    if(!write(lock_desc, pidb, strlen(pidb)))
        syslog(LOG_INFO, "pidb");
}

void laced::sys::demonize()
{
    pid_t pid = 0;
    int desc;
    pid = fork();
    if(pid < 0) 
        exit(EXIT_FAILURE);
    else if(pid > 0) 
        exit(EXIT_SUCCESS);

    if(setsid() < 0)
        exit(EXIT_FAILURE);

    pid = fork();
    if(pid < 0) exit(EXIT_FAILURE);
    else if(pid > 0) exit(EXIT_SUCCESS);

    umask(0);
    if(chdir("/") != 0)
    {
        syslog(LOG_ERR, "failed chdir '/'");
        exit(EXIT_FAILURE);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    int devnull = open("/dev/null", O_RDWR);
    dup2(devnull, STDIN_FILENO);
    dup2(devnull, STDOUT_FILENO);
    dup2(devnull, STDERR_FILENO);
    
    lock();
    openlog("laced", LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(LOG_INFO, "Daemon started");
}