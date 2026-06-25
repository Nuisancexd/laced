#include "system.h"
#include "logs.h"
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>


const char lock_file[] = "/var/run/laced.pid";


static void lock()
{
    int lock_desc = open(lock_file, O_RDWR | O_CREAT, 0640);
    if(lock_desc < 0) 
    {
        LOG_ERROR("Failed open lock file");
        syslog(LOG_ERR, "Failed open lock file");
        exit(EXIT_FAILURE);
    }
    if(lockf(lock_desc, F_TLOCK, 0) < 0)
    {
        syslog(LOG_ERR, "running");
        LOG_SUCCESS("running");
        exit(EXIT_SUCCESS);
    }

    char pidb[16] = {0 };
    snprintf(pidb, sizeof(pidb), "%d\n", getpid());
    write(lock_desc, pidb, strlen(pidb));
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
    chdir("/");

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    int devnull = open("/dev/null", O_RDWR);
    dup2(devnull, STDIN_FILENO);
    dup2(devnull, STDOUT_FILENO);
    dup2(devnull, STDERR_FILENO);

    LOG_NONE("success fork");
    
    lock();
    openlog("laced", LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(LOG_INFO, "Daemon started");
}