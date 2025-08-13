#ifndef _THREAD_POOL_H_
#define _THREAD_POOL_H_

#include "locker.h"

#include <thread>
#include <functional>
#include <condition_variable>
#include <mutex>
#include <queue>

#include "structures.h"
#include "macro.h"
#include "memory.h"

class ThreadPool
{
public:

    typedef struct vector_threads
    {
        std::thread thread;
        LIST_ENTRY(vector_threads);
    }THREADS, * PTHREADS;

    typedef struct que_task
    {
        std::function<void()> task;
        LIST_ENTRY(que_task);
    }TASK, * PTASK;


    ThreadPool(size_t threads);
    ~ThreadPool();

    VOID put_task(std::function<void()> func);
    VOID run_main_thread();
    VOID wait();

    std::atomic<bool> stop{ false };


private:

    LIST<THREADS>* work = new LIST<THREADS>;
    LIST<TASK>* qtask = new LIST<TASK>;


    std::mutex mutex;
    std::mutex wmutex;
    std::condition_variable condition;
    std::condition_variable cv_wait;

    std::atomic<size_t> threads_done = 0;
    size_t active;
};


class PipeLineEncrypt
{
private:

    typedef struct vector_threads
    {
        std::jthread thread;
        LIST_ENTRY(vector_threads);
    }THREADS, * PTHREADS;

    typedef struct data_read
    {
        BYTE* data;
        DWORD BytesRead;
    }DATA_READ;


    LIST<THREADS>* work = new LIST<THREADS>;

    std::queue<std::shared_ptr<DATA_READ>> read_que;
    std::queue<std::shared_ptr<DATA_READ>> encrypt_que;
    

    BOOL stop = FALSE;    
    bool start_read;
    bool read_done = false;
    size_t rsize = 0;
    size_t esize = 0;
    size_t wsize = 0;
    std::atomic<size_t> done_man = 0;
    mutable std::mutex mtx;    
    std::condition_variable cv_read;
    std::condition_variable cv_encrypt;
    std::condition_variable cv_write;
    std::condition_variable cv_wait;
    PFILE_INFO FileInfo;

public:

    PipeLineEncrypt();
    ~PipeLineEncrypt();

    VOID INIT(PFILE_INFO a_FileInfo);
    VOID work_read();
    VOID work_encrypt();
    VOID work_write();
    VOID wait();
};

#endif