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


class ThreadPipeLine
{
private:
    typedef struct threads
    {
        std::thread thread;
        LIST_ENTRY(threads);
    }THREADS, *PTHREADS;

    typedef struct data
    {
        BYTE* data;
        DWORD bytes;
    }DATA_READ, *PDATA_READ;

    LIST<THREADS>* work = new LIST<THREADS>;
    std::queue<DATA_READ*>* que_re = new std::queue<DATA_READ*>;
    std::queue<DATA_READ*>* que_ew = new std::queue<DATA_READ*>;

    void work_read();
    void work_encrypt();
    void work_write();

    size_t padding = 0;

    std::atomic<bool> stop = false;
    bool wait_doneman = false;
    bool doneman = false;

    struct StateContext
    {
        PFILE_INFO file;
        bool start_read = false;
        bool read_doneman = false;
        bool encrypt_doneman = false;
        bool write_doneman = false;
    };

    std::queue<StateContext*>* que_state = new std::queue<StateContext*>;
    StateContext* get_front_qstate();
    
    
    std::mutex mtx_state;
    std::mutex mtx_wait;
    std::mutex mtx_read;
    std::mutex mtx_encrypt;
    std::mutex mtx_write;

    std::condition_variable cv_read;
    std::condition_variable cv_encrypt;
    std::condition_variable cv_write;
    std::condition_variable cv_wait;

public:
    ThreadPipeLine();
    ~ThreadPipeLine();
    void wait();
    void end();
    void init(PCRYPT_INFO CryptInfo, PDRIVE_INFO data)
    {
        PFILE_INFO FInfo = new FILE_INFO;
        if(!locker::SetOptionFileInfo(FInfo, data, CryptInfo))
            return;
        StateContext* state = new StateContext;
        state->file = FInfo;
        state->start_read = true;
        {
            std::lock_guard<std::mutex> lck(mtx_state);
            que_state->push(state);
            cv_read.notify_one();
        }
    }
};

#endif