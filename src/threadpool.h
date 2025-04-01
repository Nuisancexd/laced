#ifndef _THREAD_POOL_H_
#define _THREAD_POOL_H_

#include <thread>
#include <functional>
#include <condition_variable>
#include <mutex>
#include "structures.h"
#include "macro.h"

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

    size_t threads_done = 0;
    size_t active;
};


ThreadPool::ThreadPool(size_t threads) : active(threads)
{
    for (size_t i = 0; i < threads; ++i)
    {
        PTHREADS mark = new THREADS;
        mark->thread = std::thread([this]()
            {
                while (!stop)
                {
                    std::function<void()> task;
                    
                    std::unique_lock<std::mutex> lock(mutex);
                    //condition.wait(lock, [this] { return !qtask->LIST_EMPTY() || stop; });

                    if (qtask->LIST_EMPTY())
                    {                    
                        if (++threads_done == active)
                        {
                            cv_wait.notify_all();
                        }
                        return;
                    }

                    task = std::move(qtask->LIST_HEAD_T()->task);

                    qtask->LIST_DELETE_HEAD();

                    lock.unlock();
                    task();                                      
                }
            });
        work->LIST_INSERT_HEAD(mark);
    }
}

VOID ThreadPool::run_main_thread()
{
    while (TRUE)
    {
        std::function<void()> task;
        std::unique_lock<std::mutex> lock(mutex);
        if (qtask->LIST_EMPTY())
        {            
            break;
        }
        
        task = std::move(qtask->LIST_HEAD_T()->task);
        qtask->LIST_DELETE_HEAD();
        lock.unlock();
        task();
    }    
    wait();
}


ThreadPool::~ThreadPool()
{
    std::lock_guard<std::mutex> done_lock(mutex);
    stop = true;
    condition.notify_all();
    PTHREADS mark = NULL;
    LIST_FOREACH(mark, work)
    {
        mark->thread.join();
    }

    delete qtask;
    delete work;
}


VOID ThreadPool::put_task(std::function<void()> func)
{
    std::lock_guard<std::mutex> lock(mutex);
    PTASK tsk = new TASK;
    tsk->task = std::move(func);
    qtask->LIST_INSERT_HEAD(tsk);
    condition.notify_one();
}

VOID ThreadPool::wait()
{
    std::unique_lock<std::mutex> lock(mutex);

    if (qtask->LIST_EMPTY() && threads_done == active) return;

    cv_wait.wait(lock, [this]()
        {
            std::lock_guard<std::mutex> task_lock(wmutex);

            return qtask->LIST_EMPTY() && threads_done == active;
        });
}

#endif