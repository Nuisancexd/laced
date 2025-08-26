#include "threadpool.h"
#include "api.h"
#include "filesystem.h"
#include "memory.h"
#include "logs.h"


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


/*-----PIPE_LINE-----*/

/*
TODO:
add shared_ptr
add hybrid method
fix some bugs
*/

ThreadPipeLine::ThreadPipeLine()
{
    PTHREADS mark1 = new THREADS;
    mark1->thread = std::thread(&ThreadPipeLine::work_read, this);
    work->LIST_INSERT_HEAD(mark1);
    
    PTHREADS mark2 = new THREADS;
    mark2->thread = std::thread(&ThreadPipeLine::work_encrypt, this);
    work->LIST_INSERT_HEAD(mark2);
    
    PTHREADS mark3 = new THREADS;
    mark3->thread = std::thread(&ThreadPipeLine::work_write, this);
    work->LIST_INSERT_HEAD(mark3);
}

ThreadPipeLine::~ThreadPipeLine()
{
    {
        std::lock_guard<std::mutex> lck(mtx_wait);
        stop = true;
    }

    cv_read.notify_all();
    cv_encrypt.notify_all();
    cv_write.notify_all();

    THREADS* thread = NULL;
    LIST_FOREACH(thread, work)
        thread->thread.join();

    delete work;
    delete que_re;
    delete que_ew;
    delete que_state;
}

ThreadPipeLine::StateContext* ThreadPipeLine::get_front_qstate()
{
    std::lock_guard<std::mutex> lck(mtx_state);
    if(que_state->empty())
        return NULL;
    return que_state->front();
}

void ThreadPipeLine::work_read()
{
    while(true)
    {
        std::unique_lock<std::mutex> lock(mtx_read);
        cv_read.wait(lock, [this] 
            {
                if(stop)
                    return true;
                auto* state = get_front_qstate();
                return state && state->start_read; 
            });
        if(stop) break;

        auto* state = get_front_qstate();
        if(state == NULL)
            continue;

        if(state->write_doneman 
        && state->encrypt_doneman
        && state->read_doneman)
        {
            std::lock_guard<std::mutex> lck(mtx_state);
            {
                locker::free_file_info(que_state->front()->file, true);
                delete que_state->front()->file;
                auto* p = que_state->front();
                que_state->pop();
                delete p;
                padding = 0;
                if(que_state->empty())
                {
                    std::lock_guard<std::mutex> lck(mtx_wait);
                    wait_doneman = true;
                    doneman = true;
                    cv_wait.notify_all();
                }
                continue;
            }
        }
        lock.unlock();

        PDATA_READ read = new DATA_READ;
        read->data = (BYTE*)memory::m_malloc(1048576);
        if(api::ReadFile(state->file->FileHandle, read->data, 1048576, &read->bytes) && read->bytes != 0)
        {
            if (read->bytes < 1048576 && que_state->front()->file->CryptInfo->method_policy == CryptoPolicy::AES256)
            {
                padding = read->bytes % 16;
                read->bytes -= padding;
            }

            {
                std::lock_guard<std::mutex> lck(mtx_encrypt);
                que_re->push(std::move(read));
            }
        }
        else
        {
            memory::m_free(read->data);
            delete read;
            state->read_doneman = true;
            state->start_read = false;
        }
        cv_encrypt.notify_one();
    }
}


void ThreadPipeLine::work_encrypt()
{
    while(true)
    {
        std::unique_lock<std::mutex> lock(mtx_encrypt);
        cv_encrypt.wait(lock, [this] 
        { 
            std::lock_guard<std::mutex> lck(mtx_state);
            return stop || (!que_state->empty() && que_state->front()->read_doneman);
        });
        if(stop) break;

        if(!que_re->empty())
        {
            PDATA_READ data = NULL;
            {
                data = std::move(que_re->front());
                que_re->pop();
            }
    
            if (que_state->front()->file->CryptInfo->gen_policy == GENKEY_EVERY_ONCE)
		        que_state->front()->file->CryptInfo->gen_key_method(que_state->front()->file->ctx, GLOBAL_KEYS.g_Key, GLOBAL_KEYS.g_IV);
            que_state->front()->file->CryptInfo->crypt_method(que_state->front()->file, que_state->front()->file->ctx, &que_state->front()->file->padding, data->data, data->data, data->bytes);
            
            lock.unlock();
            {
                std::lock_guard<std::mutex> lck(mtx_write);
                que_ew->push(std::move(data));
            }
        }
        else if(que_state->front()->read_doneman)
        {
            que_state->front()->encrypt_doneman = true;
        }
        cv_write.notify_one();
    }
}

void ThreadPipeLine::work_write()
{
    while(true)
    {
        std::unique_lock<std::mutex> lock(mtx_write);
        cv_write.wait(lock, [this] {
            std::lock_guard<std::mutex> lck(mtx_state);
            return stop || (!que_state->empty() && que_state->front()->encrypt_doneman);
        });

        if(stop) break;
        if(!que_ew->empty())
        {
            PDATA_READ data = NULL;
            {
                data = std::move(que_ew->front());
                que_ew->pop();
            }
            lock.unlock();
            
            filesystem::WriteFullData(que_state->front()->file->newFileHandle, data->data, data->bytes + padding);
            memory::m_free(data->data);
            delete data;
        }
        else if(!que_state->empty() && !que_state->front()->write_doneman)
        {
            que_state->front()->start_read = true;
            que_state->front()->write_doneman = true;
            cv_read.notify_one();
        }
    }
}

void ThreadPipeLine::wait()
{
    std::unique_lock<std::mutex> lock(mtx_wait);
    cv_wait.wait(lock, [this] { return wait_doneman || stop; });
}