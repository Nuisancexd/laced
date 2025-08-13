#include "threadpool.h"
#include "api.h"
#include "filesystem.h"
#include "memory.h"

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

PipeLineEncrypt::PipeLineEncrypt()
{

    PTHREADS mark1 = new THREADS;
    mark1->thread = std::jthread(&PipeLineEncrypt::work_read, this);
    work->LIST_INSERT_HEAD(mark1);

    PTHREADS mark2 = new THREADS;
    mark2->thread = std::jthread(&PipeLineEncrypt::work_encrypt, this);
    work->LIST_INSERT_HEAD(mark2);

    PTHREADS mark3 = new THREADS;
    mark3->thread = std::jthread(&PipeLineEncrypt::work_write, this);
    work->LIST_INSERT_HEAD(mark3);
}

PipeLineEncrypt::~PipeLineEncrypt()
{
    stop = true;
    cv_read.notify_all();
    cv_encrypt.notify_all();
    cv_write.notify_all();
    cv_wait.notify_all();
    THREADS* thread = NULL;
    LIST_FOREACH(thread, work)
        thread->thread.join();

    delete work;
}

VOID PipeLineEncrypt::INIT(PFILE_INFO a_FileInfo)
{
    done_man = 0;
    rsize = 0;
    esize = 0;
    wsize = 0;
    FileInfo = a_FileInfo;
    start_read = true;
    cv_read.notify_one();
}

VOID PipeLineEncrypt::work_read()
{
    while (!stop)
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv_read.wait(lock, [this] { return start_read || stop; });
        if (stop) break;
        lock.unlock();

        size_t BytesRead;
        auto read = std::make_shared<DATA_READ>();
        read->data = (BYTE*)memory::m_malloc(100);
        if (api::ReadFile(FileInfo->FileHandle, read->data, 100, &BytesRead) && BytesRead != 0)
        {
            read->BytesRead = BytesRead;
            {
                std::lock_guard<std::mutex> lck(mtx);
                read_que.push(read);
                ++rsize;
            }
            cv_encrypt.notify_one();
        }
        else
        {
            start_read = false;
            read_done = true;
            printf("DONEMAN_READ\n");
            done_man.fetch_add(1);
        }

    }
}

VOID PipeLineEncrypt::work_encrypt()
{
    while (!stop)
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv_encrypt.wait(lock, [this] { return !read_que.empty() || stop; });
        if (stop) break;
        ++esize;
        if (read_done && esize == rsize)
        {
            done_man.fetch_add(1);
            printf("DONEMAN_CRYPT\t%u\n", done_man.load());
            cv_write.notify_all();
            cv_wait.notify_all();
        }

        auto data = read_que.front();
        read_que.pop();
        lock.unlock();


        FileInfo->CryptInfo->crypt_method(FileInfo, FileInfo->ctx, &FileInfo->padding, data->data, data->data, data->BytesRead);
        {
            std::lock_guard<std::mutex> lock(mtx);
            encrypt_que.push(data);
        }

        cv_write.notify_one();
    }
}

VOID PipeLineEncrypt::work_write()
{
    while (!stop)
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv_write.wait(lock, [this] { return !encrypt_que.empty() || stop; });
        if (stop) break;

        ++wsize;
        if (read_done && wsize == rsize)
        {
            done_man.fetch_add(1);
            printf("DONEMAN\t%u\n", done_man.load());
            cv_wait.notify_all();
        }


        auto data = encrypt_que.front();
        encrypt_que.pop();
        lock.unlock();


        DWORD written;
        filesystem::WriteFullData(FileInfo->newFileHandle, data->data, data->BytesRead);
    }
}

VOID PipeLineEncrypt::wait()
{
    std::unique_lock<std::mutex> lock(mtx);
    cv_wait.wait(lock, [this] { return done_man == 3 || stop; });
}