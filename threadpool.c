/// Ex3 - Proxy Server: Elchanan Sasson - 208272625

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "threadpool.h"

/** create_threadpool creates a fixed-sized threadPool.
 * If the function succeeds, it returns a (non-NULL) "threadPool", else it returns NULL.
 */
threadpool *create_threadpool(int num_threads_in_pool) {
    if (num_threads_in_pool > MAXT_IN_POOL) {
        fprintf(stderr, "Illegal number of threads.\n");
        return NULL;
    }
    threadpool *tPool = (threadpool *) malloc(sizeof(threadpool));
    if (tPool == NULL) {
        fprintf(stderr, "Allocation failure: Memory allocation failed.\n");
        return NULL;
    }
    tPool->num_threads = num_threads_in_pool;
    tPool->qsize = 0;
    tPool->shutdown = 0;
    tPool->dont_accept = 0;
    tPool->qhead = NULL;
    tPool->qtail = NULL;
    if (pthread_mutex_init(&tPool->qlock, NULL) != 0) {
        fprintf(stderr, "init: mutex init failed.\n");
        return NULL;
    }
    if (pthread_cond_init(&tPool->q_empty, NULL) != 0) {
        fprintf(stderr, "init: cond init failed.\n");
        return NULL;
    }
    if (pthread_cond_init(&tPool->q_not_empty, NULL) != 0) {
        fprintf(stderr, "init: cond init failed.\n");
        return NULL;
    }
    tPool->threads = (pthread_t *) malloc(num_threads_in_pool * sizeof(pthread_t));
    if (tPool->threads == NULL) {
        fprintf(stderr, "Allocation failure: Memory allocation failed.\n");
        return NULL;
    }
    for (int i = 0; i < num_threads_in_pool; i++) {
        if (pthread_create(&tPool->threads[i], NULL, do_work, tPool) != 0) {
            perror("pthread_create: creat threads failed.\n");
            return NULL;
        }
    }
    return tPool;
}

/**
 * dispatch enter a "job" of type work_t into the queue.
 * when an available thread takes a job from the queue, it will
 * call the function "dispatch_to_here" with argument "arg".
 */
void dispatch(threadpool *from_me, dispatch_fn dispatch_to_here, void *arg) {
    pthread_mutex_lock(&from_me->qlock);
    if (from_me->dont_accept == 1) {
        pthread_mutex_unlock(&from_me->qlock);
        return;
    }
    pthread_mutex_unlock(&from_me->qlock);

    work_t *work = (work_t *) malloc(sizeof(work_t));
    if (work == NULL) {
        fprintf(stderr, "Allocation failure: Memory allocation failed.\n");
        exit(EXIT_FAILURE);
    }
    work->routine = dispatch_to_here;
    work->arg = arg;
    work->next = NULL;
    pthread_mutex_lock(&from_me->qlock);
    if (from_me->qhead == NULL) {
        from_me->qhead = work;
        from_me->qtail = work;
    } else {
        from_me->qtail->next = work;
        from_me->qtail = work;
    }
    from_me->qsize++;
    pthread_cond_signal(&from_me->q_not_empty);
    pthread_mutex_unlock(&from_me->qlock);
}

/// The work function of the thread.
void *do_work(void *p) {
    threadpool *tPool = (threadpool *) p;
    while (1) {
        pthread_mutex_lock(&tPool->qlock);
        if (tPool->shutdown == 1) {
            pthread_mutex_unlock(&tPool->qlock);
            return NULL;
        }
        if (tPool->qsize == 0) {
            pthread_cond_wait(&tPool->q_not_empty, &tPool->qlock);
        }
        if (tPool->shutdown == 1) {
            pthread_mutex_unlock(&tPool->qlock);
            return NULL;
        }
        work_t *workOut = tPool->qhead;
        if (workOut == NULL) {
            pthread_mutex_unlock(&tPool->qlock);
            continue;
        }
        tPool->qhead = tPool->qhead->next;
        tPool->qsize--;
        if (tPool->qsize == 0 && tPool->dont_accept == 1) {
            pthread_cond_signal(&tPool->q_empty);
        }
        pthread_mutex_unlock(&tPool->qlock);
        workOut->routine(workOut->arg);
        free(workOut);
    }
}

/**
 * destroy_threadPool kills the threadPool, causing all threads in it to commit suicide,
 * and then frees all the memory associated with the threadPool.
 */
void destroy_threadpool(threadpool *destroyme) {
    pthread_mutex_lock(&destroyme->qlock);
    destroyme->dont_accept = 1;
    if(destroyme->qsize != 0)
        pthread_cond_wait(&destroyme->q_empty, &destroyme->qlock);
    destroyme->shutdown = 1;
    pthread_cond_broadcast(&destroyme->q_not_empty);
    pthread_mutex_unlock(&destroyme->qlock);

    for (int i = 0; i < destroyme->num_threads; i++) {
        pthread_join(destroyme->threads[i], NULL);
    }
    pthread_mutex_destroy(&destroyme->qlock);
    pthread_cond_destroy(&destroyme->q_empty);
    pthread_cond_destroy(&destroyme->q_not_empty);
    free(destroyme->threads);
    free(destroyme);
}