// SPDX-License-Identifier: GPL-2.0
/*
 * Contains the core associated with submission side polling of the SQ
 * ring, offloading submissions from the application to a kernel thread.
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/audit.h>
#include <linux/security.h>
#include <linux/io_uring.h>
#include <linux/eventfd.h>
#include <uapi/linux/io_uring.h>
#include <linux/filter.h>
#include "io_uring.h"
#include "sqpoll.h"

#define IORING_SQPOLL_CAP_ENTRIES_VALUE 8

enum {
	IO_SQ_THREAD_SHOULD_STOP = 0,
	IO_SQ_THREAD_SHOULD_PARK,
};

void io_sq_thread_unpark(struct io_sq_data *sqd)
	__releases(&sqd->lock)
{
	WARN_ON_ONCE(sqd->thread == current);

	/*
	 * Do the dance but not conditional clear_bit() because it'd race with
	 * other threads incrementing park_pending and setting the bit.
	 */
	clear_bit(IO_SQ_THREAD_SHOULD_PARK, &sqd->state);
	if (atomic_dec_return(&sqd->park_pending))
		set_bit(IO_SQ_THREAD_SHOULD_PARK, &sqd->state);
	mutex_unlock(&sqd->lock);
}

void io_sq_thread_park(struct io_sq_data *sqd)
	__acquires(&sqd->lock)
{
	WARN_ON_ONCE(sqd->thread == current);

	atomic_inc(&sqd->park_pending);
	set_bit(IO_SQ_THREAD_SHOULD_PARK, &sqd->state);
	mutex_lock(&sqd->lock);
	if (sqd->thread)
		wake_up_process(sqd->thread);
}

void io_sq_thread_stop(struct io_sq_data *sqd)
{
	WARN_ON_ONCE(sqd->thread == current);
	WARN_ON_ONCE(test_bit(IO_SQ_THREAD_SHOULD_STOP, &sqd->state));

	set_bit(IO_SQ_THREAD_SHOULD_STOP, &sqd->state);
	mutex_lock(&sqd->lock);
	if (sqd->thread)
		wake_up_process(sqd->thread);
	mutex_unlock(&sqd->lock);
	wait_for_completion(&sqd->exited);
}

void io_put_sq_data(struct io_sq_data *sqd)
{
	if (refcount_dec_and_test(&sqd->refs)) {
		WARN_ON_ONCE(atomic_read(&sqd->park_pending));

		io_sq_thread_stop(sqd);
		kfree(sqd);
	}
}

static __cold void io_sqd_update_thread_idle(struct io_sq_data *sqd)
{
	struct io_ring_ctx *ctx;
	unsigned sq_thread_idle = 0;

	list_for_each_entry(ctx, &sqd->ctx_list, sqd_list)
		sq_thread_idle = max(sq_thread_idle, ctx->sq_thread_idle);
	sqd->sq_thread_idle = sq_thread_idle;
}

void io_sq_thread_finish(struct io_ring_ctx *ctx)
{
	struct io_sq_data *sqd = ctx->sq_data;

	if (sqd) {
		sqd->map = NULL;
		sqd->router = NULL;
		sqd->qemurouter = NULL;
		sqd->map_d = NULL;
		io_sq_thread_park(sqd);
		list_del_init(&ctx->sqd_list);
		io_sqd_update_thread_idle(sqd);
		io_sq_thread_unpark(sqd);

		io_put_sq_data(sqd);
		ctx->sq_data = NULL;
	}
}

static struct io_sq_data *io_attach_sq_data(struct io_uring_params *p)
{
	struct io_ring_ctx *ctx_attach;
	struct io_sq_data *sqd;
	struct fd f;

	f = fdget(p->wq_fd);
	if (!f.file)
		return ERR_PTR(-ENXIO);
	if (!io_is_uring_fops(f.file)) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}

	ctx_attach = f.file->private_data;
	sqd = ctx_attach->sq_data;
	if (!sqd) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}
	if (sqd->task_tgid != current->tgid) {
		fdput(f);
		return ERR_PTR(-EPERM);
	}

	refcount_inc(&sqd->refs);
	fdput(f);
	return sqd;
}

static struct io_sq_data *io_get_sq_data(struct io_uring_params *p,
					 bool *attached)
{
	struct io_sq_data *sqd;

	*attached = false;
	if (p->flags & IORING_SETUP_ATTACH_WQ) {
		sqd = io_attach_sq_data(p);
		if (!IS_ERR(sqd)) {
			*attached = true;
			return sqd;
		}
		/* fall through for EPERM case, setup new sqd/task */
		if (PTR_ERR(sqd) != -EPERM)
			return sqd;
	}

	sqd = kzalloc(sizeof(*sqd), GFP_KERNEL);
	if (!sqd)
		return ERR_PTR(-ENOMEM);

	atomic_set(&sqd->park_pending, 0);
	refcount_set(&sqd->refs, 1);
	INIT_LIST_HEAD(&sqd->ctx_list);
	mutex_init(&sqd->lock);
	init_waitqueue_head(&sqd->wait);
	init_completion(&sqd->exited);
	return sqd;
}

static inline bool io_sqd_events_pending(struct io_sq_data *sqd)
{
	return READ_ONCE(sqd->state);
}

static int __io_sq_thread(struct io_ring_ctx *ctx, bool cap_entries)
{
	unsigned int to_submit;
	int ret = 0;

	to_submit = io_sqring_entries(ctx);
	/* if we're handling multiple rings, cap submit size for fairness */
	if (cap_entries && to_submit > IORING_SQPOLL_CAP_ENTRIES_VALUE)
		to_submit = IORING_SQPOLL_CAP_ENTRIES_VALUE;

	if (!wq_list_empty(&ctx->iopoll_list) || to_submit) {
		const struct cred *creds = NULL;

		if (ctx->sq_creds != current_cred())
			creds = override_creds(ctx->sq_creds);

		mutex_lock(&ctx->uring_lock);
		if (!wq_list_empty(&ctx->iopoll_list))
			io_do_iopoll(ctx, true);

		/*
		 * Don't submit if refs are dying, good for io_uring_register(),
		 * but also it is relied upon by io_ring_exit_work()
		 */
		if (to_submit && likely(!percpu_ref_is_dying(&ctx->refs)) &&
		    !(ctx->flags & IORING_SETUP_R_DISABLED))
			ret = io_submit_sqes(ctx, to_submit);
		mutex_unlock(&ctx->uring_lock);

		if (to_submit && wq_has_sleeper(&ctx->sqo_sq_wait))
			wake_up(&ctx->sqo_sq_wait);
		if (creds)
			revert_creds(creds);
	}

	return ret;
}

static bool io_sqd_handle_event(struct io_sq_data *sqd)
{
	bool did_sig = false;
	struct ksignal ksig;

	if (test_bit(IO_SQ_THREAD_SHOULD_PARK, &sqd->state) ||
	    signal_pending(current)) {
		mutex_unlock(&sqd->lock);
		if (signal_pending(current))
			did_sig = get_signal(&ksig);
		cond_resched();
		mutex_lock(&sqd->lock);
	}
	return did_sig || test_bit(IO_SQ_THREAD_SHOULD_STOP, &sqd->state);
}
noinline int io_pop_evo(int vq_num, struct io_ring_ctx *ctx)
{
	int vq_num2;//meanless just a noop, in order to kprobe
	vq_num2 = vq_num;
	ctx->iobpf.vq_num = vq_num2;
	// printk("io_pop_evo is ok 2,nr_bpf_progs is %d\n",ctx->nr_bpf_progs);
	// printk("io_pop_evo the ctx addr is %lx\n",ctx);
	if(ctx->nr_bpf_progs>0)
	{
		bpf_prog_run(ctx->bpf_progs[0].prog, ctx);
	}
	return vq_num2;
}
// EXPORT_SYMBOL_GPL(io_pop_evo)

static int io_sq_thread(void *data)
{
	struct io_sq_data *sqd = data;
	struct io_ring_ctx *ctx;
	struct eventfd_ctx *eventfd;
	int *key;
	int vq_id;
	int vq_id2;
	int i=0;
	int err;
	u64 router;
	unsigned int router2=0;
	unsigned int temp;
	struct bpf_map *router_map;
	struct bpf_map *qemurouter_map;
	struct bpf_map *map_d;
	int vq_fd = 79;
	int router_fd;
	int Qemurouter_fd;
	int map_d_fd;
	unsigned long timeout = 0;
	char buf[TASK_COMM_LEN];
	u64 KVM_router;
	DEFINE_WAIT(wait);

	snprintf(buf, sizeof(buf), "iou-sqp-%d", sqd->task_pid);
	set_task_comm(current, buf);

	if (sqd->sq_cpu != -1)
		set_cpus_allowed_ptr(current, cpumask_of(sqd->sq_cpu));
	else
		set_cpus_allowed_ptr(current, cpu_online_mask);
	current->flags |= PF_NO_SETAFFINITY;

	mutex_lock(&sqd->lock);
	while (1) {
		bool cap_entries, sqt_spin = false;
		if (io_sqd_events_pending(sqd) || signal_pending(current)) {
			if (io_sqd_handle_event(sqd))
				break;
			timeout = jiffies + sqd->sq_thread_idle;
		}

		cap_entries = !list_is_singular(&sqd->ctx_list);
		list_for_each_entry(ctx, &sqd->ctx_list, sqd_list) {
			if(ctx->qemu.vqfd!=0)
				vq_fd = ctx->qemu.vqfd;
			temp = 0;
			KVM_router = 0;
			
			if(ctx->router_enable)
			{
				router = 0x0;
				vq_id = ctx->vqid;
				
				KVM_router = ctx->router->router;
				if(KVM_router>0)
				{
					
					router = KVM_router;
					
					ctx->router->router = 0;
					
				}
				
				//before proccess check whether has req to be processed
				ctx->qemu.qemu_router = 0;
				if(router>0)
				{	

					if(sqd->begin>0)
						sqd->begin--;
					ctx->qemu.begin = sqd->begin;
					vq_id2 =  io_pop_evo(ctx->vqid,ctx);
					
					if(ctx->qemu.qemu_router == 0) //after pop, check whether notiy qemu
					{
							eventfd = eventfd_ctx_fdget(vq_fd+ctx->vqid);
							if(eventfd)
								eventfd_signal_evo(eventfd,1);
							eventfd_ctx_put(eventfd);
					}
					// printk("vq is %d, router is %u\n",vq_id,router);
					ctx->qemu.qemu_router = 0;
					sqd->begin = ctx->qemu.begin;
				}				
				
			}


			// int ret = __io_sq_thread(ctx, cap_entries);

			// if (!sqt_spin && (ret > 0 || !wq_list_empty(&ctx->iopoll_list)))
			// 	sqt_spin = true;
		}
		if (io_run_task_work())
			sqt_spin = true;
		if (sqt_spin || !time_after(jiffies, timeout)) {
			cond_resched();
			if (sqt_spin)
				timeout = jiffies + sqd->sq_thread_idle;
			continue;
		}
		prepare_to_wait(&sqd->wait, &wait, TASK_INTERRUPTIBLE);
		if (!io_sqd_events_pending(sqd) && !task_work_pending(current)) {
			bool needs_sched = true;
			list_for_each_entry(ctx, &sqd->ctx_list, sqd_list) {
				atomic_or(IORING_SQ_NEED_WAKEUP,
						&ctx->rings->sq_flags);
				if ((ctx->flags & IORING_SETUP_IOPOLL) &&
				    !wq_list_empty(&ctx->iopoll_list)) {
					needs_sched = false;
					break;
				}

				/*
				 * Ensure the store of the wakeup flag is not
				 * reordered with the load of the SQ tail
				 */
				smp_mb__after_atomic();
				if (io_sqring_entries(ctx)) {
					needs_sched = false;
					break;
				}
			}
			if (needs_sched) {
				mutex_unlock(&sqd->lock);
				schedule();
				mutex_lock(&sqd->lock);
			}
			list_for_each_entry(ctx, &sqd->ctx_list, sqd_list)
				atomic_andnot(IORING_SQ_NEED_WAKEUP,
						&ctx->rings->sq_flags);
		}
		finish_wait(&sqd->wait, &wait);
		timeout = jiffies + sqd->sq_thread_idle;
	}

	io_uring_cancel_generic(true, sqd);
	sqd->thread = NULL;
	list_for_each_entry(ctx, &sqd->ctx_list, sqd_list)
		atomic_or(IORING_SQ_NEED_WAKEUP, &ctx->rings->sq_flags);
	io_run_task_work();
	mutex_unlock(&sqd->lock);

	complete(&sqd->exited);
	do_exit(0);
}

int io_sqpoll_wait_sq(struct io_ring_ctx *ctx)
{
	DEFINE_WAIT(wait);

	do {
		if (!io_sqring_full(ctx))
			break;
		prepare_to_wait(&ctx->sqo_sq_wait, &wait, TASK_INTERRUPTIBLE);

		if (!io_sqring_full(ctx))
			break;
		schedule();
	} while (!signal_pending(current));

	finish_wait(&ctx->sqo_sq_wait, &wait);
	return 0;
}

__cold int io_sq_offload_create(struct io_ring_ctx *ctx,
				struct io_uring_params *p)
{
	int ret;

	/* Retain compatibility with failing for an invalid attach attempt */
	if ((ctx->flags & (IORING_SETUP_ATTACH_WQ | IORING_SETUP_SQPOLL)) ==
				IORING_SETUP_ATTACH_WQ) {
		struct fd f;

		f = fdget(p->wq_fd);
		if (!f.file)
			return -ENXIO;
		if (!io_is_uring_fops(f.file)) {
			fdput(f);
			return -EINVAL;
		}
		fdput(f);
	}
	if (ctx->flags & IORING_SETUP_SQPOLL) {
		struct task_struct *tsk;
		struct io_sq_data *sqd;
		struct bpf_map *map;
		struct bpf_map *map_d;
		struct bpf_map *router;
		struct bpf_map *qemurouter;
		
		bool attached;

		ret = security_uring_sqpoll();
		if (ret)
			return ret;

		sqd = io_get_sq_data(p, &attached);
		if (IS_ERR(sqd)) {
			ret = PTR_ERR(sqd);
			goto err;
		}

		ctx->sq_creds = get_current_cred();
		ctx->sq_data = sqd;
		ctx->sq_thread_idle = msecs_to_jiffies(p->sq_thread_idle);
		if (!ctx->sq_thread_idle)
			ctx->sq_thread_idle = HZ;

		io_sq_thread_park(sqd);
		list_add(&ctx->sqd_list, &sqd->ctx_list);
		io_sqd_update_thread_idle(sqd);
		/* don't attach to a dying SQPOLL thread, would be racy */
		ret = (attached && !sqd->thread) ? -ENXIO : 0;
		io_sq_thread_unpark(sqd);

		if (ret < 0)
			goto err;
		if (attached)
			return 0;

		if (p->flags & IORING_SETUP_SQ_AFF) {
			int cpu = p->sq_thread_cpu;

			ret = -EINVAL;
			if (cpu >= nr_cpu_ids || !cpu_online(cpu))
				goto err_sqpoll;
			sqd->sq_cpu = cpu;
		} else {
			sqd->sq_cpu = -1;
		}
		
		if (p->map_fd==0)
		{
			printk("map_fd get error \n");
		}else
		{
			map = bpf_map_get(p->map_fd);
			if (IS_ERR(map))
			{
				printk("bpf get error \n");
			}
			if(map!=NULL)
			{
				sqd->map = map;
				
			}
		}
		if (p->router_fd==0)
		{
			printk("map_fd get error \n");
		}else
		{
			router = bpf_map_get(p->router_fd);
			if (IS_ERR(router))
			{
				printk("bpf get error \n");
			}
			if(router!=NULL)
			{
				sqd->router = router;
				
			}
		}
		if (p->qemurouter_fd==0)
		{
			printk("qemurouter_fd get error \n");
		}else
		{
			qemurouter = bpf_map_get(p->qemurouter_fd);
			if (IS_ERR(qemurouter))
			{
				printk("bpf get error \n");
			}
			if(qemurouter!=NULL)
			{
				sqd->qemurouter = qemurouter;
				
			}
		}
		if (p->map_d_fd==0)
		{
			printk("qemurouter_fd get error \n");
		}else
		{
			map_d = bpf_map_get(p->map_d_fd);
			if (IS_ERR(map_d))
			{
				printk("bpf get error \n");
			}
			if(map_d!=NULL)
			{
				sqd->map_d = map_d;
				
			}
		}
		sqd->begin = 500;
		sqd->task_pid = current->pid;
		sqd->task_tgid = current->tgid;
		if((p->map_fd!=0)||(p->map_d_fd!=0)||(p->router_fd!=0)||(p->qemurouter_fd!=0))
		{
			if(sqd->map==NULL||sqd->router==NULL||sqd->qemurouter==NULL||sqd->map_d==NULL)
				goto err_sqpoll;
		}
		
		printk("create_io_thread \n");
		tsk = create_io_thread(io_sq_thread, sqd, NUMA_NO_NODE);
		if (IS_ERR(tsk)) {
			ret = PTR_ERR(tsk);
			goto err_sqpoll;
		}

		sqd->thread = tsk;
		ret = io_uring_alloc_task_context(tsk, ctx);
		if(sqd->map!=NULL)
		{
			ctx->map = sqd->map;
		}
		if(sqd->map_d!=NULL)
		{
			ctx->map_d = sqd->map_d;
		}
		wake_up_new_task(tsk);
		if (ret)
			goto err;
	} else if (p->flags & IORING_SETUP_SQ_AFF) {
		/* Can't have SQ_AFF without SQPOLL */
		ret = -EINVAL;
		goto err;
	}

	return 0;
err_sqpoll:
	complete(&ctx->sq_data->exited);
err:
	io_sq_thread_finish(ctx);
	return ret;
}
