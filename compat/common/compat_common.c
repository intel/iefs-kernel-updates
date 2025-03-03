// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright(c) 2020 - 2021 Intel Corporation.
 */

#include "compat.h"

/* Returns the ib_uobject or an error. The caller should check for IS_ERR. */
static struct ib_uobject *
lookup_get_idr_uobject(const struct uverbs_api_object *obj,
                       struct ib_uverbs_file *ufile, s64 id,
                       enum rdma_lookup_mode mode)
{
        struct ib_uobject *uobj;
#ifndef UVERBS_FILE_HAVE_XARRAY_IDR
        unsigned long idrno = id;
#endif

	if (id < 0)
                return ERR_PTR(-EINVAL);

        rcu_read_lock();
        /* object won't be released as we're protected in rcu */
#ifndef UVERBS_FILE_HAVE_XARRAY_IDR
        uobj = idr_find(&ufile->idr, idrno);
#else
	uobj = xa_load(&ufile->idr, id);
#endif
        if (!uobj) {
                uobj = ERR_PTR(-ENOENT);
                goto free;
        }

        /*
         * The idr_find is guaranteed to return a pointer to something that
         * isn't freed yet, or NULL, as the free after idr_remove goes through
         * kfree_rcu(). However the object may still have been released and
         * kfree() could be called at any time.
         */
        if (!kref_get_unless_zero(&uobj->ref))
                uobj = ERR_PTR(-ENOENT);

free:
        rcu_read_unlock();
        return uobj;
}

static int uverbs_try_lock_object(struct ib_uobject *uobj,
                                  enum rdma_lookup_mode mode)
{
        /*
         * When a shared access is required, we use a positive counter. Each
         * shared access request checks that the value != -1 and increment it.
         * Exclusive access is required for operations like write or destroy.
         * In exclusive access mode, we check that the counter is zero (nobody
         * claimed this object) and we set it to -1. Releasing a shared access
         * lock is done simply by decreasing the counter. As for exclusive
         * access locks, since only a single one of them is is allowed
         * concurrently, setting the counter to zero is enough for releasing
         * this lock.
         */
        switch (mode) {
        case UVERBS_LOOKUP_READ:
#ifdef HAVE_ATOMIC_FETCH_ADD_UNLESS
		return atomic_fetch_add_unless(&uobj->usecnt, 1, -1) == -1 ?
#else
                return __atomic_add_unless(&uobj->usecnt, 1, -1) == -1 ?
#endif
                        -EBUSY : 0;
        case UVERBS_LOOKUP_WRITE:
                /* lock is exclusive */
                return atomic_cmpxchg(&uobj->usecnt, 0, -1) == 0 ? 0 : -EBUSY;
        case UVERBS_LOOKUP_DESTROY:
                return 0;
        }
        return 0;
}

static void uverbs_uobject_free(struct kref *ref)
{
        struct ib_uobject *uobj =
                container_of(ref, struct ib_uobject, ref);

#ifdef TYPE_CLASS_NO_NEEDS_KFREE_RCU
		kfree_rcu(uobj, rcu);
#else
        if (uobj->uapi_object->type_class->needs_kfree_rcu)
                kfree_rcu(uobj, rcu);
        else
                kfree(uobj);
#endif
}

void uverbs_uobject_put(struct ib_uobject *uobject)
{
        kref_put(&uobject->ref, uverbs_uobject_free);
}

struct ib_uobject *rdma_lookup_get_uobject(const struct uverbs_api_object *obj,
                                           struct ib_uverbs_file *ufile, s64 id,
#ifndef RDMA_LOOKUP_GET_UOBJECT_HAVE_ATTR
                                           enum rdma_lookup_mode mode)
#else
					   enum rdma_lookup_mode mode,
					   struct uverbs_attr_bundle *attrs)
#endif
{
        struct ib_uobject *uobj;
        int ret;

        if (IS_ERR(obj) && PTR_ERR(obj) == -ENOMSG) {
                /* must be UVERBS_IDR_ANY_OBJECT, see uapi_get_object() */
                uobj = lookup_get_idr_uobject(NULL, ufile, id, mode);
                if (IS_ERR(uobj))
                        return uobj;
        } else {
                if (IS_ERR(obj))
                        return ERR_PTR(-EINVAL);

                uobj = obj->type_class->lookup_get(obj, ufile, id, mode);
                if (IS_ERR(uobj))
                        return uobj;

                if (uobj->uapi_object != obj) {
                        ret = -EINVAL;
                        goto free;
                }
        }

        /*
         * If we have been disassociated block every command except for
         * DESTROY based commands.
         */
        if (mode != UVERBS_LOOKUP_DESTROY &&
            !srcu_dereference(ufile->device->ib_dev,
                              &ufile->device->disassociate_srcu)) {
                ret = -EIO;
                goto free;
        }

        ret = uverbs_try_lock_object(uobj, mode);
        if (ret)
                goto free;
#ifdef RDMA_LOOKUP_GET_UOBJECT_HAVE_ATTR
	if (attrs)
		attrs->context = uobj->context;
#endif

        return uobj;
free:

        uobj->uapi_object->type_class->lookup_put(uobj, mode);
        uverbs_uobject_put(uobj);
        return ERR_PTR(ret);
}

static void assert_uverbs_usecnt(struct ib_uobject *uobj,
                                 enum rdma_lookup_mode mode)
{
#ifdef CONFIG_LOCKDEP
        switch (mode) {
        case UVERBS_LOOKUP_READ:
                WARN_ON(atomic_read(&uobj->usecnt) <= 0);
                break;
        case UVERBS_LOOKUP_WRITE:
                WARN_ON(atomic_read(&uobj->usecnt) != -1);
                break;
        case UVERBS_LOOKUP_DESTROY:
                break;
        }
#endif
}

void rdma_lookup_put_uobject(struct ib_uobject *uobj,
                             enum rdma_lookup_mode mode)
{
        assert_uverbs_usecnt(uobj, mode);
        /*
         * In order to unlock an object, either decrease its usecnt for
         * read access or zero it in case of exclusive access. See
         * uverbs_try_lock_object for locking schema information.
         */
        switch (mode) {
        case UVERBS_LOOKUP_READ:
                atomic_dec(&uobj->usecnt);
                break;
        case UVERBS_LOOKUP_WRITE:
                atomic_set(&uobj->usecnt, 0);
                break;
        case UVERBS_LOOKUP_DESTROY:
                break;
        }

        uobj->uapi_object->type_class->lookup_put(uobj, mode);
        /* Pairs with the kref obtained by type->lookup_get */
        uverbs_uobject_put(uobj);
}

#if !defined(HAVE_XARRAY) && !defined(HAVE_MOFED)
int xa_alloc_irq(struct xarray *xa, u32 *id,
		 void *entry, struct xa_limit limit, gfp_t gfp)
{
	int ret = 0;
	unsigned long flags;

	idr_preload(GFP_KERNEL);
	spin_lock_irqsave(&xa->lock, flags);

	ret = idr_alloc(&xa->table, entry, limit.min, limit.max, gfp);
	if (ret >= 0) {
		*id = ret;
		/* xa_alloc_irq returns 0 for success */
		ret = 0;
	}

	spin_unlock_irqrestore(&xa->lock, flags);
	idr_preload_end();
	return ret;
}
EXPORT_SYMBOL(xa_alloc_irq);
#endif
