// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright(c) 2020 Intel Corporation.
 */

/* This file contains the base of the rendezvous RDMA driver */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/parser.h>

#include <rdma/ib_user_sa.h>

#include "rv.h"
#include "trace.h"

MODULE_AUTHOR("Kaike Wan");
MODULE_DESCRIPTION("Rendezvous Kmod");
MODULE_LICENSE("Dual BSD/GPL");

static void rv_add_one(struct ib_device *device);
static void rv_remove_one(struct ib_device *device, void *client_data);
#ifdef HAS_DEV_RENAME  /* currently only upstream */
static void rv_rename_dev(struct ib_device *device, void *client_data);
#endif

static struct ib_client rv_client = {
	.name = "rv",
	.add = rv_add_one,
	.remove = rv_remove_one,
#ifdef HAS_DEV_RENAME  /* currently only upstream */
	.rename = rv_rename_dev
#endif
};

static struct list_head rv_dev_list;	/* list of rv_device */
static spinlock_t rv_dev_list_lock;

struct rv_device *rv_device_get(char *dev_name, struct rv_user *rv)
{
	struct rv_device *dev;
	unsigned long flags;

	spin_lock_irqsave(&rv_dev_list_lock, flags);
	list_for_each_entry(dev, &rv_dev_list, dev_entry) {
		if (strcmp(dev->ib_dev->name, dev_name) == 0) {
			if (!kref_get_unless_zero(&dev->kref))
				continue; /* skip, going away */
			list_add_tail(&rv->user_entry, &dev->user_list);
			spin_unlock_irqrestore(&rv_dev_list_lock, flags);
			trace_rv_dev_get(dev_name, kref_read(&dev->kref));
			return dev;
		}
	}
	spin_unlock_irqrestore(&rv_dev_list_lock, flags);
	rv_err(RV_INVALID, "Could not find IB dev %s\n", dev_name);
	return NULL;
}

static void rv_device_release(struct kref *kref)
{
	struct rv_device *dev = container_of(kref, struct rv_device, kref);

	ib_unregister_event_handler(&dev->event_handler); /* may need sooner */
	kfree(dev);
}

void rv_device_put(struct rv_device *dev)
{
	trace_rv_dev_put((dev->ib_dev && dev->ib_dev->name) ?
			 dev->ib_dev->name : "nil", kref_read(&dev->kref));
	kref_put(&dev->kref, rv_device_release);
}

/*
 * Remove a rv_user from rv_device.user_list
 *
 * @rv - The rv_user to remove
 *
 * Return:
 *   0 - The rv_user is in rv_device.user_list and removed;
 *   1 - The rv_user is already not in rv_device.user_list.
 */
int rv_device_del_user(struct rv_user *rv)
{
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&rv_dev_list_lock, flags);
	if (list_empty(&rv->user_entry))
		ret = 1;
	else
		list_del_init(&rv->user_entry);
	spin_unlock_irqrestore(&rv_dev_list_lock, flags);

	return ret;
}

/* verbs device level async events */
static void rv_device_event_handler(struct ib_event_handler *handler,
				    struct ib_event *event)
{
	struct rv_device *dev;

	dev = ib_get_client_data(event->device, &rv_client);
	if (!dev || dev->ib_dev != event->device)
		return;

	trace_rv_device_event(dev->ib_dev->name, ib_event_msg(event->event));
	switch (event->event) {
	case IB_EVENT_DEVICE_FATAL:
	case IB_EVENT_PORT_ERR:
	case IB_EVENT_PORT_ACTIVE:
	case IB_EVENT_LID_CHANGE:
	case IB_EVENT_PKEY_CHANGE:
	case IB_EVENT_SM_CHANGE:
	case IB_EVENT_CLIENT_REREGISTER:
	case IB_EVENT_GID_CHANGE:
	default:
		break;
	}
}

static void rv_add_one(struct ib_device *device)
{
	struct rv_device *dev;
	unsigned long flags;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		rv_ptr_err("ib_device", device,
			   "Failed to alloc memory for %s\n",  device->name);
		return;
	}
	dev->ib_dev = device;
	kref_init(&dev->kref);
	mutex_init(&dev->listener_mutex);
	spin_lock_init(&dev->listener_lock);
	INIT_LIST_HEAD(&dev->listener_list);
	INIT_LIST_HEAD(&dev->user_list);
	spin_lock_irqsave(&rv_dev_list_lock, flags);
	list_add(&dev->dev_entry, &rv_dev_list);
	spin_unlock_irqrestore(&rv_dev_list_lock, flags);
	trace_rv_dev_add(device->name, kref_read(&dev->kref));
	ib_set_client_data(device, &rv_client, dev);

	INIT_IB_EVENT_HANDLER(&dev->event_handler, device,
			      rv_device_event_handler);
	ib_register_event_handler(&dev->event_handler);

	return;
}

static void rv_device_detach_users(struct rv_device *dev)
{
	unsigned long flags;
	struct rv_user *rv;

	spin_lock_irqsave(&rv_dev_list_lock, flags);
	while (!list_empty(&dev->user_list)) {
		rv = list_first_entry(&dev->user_list, struct rv_user,
				      user_entry);
		/*
		 * Remove the rv_user from the user_list so that the user
		 * application knows that the remove_one handler is cleaning
		 * up this rv_user. After this, the rv->user_entry itself is
		 * an empty list, an indicator that the remove_one handler
		 * owns this rv_user.
		 */
		list_del_init(&rv->user_entry);

		/*
		 * Since we can't take the rv->mutex after holding
		 * rv_dev_list_lock, we have to release it first.
		 * Since the user application knows that the remove_one handler
		 * owns the rv_user, there is no risk that the user application
		 * will detach it.
		 */
		spin_unlock_irqrestore(&rv_dev_list_lock, flags);

		/* Release resources */
		rv_detach_user(rv);

		/* Acquire the rv_dev_list_lock again for next rv_user */
		spin_lock_irqsave(&rv_dev_list_lock, flags);
	}
	spin_unlock_irqrestore(&rv_dev_list_lock, flags);
}

static void rv_remove_one(struct ib_device *device, void *client_data)
{
	struct rv_device *dev = client_data;
	unsigned long flags;
	unsigned long wait_time = 2000; /* 2 seconds */
	unsigned long sleep_time = msecs_to_jiffies(100);
	unsigned long end;

	trace_rv_dev_remove(device->name, kref_read(&dev->kref));
	/*
	 * Remove the device from the device list so that no new rv_user
	 * can be attached to it.
	 */
	spin_lock_irqsave(&rv_dev_list_lock, flags);
	list_del(&dev->dev_entry);
	spin_unlock_irqrestore(&rv_dev_list_lock, flags);

	/*
	 * Wait for some time so that the user applications can finish their
	 * cleanup after receiving the port_down notification.
	 */
	end = jiffies + msecs_to_jiffies(wait_time);
	while (time_before(jiffies, end) && !list_empty(&dev->user_list))
		schedule_timeout_interruptible(sleep_time);

	/* We have to remove any remaining rv_users */
	rv_device_detach_users(dev);

	/* Wait until all resources are released */
	while (kref_read(&dev->kref) > 1)
		schedule_timeout_interruptible(sleep_time);

	/* Finally free the device */
	rv_device_put(dev);
}

#ifdef HAS_DEV_RENAME  /* currently only upstream */
static void rv_rename_dev(struct ib_device *device, void *client_data)
{
	return;
}
#endif

static void rv_init_devices(void)
{
	spin_lock_init(&rv_dev_list_lock);
	INIT_LIST_HEAD(&rv_dev_list);
}

static void rv_deinit_devices(void)
{
	struct rv_device *dev, *temp;
	unsigned long flags;

	synchronize_rcu(); /* make sure previous kfree_rcu have completed */
	spin_lock_irqsave(&rv_dev_list_lock, flags);
	list_for_each_entry_safe(dev, temp, &rv_dev_list, dev_entry) {
		list_del(&dev->dev_entry);
		rv_device_put(dev);
	}
	spin_unlock_irqrestore(&rv_dev_list_lock, flags);
}

static int __init rv_init_module(void)
{

	pr_info("Loading rendezvous module");

	rv_init_devices();

	if (ib_register_client(&rv_client)) {
		rv_err(RV_INVALID, "Failed to register with the IB core\n");
		return -EINVAL;
	}

	if (rv_file_init()) {
		ib_unregister_client(&rv_client);
		return -EINVAL;
	}
	return 0;
}

static void __exit rv_cleanup_module(void)
{
	rv_file_uninit();
	ib_unregister_client(&rv_client);
	rv_deinit_devices();
}

module_init(rv_init_module);
module_exit(rv_cleanup_module);
