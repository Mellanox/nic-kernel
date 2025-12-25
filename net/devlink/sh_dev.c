// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#include <linux/device/faux.h>
#include <net/devlink.h>

#include "devl_internal.h"

static LIST_HEAD(shd_list);
static DEFINE_MUTEX(shd_mutex); /* Protects shd_list and shd->list */

/* This structure represents a shared devlink instance,
 * there is one created per identifier (e.g., serial number).
 */
struct devlink_shd {
	/* Node in shd list */
	struct list_head list;
	/* Identifier string (e.g., serial number) */
	const char *id;
	/* List of per-device instances */
	struct list_head dev_list;
	/* Related faux device */
	struct faux_device *faux_dev;
	/* Driver private data */
	char priv[] __aligned(NETDEV_ALIGN);
};

static struct devlink_shd *devlink_shd_lookup(const char *id)
{
	struct devlink_shd *shd;

	list_for_each_entry(shd, &shd_list, list) {
		if (!strcmp(shd->id, id))
			return shd;
	}

	return NULL;
}

static struct devlink_shd *devlink_shd_create(const char *id,
					      const struct devlink_ops *ops,
					      size_t priv_size)
{
	struct faux_device *faux_dev;
	struct devlink_shd *shd;
	struct devlink *devlink;

	/* Create faux device - probe will be called synchronously */
	faux_dev = faux_device_create(id, NULL, NULL);
	if (!faux_dev)
		return NULL;

	devlink = devlink_alloc(ops, sizeof(struct devlink_shd) + priv_size,
				&faux_dev->dev);
	if (!devlink) {
		faux_device_destroy(faux_dev);
		return NULL;
	}
	shd = devlink_priv(devlink);

	shd->id = kstrdup(id, GFP_KERNEL);
	if (!shd->id) {
		devlink_free(devlink);
		faux_device_destroy(faux_dev);
		return NULL;
	}
	INIT_LIST_HEAD(&shd->dev_list);
	shd->faux_dev = faux_dev;

	devl_lock(devlink);
	devl_register(devlink);
	devl_unlock(devlink);

	list_add_tail(&shd->list, &shd_list);

	return shd;
}

static void devlink_shd_destroy(struct devlink_shd *shd)
{
	struct devlink *devlink = priv_to_devlink(shd);
	struct faux_device *faux_dev = shd->faux_dev;

	list_del(&shd->list);
	devl_lock(devlink);
	devl_unregister(devlink);
	devl_unlock(devlink);
	kfree(shd->id);
	devlink_free(devlink);
	faux_device_destroy(faux_dev);
}

/**
 * devlink_shd_get - Get or create a shared devlink instance
 * @id: Identifier string (e.g., serial number) for the shared instance
 * @ops: Devlink operations structure
 * @priv_size: Size of private data structure
 * @owner: Owner structure embedded in the device (contains list node)
 *
 * Gets an existing shared devlink instance identified by @id, or creates
 * a new one if it doesn't exist. The device is automatically added to
 * the shared instance's device list via @owner. Returns the devlink instance
 * with a reference held. The caller must call devlink_shd_put() when done.
 *
 * Return: Pointer to the shared devlink instance on success,
 *         NULL on failure
 */
struct devlink *devlink_shd_get(const char *id,
				const struct devlink_ops *ops,
				size_t priv_size,
				struct devlink_shd_owner *owner)
{
	struct devlink_shd *shd;

	if (WARN_ON(!id || !ops || !owner))
		return NULL;

	mutex_lock(&shd_mutex);

	/* Try to find existing instance */
	shd = devlink_shd_lookup(id);
	if (shd)
		goto found;

	/* Create new instance */
	shd = devlink_shd_create(id, ops, priv_size);
	if (!shd)
		goto unlock;

found:
	list_add_tail(&owner->list, &shd->dev_list);

unlock:
	mutex_unlock(&shd_mutex);
	return priv_to_devlink(shd);
}
EXPORT_SYMBOL_GPL(devlink_shd_get);

/**
 * devlink_shd_put - Release a reference on a shared devlink instance
 * @devlink: Shared devlink instance
 * @owner: Owner structure embedded in the device (contains list node)
 *
 * Removes the device from the shared instance's device list via @owner and
 * releases a reference on a shared devlink instance obtained via
 * devlink_shd_get().
 */
void devlink_shd_put(struct devlink *devlink, struct devlink_shd_owner *owner)
{
	struct devlink_shd *shd;

	if (WARN_ON(!devlink || !owner))
		return;

	mutex_lock(&shd_mutex);
	shd = devlink_priv(devlink);
	list_del(&owner->list);
	if (list_empty(&shd->dev_list))
		devlink_shd_destroy(shd);
	mutex_unlock(&shd_mutex);
}
EXPORT_SYMBOL_GPL(devlink_shd_put);

/**
 * devlink_shd_get_priv - Get private data from shared devlink instance
 * @devlink: Devlink instance
 *
 * Returns a pointer to the driver's private data structure within
 * the shared devlink instance.
 *
 * Return: Pointer to private data
 */
void *devlink_shd_get_priv(struct devlink *devlink)
{
	struct devlink_shd *shd = devlink_priv(devlink);

	return shd->priv;
}
EXPORT_SYMBOL_GPL(devlink_shd_get_priv);
