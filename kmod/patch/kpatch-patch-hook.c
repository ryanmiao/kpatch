/*
 * Copyright (C) 2013-2014 Josh Poimboeuf <jpoimboe@redhat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA,
 * 02110-1301, USA.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include "kpatch.h"

static bool replace;
module_param(replace, bool, S_IRUGO);
MODULE_PARM_DESC(replace, "replace all previously loaded patch modules");

extern char __kpatch_patches, __kpatch_patches_end;

static struct kpatch_module kpmod;
static struct kobject *patch_kobj;
static struct kobject *funcs_kobj;

struct kpatch_attribute {
	struct kobj_attribute attr;
	struct kpatch_patch kaddr;
	char name[KSYM_NAME_LEN];
};

static ssize_t patch_enabled_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", kpmod.enabled);
}

static ssize_t patch_enabled_store(struct kobject *kobj,
				   struct kobj_attribute *attr, const char *buf,
				   size_t count)
{
	int ret;
	unsigned long val;

	/* only disabling is supported */
	if (!kpmod.enabled)
		return -EINVAL;

	ret = kstrtoul(buf, 10, &val);
	if (ret)
		return ret;

	val = !!val;

	/* only disabling is supported */
	if (val)
		return -EINVAL;

	ret = kpatch_unregister(&kpmod);
	if (ret)
		return ret;

	return count;
}

static ssize_t patch_func_show(struct kobject *kobj,
			 struct kobj_attribute *attr, char *buf)
{
	int i;
	int ret = 0;
	struct kpatch_func *func = kpmod.funcs;

	struct kpatch_attribute *pkattr = 
		container_of(attr, struct kpatch_attribute, attr);

	if (pkattr && pkattr->name) {
		ret = snprintf(buf, PAGE_SIZE, "%s\t0x%lx\t0x%lx\n",
			       pkattr->name, pkattr->kaddr.old_addr,
			       pkattr->kaddr.new_addr);
	} else {
		ret = snprintf(buf, PAGE_SIZE,
			       "Failed to fetch kpatch_attribute\n");
	}

	return ret;
}

static struct kpatch_attribute patch_enabled_attr;

static struct kpatch_attribute *patch_funcs_attr = NULL;

static int __init patch_init(void)
{
	struct kpatch_patch *patches;
	int ret;

	kpmod.mod = THIS_MODULE;
	kpmod.patches = (struct kpatch_patch *)&__kpatch_patches;
	kpmod.patches_nr = (&__kpatch_patches_end - &__kpatch_patches) /
			  sizeof(*patches);
	kpmod.funcs = kzalloc(kpmod.num_funcs * sizeof(struct kpatch_func),
			      GFP_KERNEL);
	if (!kpmod.funcs)
		return -ENOMEM;

	patch_enabled_attr.attr.show = patch_enabled_show;
	patch_enabled_attr.attr.store = patch_enabled_store;
	strncpy(patch_enabled_attr.name, "enabled", KSYM_NAME_LEN);
	patch_enabled_attr.attr.attr.mode = S_IWUSR | S_IRUGO;
	patch_enabled_attr.attr.attr.name = patch_enabled_attr.name;

	patch_funcs_attr = kzalloc(kpmod.num_funcs * 
				  sizeof(struct kpatch_attribute), GFP_KERNEL);
	if (!patch_funcs_attr) {
		ret = -ENOMEM;
		goto err_free;
	}

	patch_kobj = kobject_create_and_add(THIS_MODULE->name,
					    kpatch_patches_kobj);
	if (!patch_kobj) {
		ret = -ENOMEM;
		goto err_free;
	}

	funcs_kobj = kobject_create_and_add("funcs", patch_kobj);
	if (!funcs_kobj) {
		ret = -ENOMEM;
		goto err_free;
	}

	ret = sysfs_create_file(patch_kobj, &patch_enabled_attr.attr.attr);
	if (ret)
		goto err_put;

	for (i = 0; i < kpmod.num_funcs; i++) {
		kpmod.funcs[i].old_addr = patches[i].old_addr;
		kpmod.funcs[i].old_size = patches[i].old_size;
		kpmod.funcs[i].new_addr = patches[i].new_addr;
		kpmod.funcs[i].new_size = patches[i].new_size;

		sprint_symbol_no_offset(patch_funcs_attr[i].name,
					patches[i].old_addr);
		patch_funcs_attr[i].attr.show = patch_func_show;
		patch_funcs_attr[i].attr.attr.mode = S_IRUGO;
		patch_funcs_attr[i].attr.attr.name = patch_funcs_attr[i].name;
		patch_funcs_attr[i].kaddr.old_addr = patches[i].old_addr;
		patch_funcs_attr[i].kaddr.old_size = patches[i].old_size;
		patch_funcs_attr[i].kaddr.new_addr = patches[i].new_addr;
		patch_funcs_attr[i].kaddr.new_size = patches[i].new_size;

		ret = sysfs_create_file(funcs_kobj,
					&patch_funcs_attr[i].attr.attr);
		if (ret)
			goto err_put2;
	}

	ret = kpatch_register(&kpmod, replace);
	if (ret)
		goto err_sysfs;

	return 0;

err_sysfs:
	sysfs_remove_file(patch_kobj, &patch_enabled_attr.attr.attr);
err_put2:
	for (i--; i >= 0; i--) {
	        sysfs_remove_file(funcs_kobj,
				  &patch_funcs_attr[i].attr.attr);
	}
	kobject_put(funcs_kobj);
err_put:
	kobject_put(patch_kobj);
err_free:
	kfree(patch_funcs_attr);
	kfree(kpmod.funcs);
	return ret;
}

static void __exit patch_exit(void)
{
	int i;
	WARN_ON(kpmod.enabled);
	for (i = 0; i < kpmod.num_funcs; i++) {
	        sysfs_remove_file(funcs_kobj, &patch_funcs_attr[i].attr.attr);
	}
	kobject_put(funcs_kobj);
	sysfs_remove_file(patch_kobj, &patch_enabled_attr.attr.attr);
	kobject_put(patch_kobj);
	kfree(patch_funcs_attr);
	kfree(kpmod.funcs);
}

module_init(patch_init);
module_exit(patch_exit);
MODULE_LICENSE("GPL");
