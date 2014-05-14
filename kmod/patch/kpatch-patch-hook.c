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

struct kpatch_func_obj {
	struct kobject *func_kobj;
	struct kobj_attribute old_addr_attr;
	struct kobj_attribute new_addr_attr;
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

static struct kobj_attribute patch_enabled_attr =
	__ATTR(enabled, 0644, patch_enabled_show, patch_enabled_store);

static ssize_t patch_old_addr_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	int ret = -EIO;

	struct kpatch_func_obj *pfunc =
		container_of(attr, struct kpatch_func_obj, old_addr_attr);

	if (pfunc)
		ret = sprintf(buf, "0x%lx\n", pfunc->kaddr.old_addr);

	return ret;
}

static ssize_t patch_new_addr_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	int ret = -EIO;

	struct kpatch_func_obj *pfunc =
		container_of(attr, struct kpatch_func_obj, new_addr_attr);

	if (pfunc)
		ret = sprintf(buf, "0x%lx\n", pfunc->kaddr.new_addr);

	return ret;
}

static struct kpatch_func_obj *patch_funcs = NULL;

static int __init patch_init(void)
{
	int ret;
	int i = 0, j = 0;
	struct kobject *func_tmp;
	struct kobj_attribute old_addr_attr =
		__ATTR(old_addr, S_IRUGO, patch_old_addr_show, NULL);
	struct kobj_attribute new_addr_attr =
		__ATTR(new_addr, S_IRUGO, patch_new_addr_show, NULL);

	kpmod.mod = THIS_MODULE;
	kpmod.patches = (struct kpatch_patch *)&__kpatch_patches;
	kpmod.patches_nr = (&__kpatch_patches_end - &__kpatch_patches) /
			    sizeof(struct kpatch_patch);

	patch_funcs = kzalloc(kpmod.patches_nr * sizeof(struct kpatch_func_obj),
			      GFP_KERNEL);
	if (!patch_funcs) {
		ret = -ENOMEM;
		goto err_free;
	}

	patch_kobj = kobject_create_and_add(THIS_MODULE->name,
					    kpatch_patches_kobj);
	if (!patch_kobj) {
		ret = -ENOMEM;
		goto err_free;
	}

	ret = sysfs_create_file(patch_kobj, &patch_enabled_attr.attr);
	if (ret)
		goto err_put;

	funcs_kobj = kobject_create_and_add("functions", patch_kobj);
	if (!funcs_kobj) {
		ret = -ENOMEM;
		goto err_sysfs;
	}

	for (i = 0; i < kpmod.patches_nr; i++) {
		sprint_symbol_no_offset(patch_funcs[i].name,
					kpmod.patches[i].old_addr);
		func_tmp = kobject_create_and_add(patch_funcs[i].name,
						  funcs_kobj);
		if (!func_tmp) {
			ret = -ENOMEM;
			goto err_put2;
		}
		patch_funcs[i].func_kobj = func_tmp;
		memcpy(&patch_funcs[i].old_addr_attr, &old_addr_attr,
		       sizeof(struct kobj_attribute));
		memcpy(&patch_funcs[i].new_addr_attr, &new_addr_attr,
		       sizeof(struct kobj_attribute));
		patch_funcs[i].kaddr.old_addr = kpmod.patches[i].old_addr;
		patch_funcs[i].kaddr.old_size = kpmod.patches[i].old_size;
		patch_funcs[i].kaddr.new_addr = kpmod.patches[i].new_addr;
		patch_funcs[i].kaddr.new_size = kpmod.patches[i].new_size;
	}

	for (j = 0; j < kpmod.patches_nr; j++) {
		ret = sysfs_create_file(patch_funcs[j].func_kobj,
					&patch_funcs[j].old_addr_attr.attr);
		if (ret)
			goto err_sysfs2;

		ret = sysfs_create_file(patch_funcs[j].func_kobj,
					&patch_funcs[j].new_addr_attr.attr);
		if (ret)
			goto err_sysfs2;
	}

	ret = kpatch_register(&kpmod, replace);
	if (ret)
		goto err_sysfs2;

	return 0;

err_sysfs2:
	for (j--; j >= 0; j--) {
	        sysfs_remove_file(patch_funcs[j].func_kobj,
				  &patch_funcs[j].old_addr_attr.attr);
	        sysfs_remove_file(patch_funcs[j].func_kobj,
				  &patch_funcs[j].new_addr_attr.attr);
	}
err_put2:
	for (i--; i >= 0; i--) {
		kobject_put(patch_funcs[i].func_kobj);
	}
	kobject_put(funcs_kobj);
err_sysfs:
	sysfs_remove_file(patch_kobj, &patch_enabled_attr.attr);
err_put:
	kobject_put(patch_kobj);
err_free:
	kfree(patch_funcs);
	return ret;
}

static void __exit patch_exit(void)
{
	int i;
	WARN_ON(kpmod.enabled);

	for (i = 0; i < kpmod.patches_nr; i++) {
		sysfs_remove_file(patch_funcs[i].func_kobj,
				  &patch_funcs[i].old_addr_attr.attr);
	        sysfs_remove_file(patch_funcs[i].func_kobj,
				  &patch_funcs[i].new_addr_attr.attr);
		kobject_put(patch_funcs[i].func_kobj);
	}

	kobject_put(funcs_kobj);
	sysfs_remove_file(patch_kobj, &patch_enabled_attr.attr);
	kobject_put(patch_kobj);
	kfree(patch_funcs);
}

module_init(patch_init);
module_exit(patch_exit);
MODULE_LICENSE("GPL");
