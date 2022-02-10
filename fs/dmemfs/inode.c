// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/fs/dmemfs/inode.c
 *
 * Authors:
 *   Chen Zhuo	     <sagazchen@tencent.com>
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/capability.h>
#include <linux/magic.h>
#include <linux/mman.h>
#include <linux/statfs.h>
#include <linux/pagemap.h>
#include <linux/parser.h>
#include <linux/pfn_t.h>
#include <linux/pagevec.h>
#include <linux/fs_parser.h>
#include <linux/seq_file.h>
#include <linux/dmem.h>

MODULE_AUTHOR("Tencent Corporation");
MODULE_LICENSE("GPL v2");

#define CREATE_TRACE_POINTS
#include "trace.h"

struct dmemfs_mount_opts {
	unsigned long dpage_size;
};

struct dmemfs_fs_info {
	struct dmemfs_mount_opts mount_opts;
};

enum dmemfs_param {
	Opt_dpagesize,
};

const struct fs_parameter_spec dmemfs_fs_parameters[] = {
	fsparam_string("pagesize", Opt_dpagesize),
	{}
};

static int check_dpage_size(unsigned long dpage_size)
{
	if (dpage_size != PAGE_SIZE && dpage_size != PMD_SIZE &&
	      dpage_size != PUD_SIZE)
		return -EINVAL;

	return 0;
}

static struct inode *
dmemfs_get_inode(struct super_block *sb, const struct inode *dir, umode_t mode);

static int
__create_file(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode = dmemfs_get_inode(dir->i_sb, dir, mode);
	int error = -ENOSPC;

	if (inode) {
		d_instantiate(dentry, inode);
		dget(dentry);	/* Extra count - pin the dentry in core */
		error = 0;
		dir->i_mtime = dir->i_ctime = current_time(inode);
		if (mode & S_IFDIR)
			inc_nlink(dir);
	}
	return error;
}

static int dmemfs_create(struct inode *dir, struct dentry *dentry,
			 umode_t mode, bool excl)
{
	return __create_file(dir, dentry, mode | S_IFREG);
}

static int dmemfs_mkdir(struct inode *dir, struct dentry *dentry,
			umode_t mode)
{
	return __create_file(dir, dentry, mode | S_IFDIR);
}

static void inode_drop_dpages(struct inode *inode, loff_t start, loff_t end);

static int dmemfs_truncate(struct inode *inode, loff_t newsize)
{
	struct super_block *sb = inode->i_sb;
	loff_t current_size;

	if (newsize & ((1 << sb->s_blocksize_bits) - 1))
		return -EINVAL;

	current_size = i_size_read(inode);
	i_size_write(inode, newsize);

	if (newsize >= current_size)
		return 0;

	/* it cuts the inode down */

	/*
	 * we should make sure inode->i_size has been updated before
	 * unmapping and dropping radix entries, so that other sides
	 * can not create new i_mapping entry beyond inode->i_size
	 * and the radix entry in the truncated region is not being
	 * used
	 *
	 * see the comments in dmemfs_fault()
	 */
	synchronize_rcu();

	/*
	 * should unmap all mapping first as dmem pages are freed in
	 * inode_drop_dpages()
	 *
	 * after that, dmem page in the truncated region is not used
	 * by any process
	 */
	unmap_mapping_range(inode->i_mapping, newsize, 0, 1);

	inode_drop_dpages(inode, newsize, LLONG_MAX);
	return 0;
}

/*
 * same logic as simple_setattr but we need to handle ftruncate
 * carefully as we inserted self-defined entry into radix tree
 */
static int dmemfs_setattr(struct dentry *dentry, struct iattr *iattr)
{
	struct inode *inode = dentry->d_inode;
	int error;

	error = setattr_prepare(dentry, iattr);
	if (error)
		return error;

	if (iattr->ia_valid & ATTR_SIZE) {
		error = dmemfs_truncate(inode, iattr->ia_size);
		if (error)
			return error;
	}
	setattr_copy(inode, iattr);
	mark_inode_dirty(inode);
	return 0;
}

static unsigned long dmem_pgoff_to_index(struct inode *inode, pgoff_t pgoff)
{
	struct super_block *sb = inode->i_sb;

	return pgoff >> (sb->s_blocksize_bits - PAGE_SHIFT);
}

static void *dmem_addr_to_entry(struct inode *inode, phys_addr_t addr)
{
	struct super_block *sb = inode->i_sb;

	addr >>= sb->s_blocksize_bits;
	return xa_mk_value(addr);
}

static phys_addr_t dmem_entry_to_addr(struct inode *inode, void *entry)
{
	struct super_block *sb = inode->i_sb;

	WARN_ON(!xa_is_value(entry));
	return xa_to_value(entry) << sb->s_blocksize_bits;
}

static unsigned long
dmem_addr_to_pfn(struct inode *inode, phys_addr_t addr, pgoff_t pgoff,
		 unsigned int fault_shift)
{
	struct super_block *sb = inode->i_sb;
	unsigned long pfn = addr >> PAGE_SHIFT;
	unsigned long mask;

	mask = (1UL << ((unsigned int)sb->s_blocksize_bits - fault_shift)) - 1;
	mask <<= fault_shift - PAGE_SHIFT;

	return pfn + (pgoff & mask);
}

static inline unsigned long dmem_page_size(struct inode *inode)
{
	return inode->i_sb->s_blocksize;
}

static int check_inode_size(struct inode *inode, loff_t offset)
{
	WARN_ON_ONCE(!rcu_read_lock_held());

	if (offset >= i_size_read(inode))
		return -EINVAL;

	return 0;
}

static unsigned
dmemfs_find_get_entries(struct address_space *mapping, unsigned long start,
			unsigned int nr_entries, void **entries,
			unsigned long *indices)
{
	XA_STATE(xas, &mapping->i_pages, start);

	void *entry;
	unsigned int ret = 0;

	if (!nr_entries)
		return 0;

	rcu_read_lock();

	xas_for_each(&xas, entry, ULONG_MAX) {
		if (xas_retry(&xas, entry))
			continue;

		if (xa_is_value(entry))
			goto export;

		if (unlikely(entry != xas_reload(&xas)))
			goto retry;

export:
		indices[ret] = xas.xa_index;
		entries[ret] = entry;
		if (++ret == nr_entries)
			break;
		continue;
retry:
		xas_reset(&xas);
	}
	rcu_read_unlock();
	return ret;
}

static void *find_radix_entry_or_next(struct address_space *mapping,
				      unsigned long start,
				      unsigned long *eindex)
{
	void *entry = NULL;

	dmemfs_find_get_entries(mapping, start, 1, &entry, eindex);
	return entry;
}

/*
 * find the entry in radix tree based on @index, create it if
 * it does not exist
 *
 * return the entry with rcu locked, otherwise ERR_PTR()
 * is returned
 */
static void *
radix_get_create_entry(struct vm_area_struct *vma, unsigned long fault_addr,
		       struct inode *inode, pgoff_t pgoff)
{
	struct address_space *mapping = inode->i_mapping;
	unsigned long eindex, index;
	loff_t offset;
	phys_addr_t addr;
	gfp_t gfp_masks = mapping_gfp_mask(mapping) & ~__GFP_HIGHMEM;
	void *entry;
	unsigned int try_dpages, dpages;
	int ret;

retry:
	offset = ((loff_t)pgoff << PAGE_SHIFT);
	index = dmem_pgoff_to_index(inode, pgoff);
	rcu_read_lock();
	ret = check_inode_size(inode, offset);
	if (ret) {
		rcu_read_unlock();
		return ERR_PTR(ret);
	}

	try_dpages = dmem_pgoff_to_index(inode, (i_size_read(inode) - offset)
				     >> PAGE_SHIFT);
	entry = find_radix_entry_or_next(mapping, index, &eindex);
	if (entry) {
		WARN_ON(!xa_is_value(entry));
		if (eindex == index)
			return entry;

		WARN_ON(eindex <= index);
		try_dpages = eindex - index;
	}
	rcu_read_unlock();

	/* entry does not exist, create it */
	addr = dmem_alloc_pages_vma(vma, fault_addr, try_dpages, &dpages);
	if (!addr) {
		/*
		 * do not return -ENOMEM as that will trigger OOM,
		 * it is useless for reclaiming dmem page
		 */
		ret = -EINVAL;
		goto exit;
	}

	try_dpages = dpages;
	while (dpages) {
		rcu_read_lock();
		ret = check_inode_size(inode, offset);
		if (ret)
			goto unlock_rcu;

		entry = dmem_addr_to_entry(inode, addr);
		entry = xa_store(&mapping->i_pages, index, entry, gfp_masks);
		if (!xa_is_err(entry)) {
			addr += inode->i_sb->s_blocksize;
			offset += inode->i_sb->s_blocksize;
			dpages--;
			mapping->nrexceptional++;
			trace_dmemfs_radix_tree_insert(index, entry);
			index++;
		}

unlock_rcu:
		rcu_read_unlock();
		if (ret)
			break;
	}

	if (dpages)
		dmem_free_pages(addr, dpages);

	/* we have created some entries, let's retry it */
	if (ret == -EEXIST || try_dpages != dpages)
		goto retry;
exit:
	return ERR_PTR(ret);
}

static void radix_put_entry(void)
{
	rcu_read_unlock();
}

static vm_fault_t dmemfs_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct inode *inode = file_inode(vma->vm_file);
	phys_addr_t addr;
	void *entry;
	int ret;

	if (vmf->pgoff > (MAX_LFS_FILESIZE >> PAGE_SHIFT))
		return VM_FAULT_SIGBUS;

	entry = radix_get_create_entry(vma, (unsigned long)vmf->address,
				       inode, vmf->pgoff);
	if (IS_ERR(entry)) {
		ret = PTR_ERR(entry);
		goto exit;
	}

	addr = dmem_entry_to_addr(inode, entry);
	ret = vmf_insert_pfn(vma, (unsigned long)vmf->address,
			    dmem_addr_to_pfn(inode, addr, vmf->pgoff,
					     PAGE_SHIFT));
	radix_put_entry();

exit:
	return ret;
}

static unsigned long dmemfs_pagesize(struct vm_area_struct *vma)
{
	return dmem_page_size(file_inode(vma->vm_file));
}

static const struct vm_operations_struct dmemfs_vm_ops = {
	.fault = dmemfs_fault,
	.pagesize = dmemfs_pagesize,
};

int dmemfs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file_inode(file);

	if (vma->vm_pgoff & ((dmem_page_size(inode) - 1) >> PAGE_SHIFT))
		return -EINVAL;

	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	vma->vm_flags |= VM_PFNMAP;

	file_accessed(file);
	vma->vm_ops = &dmemfs_vm_ops;
	return 0;
}

static const struct inode_operations dmemfs_dir_inode_operations = {
	.create		= dmemfs_create,
	.lookup		= simple_lookup,
	.unlink		= simple_unlink,
	.mkdir		= dmemfs_mkdir,
	.rmdir		= simple_rmdir,
	.rename		= simple_rename,
};

static const struct inode_operations dmemfs_file_inode_operations = {
	.setattr = dmemfs_setattr,
	.getattr = simple_getattr,
};

static const struct file_operations dmemfs_file_operations = {
	.mmap = dmemfs_file_mmap,
};

static int dmemfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct dmemfs_fs_info *fsi = fc->s_fs_info;
	struct fs_parse_result result;
	int opt, ret;

	opt = fs_parse(fc, dmemfs_fs_parameters, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_dpagesize:
		fsi->mount_opts.dpage_size = memparse(param->string, NULL);
		ret = check_dpage_size(fsi->mount_opts.dpage_size);
		if (ret) {
			pr_warn("dmemfs: unknown pagesize %x.\n",
				result.uint_32);
			return ret;
		}
		break;
	default:
		pr_warn("dmemfs: unknown mount option [%x].\n",
			opt);
		return -EINVAL;
	}

	return 0;
}

struct inode *dmemfs_get_inode(struct super_block *sb,
			       const struct inode *dir, umode_t mode)
{
	struct inode *inode = new_inode(sb);

	if (inode) {
		inode->i_ino = get_next_ino();
		inode_init_owner(inode, dir, mode);
		inode->i_mapping->a_ops = &empty_aops;
		mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
		mapping_set_unevictable(inode->i_mapping);
		inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
		switch (mode & S_IFMT) {
		default:
			init_special_inode(inode, mode, 0);
			break;
		case S_IFREG:
			inode->i_op = &dmemfs_file_inode_operations;
			inode->i_fop = &dmemfs_file_operations;
			break;
		case S_IFDIR:
			inode->i_op = &dmemfs_dir_inode_operations;
			inode->i_fop = &simple_dir_operations;

			/*
			 * directory inodes start off with i_nlink == 2
			 * (for "." entry)
			 */
			inc_nlink(inode);
			break;
		case S_IFLNK:
			inode->i_op = &page_symlink_inode_operations;
			break;
		}
	}
	return inode;
}

static int dmemfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	simple_statfs(dentry, buf);
	buf->f_bsize = dentry->d_sb->s_blocksize;

	return 0;
}

/*
 * should make sure the dmem page in the dropped region is not
 * being mapped by any process
 */
static void inode_drop_dpages(struct inode *inode, loff_t start, loff_t end)
{
	struct address_space *mapping = inode->i_mapping;
	struct pagevec pvec;
	unsigned long istart, iend, indices[PAGEVEC_SIZE];
	int i;

	/* we never use normap page */
	WARN_ON(mapping->nrpages);

	/* if no dpage is allocated for the inode */
	if (!mapping->nrexceptional)
		return;

	istart = dmem_pgoff_to_index(inode, start >> PAGE_SHIFT);
	iend = dmem_pgoff_to_index(inode, end >> PAGE_SHIFT);
	pagevec_init(&pvec);
	while (istart < iend) {
		pvec.nr = dmemfs_find_get_entries(mapping, istart,
				min(iend - istart,
				(unsigned long)PAGEVEC_SIZE),
				(void **)pvec.pages,
				indices);
		if (!pvec.nr)
			break;

		for (i = 0; i < pagevec_count(&pvec); i++) {
			phys_addr_t addr;

			istart = indices[i];
			if (istart >= iend)
				break;

			xa_erase(&mapping->i_pages, istart);
			trace_dmemfs_radix_tree_delete(istart, pvec.pages[i]);
			mapping->nrexceptional--;

			addr = dmem_entry_to_addr(inode, pvec.pages[i]);
			dmem_free_page(addr);
		}

		/*
		 * only exception entries in pagevec, it's safe to
		 * reinit it
		 */
		pagevec_reinit(&pvec);
		cond_resched();
		istart++;
	}
}

static void dmemfs_evict_inode(struct inode *inode)
{
	/* no VMA works on it */
	WARN_ON(!RB_EMPTY_ROOT(&inode->i_data.i_mmap.rb_root));

	inode_drop_dpages(inode, 0, LLONG_MAX);
	clear_inode(inode);
}

/*
 * Display the mount options in /proc/mounts.
 */
static int dmemfs_show_options(struct seq_file *m, struct dentry *root)
{
	struct dmemfs_fs_info *fsi = root->d_sb->s_fs_info;

	if (check_dpage_size(fsi->mount_opts.dpage_size))
		seq_printf(m, ",pagesize=%lx", fsi->mount_opts.dpage_size);
	return 0;
}

static const struct super_operations dmemfs_ops = {
	.statfs	= dmemfs_statfs,
	.evict_inode = dmemfs_evict_inode,
	.drop_inode = generic_delete_inode,
	.show_options = dmemfs_show_options,
};

static int
dmemfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct inode *inode;
	struct dmemfs_fs_info *fsi = sb->s_fs_info;
	int ret;

	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = fsi->mount_opts.dpage_size;
	sb->s_blocksize_bits = ilog2(fsi->mount_opts.dpage_size);
	sb->s_magic = DMEMFS_MAGIC;
	sb->s_op = &dmemfs_ops;
	sb->s_time_gran = 1;

	ret = dmem_alloc_init(sb->s_blocksize_bits);
	if (ret)
		return ret;

	inode = dmemfs_get_inode(sb, NULL, S_IFDIR);
	sb->s_root = d_make_root(inode);

	if (!sb->s_root) {
		dmem_alloc_uinit();
		return -ENOMEM;
	}
	return 0;
}

static int dmemfs_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, dmemfs_fill_super);
}

static void dmemfs_free_fc(struct fs_context *fc)
{
	kfree(fc->s_fs_info);
}

static const struct fs_context_operations dmemfs_context_ops = {
	.free		= dmemfs_free_fc,
	.parse_param	= dmemfs_parse_param,
	.get_tree	= dmemfs_get_tree,
};

int dmemfs_init_fs_context(struct fs_context *fc)
{
	struct dmemfs_fs_info *fsi;

	fsi = kzalloc(sizeof(*fsi), GFP_KERNEL);
	if (!fsi)
		return -ENOMEM;

	fsi->mount_opts.dpage_size = PAGE_SIZE;
	fc->s_fs_info = fsi;
	fc->ops = &dmemfs_context_ops;
	return 0;
}

static void dmemfs_kill_sb(struct super_block *sb)
{
	bool has_inode = !!sb->s_root;

	kill_litter_super(sb);

	/* do not uninit dmem allocator if mount failed */
	if (has_inode)
		dmem_alloc_uinit();
}

static struct file_system_type dmemfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "dmemfs",
	.init_fs_context = dmemfs_init_fs_context,
	.kill_sb	= dmemfs_kill_sb,
};

static int __init dmemfs_init(void)
{
	int ret;

	ret = register_filesystem(&dmemfs_fs_type);

	return ret;
}

static void __exit dmemfs_uninit(void)
{
	unregister_filesystem(&dmemfs_fs_type);
}

module_init(dmemfs_init);
module_exit(dmemfs_uninit);
