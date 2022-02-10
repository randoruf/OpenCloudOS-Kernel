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

MODULE_AUTHOR("Tencent Corporation");
MODULE_LICENSE("GPL v2");

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

static const struct inode_operations dmemfs_dir_inode_operations = {
	.create		= dmemfs_create,
	.lookup		= simple_lookup,
	.unlink		= simple_unlink,
	.mkdir		= dmemfs_mkdir,
	.rmdir		= simple_rmdir,
	.rename		= simple_rename,
};

static const struct inode_operations dmemfs_file_inode_operations = {
	.setattr = simple_setattr,
	.getattr = simple_getattr,
};

static const struct file_operations dmemfs_file_operations = {
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

static const struct super_operations dmemfs_ops = {
	.statfs	= dmemfs_statfs,
	.drop_inode = generic_delete_inode,
};

static int
dmemfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct inode *inode;
	struct dmemfs_fs_info *fsi = sb->s_fs_info;

	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = fsi->mount_opts.dpage_size;
	sb->s_blocksize_bits = ilog2(fsi->mount_opts.dpage_size);
	sb->s_magic = DMEMFS_MAGIC;
	sb->s_op = &dmemfs_ops;
	sb->s_time_gran = 1;

	inode = dmemfs_get_inode(sb, NULL, S_IFDIR);
	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		return -ENOMEM;

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
	kill_litter_super(sb);
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
