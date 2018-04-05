#include "ki_dev.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <asm/uaccess.h>

static int i = 0;
static dev_t dev;
static struct cdev c_dev;
static struct class *cl;

int loltamere(void) { return 7; }
static void thisisatest(void) {	int i = 0; i++; }

static long false_ioctl(int asd, int tmp)
{
	return asd * 2 + tmp;
}

static long my_ioctl(int fd, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	int tmp;
	i++;

    if (cmd == 0xb0bca7)
            return false_ioctl(1, 1);

    if (cmd == 0xa110c)
            return 0;

	if (cmd == 0xcafe)
	{
		printk("Cafe stuff\n");
		ret = EINVAL;
	}
	else if (cmd == 0xc0ca)
	{
		printk("Coca stuff\n");
		tmp = 7;
		tmp *=2;
		ret = 3;
		tmp += 2 * fd;
		ret = tmp;
		ret = false_ioctl(ret, 0xc1a55ed + i);
	}
	else
		ret = ENODEV;

	printk("Failed stuff\n");
	return -ret;
}

static struct file_operations fops =
{
	.owner = THIS_MODULE,
	.unlocked_ioctl = (void*)my_ioctl,
	.compat_ioctl = (void*)my_ioctl
};

int my_init_module(void)
{
	struct device *dev_ret;

    int fops_size = sizeof(fops);
    printk("fops_size: %d\n", fops_size);
    printk("%p - %p\n", &fops, &fops.unlocked_ioctl);

	if (alloc_chrdev_region(&dev, MAJOR_NUMBER, MINOR_NUMBER, "ki_dev"))
		return -printk("######## Failed chardev alloc\n");

	cdev_init(&c_dev, &fops);

	if (cdev_add(&c_dev, dev, MINOR_NUMBER) < 0)
		return -printk("######## Failed cdev_add\n");

	if (IS_ERR(cl = class_create(THIS_MODULE, "char")))
	{
		cdev_del(&c_dev);
		unregister_chrdev_region(dev, MINOR_NUMBER);
		return -printk("######## Failed class_create\n");
	}

	if (IS_ERR(dev_ret = device_create(cl, NULL, dev, NULL, "ki")))
	{
		class_destroy(cl);
		cdev_del(&c_dev);
		unregister_chrdev_region(dev, MINOR_NUMBER);
		return -printk("######## Failed device_create\n");
	}

	return 0;
}

void my_cleanup_module(void)
{
	int i = loltamere();
	thisisatest();
	return;
}

module_init(my_init_module);
module_exit(my_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("P1kachu");
MODULE_DESCRIPTION("Just testing IOCTLs");
