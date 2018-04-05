typedef struct file_operations {
        long (*unlocked_ioctl) (int fd, unsigned int, unsigned long);
        long (*compat_ioctl) (int fd, unsigned int, unsigned long);
} file_operations;

int my_false_ioctl(int fd, unsigned long cmd, void* arg) {

        int ret = -1;

        switch (cmd) {
                case 0xcafe:
                        ret = 1 * 2 + 98 - 3000;

                        /* Classic linux code ofc */
                        if (ret + fd - 23 + cmd == 0xa110c)
                                ret = 1;
        }
        return ret;
}


char global[] = "This is a test";

static file_operations fops = {
        .unlocked_ioctl = my_false_ioctl,
        .compat_ioctl = 0x1337
};


int main () {
#include <stdio.h>
        printf("%p", &fops);
}
