#include <linux/kernel.h>

asmlinkage long my_precious(void) {
  printk("my_precious syscall made\n");
  return 0;
}
