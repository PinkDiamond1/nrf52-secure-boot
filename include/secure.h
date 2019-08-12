#ifndef __SECURE_H__
#define __SECURE_H__

#ifndef DEVICE_SECRET_ADDRESS
#define DEVICE_SECRET_ADDRESS 0x000FD000
#endif

#ifndef DEVICE_SECRET_SIZE
#define DEVICE_SECRET_SIZE 0x00001000
#endif

void copy_kdr();

#endif
