#ifndef __SECURE_H__
#define __SECURE_H__

extern unsigned int _device_secrets_address;
extern unsigned int _device_secrets_length;

#ifndef DEVICE_SECRET_ADDRESS
#define DEVICE_SECRET_ADDRESS (uint32_t) &_device_secrets_address
#endif

#ifndef DEVICE_SECRET_SIZE
#define DEVICE_SECRET_SIZE (uint32_t) &_device_secrets_length
#endif

uint32_t copy_kdr();

#endif
