#ifndef __SECURE_H__
#define __SECURE_H__

extern unsigned int _device_secrets_address;
extern unsigned int _device_secrets_length;

#define ALLOW_DEBUGGER_ACCESS 0xFFFFFFFF
#define DISALLOW_DEBUGGER_ACCESS 0xFFFFFF00

#ifndef DEVICE_SECRET_ADDRESS
#define DEVICE_SECRET_ADDRESS (uint32_t) &_device_secrets_address
#endif

#ifndef DEVICE_SECRET_SIZE
#define DEVICE_SECRET_SIZE (uint32_t) &_device_secrets_length
#endif

#define ALREADY_WRITTEN 0x00000002
#define GENERATE_AND_WRITE 0x00000001

uint32_t copy_kdr();

#endif
