#ifndef __SECURE_H__
#define __SECURE_H__

extern unsigned int _device_secrets_address;
extern unsigned int _device_secrets_length;

#define ALLOW_DEBUGGER_ACCESS 1

#ifndef DEVICE_SECRET_ADDRESS
#define DEVICE_SECRET_ADDRESS (uint32_t) &_device_secrets_address
#endif

#ifndef DEVICE_SECRET_SIZE
#define DEVICE_SECRET_SIZE (uint32_t) &_device_secrets_length
#endif

#if ALLOW_DEBUGGER_ACCESS == 1
  #define AP_PROTECT 0xFFFFFFFF
#else
  #define AP_PROTECT 0xFFFFFF00
#endif

uint32_t copy_kdr();

#endif
