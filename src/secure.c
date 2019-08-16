/* NRF52840 Hardware Interface Library. */
#include "nrf52840.h"
#include "secure.h"
#include "nrf_error.h"

/*
* Set the read back protection using Control Access Ports. By specifying it as
* an "section" we can reference it in our linkerscript and write into the
* register while flashing the hardware.
* Available Options:
* 1. ALLOW_DEBUGGER_ACCESS
* 2. DISALLOW_DEBUGGER_ACCESS
*/
const unsigned int *approtect_set __attribute__((section(".ctrlap"))) __attribute__((used))= (unsigned int *) ALLOW_DEBUGGER_ACCESS;

/*
* Available Options:
* 1. Device Secret is already on flash at 0x000E0000 - ALREADY_WRITTEN
* 2. Device Secret must be generated and written on flash - GENERATE_AND_WRITE
*/
#define MOCK_ALREADY_WRITTEN 0x00000001
const uint32_t *secrets_flag_write __attribute__((section(".device_secrets"))) __attribute__((used)) = (uint32_t *) MOCK_ALREADY_WRITTEN;

/*
* This function copies the device root key from a flash section and copies into
* the secure RAM of the cryptocell (a.k.a KDR registers). This function is
* attributed to NOT be optimized because it invovles a register read/write delay
* which must be handled with assembly code.
*/
uint32_t __attribute__((optimize("-O0"))) copy_kdr() {

  NRF_CRYPTOCELL->ENABLE = 1;

  //set life cycle state to secure so you can write into KDR registers only once.
  NRF_CC_HOST_RGF->HOST_IOT_LCS = 2UL;

  __asm("nop;nop;nop;nop;nop;nop;nop");

  //check if LCS_VALID_FLAG(read-only) is set
  if (!(NRF_CC_HOST_RGF->HOST_IOT_LCS & (1<<8))) {
    return NRF_ERROR_INTERNAL;
  }

  //check if the flash region contains a key
  uint32_t *device_secrets = ((uint32_t *)(0x000E0000));
  uint32_t secrets_flag_read = device_secrets[0];

  if (secrets_flag_read == 1UL) {
    //copy key from flash to KDR registers
    NRF_CC_HOST_RGF->HOST_IOT_KDR0 = device_secrets[1];
    NRF_CC_HOST_RGF->HOST_IOT_KDR1 = device_secrets[2];
    NRF_CC_HOST_RGF->HOST_IOT_KDR2 = device_secrets[3];
    NRF_CC_HOST_RGF->HOST_IOT_KDR3 = device_secrets[4];
  }
  else {
    return NRF_ERROR_INTERNAL;
  }

  //check if the key is retained in the registers
  if (NRF_CC_HOST_RGF->HOST_IOT_KDR0 != 1UL) {
    return NRF_ERROR_INTERNAL;
  }

  NRF_CRYPTOCELL->ENABLE = 0;

  return NRF_SUCCESS;
}
