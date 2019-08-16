/* NRF52840 Hardware Interface Library. */
#include "nrf52840.h"
#include "secure.h"
#include "nrf_error.h"

/*
* Set the read back protection using Control Access Ports. By specifying it as
* an "section" we can reference it in our linkerscript and write into the
* register while flashing the hardware. Check secure.h for configuration.
*/
const unsigned int *approtect_set __attribute__((section(".ctrlap"))) __attribute__((used))= (unsigned int *) AP_PROTECT;

#define PRIVATE_KEY_0 0xDEADBEEF
#define PRIVATE_KEY_1 0xDEADBEEF
#define PRIVATE_KEY_2 0xDEADBEEF
#define PRIVATE_KEY_3 0xDEADBEEF

const unsigned int *my_private_key[4] __attribute__((section(".private_key")))= {
  (unsigned int *) PRIVATE_KEY_0,
  (unsigned int *) PRIVATE_KEY_1,
  (unsigned int *) PRIVATE_KEY_2,
  (unsigned int *) PRIVATE_KEY_3
};

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

  //copy key from flash to KDR registers
  NRF_CC_HOST_RGF->HOST_IOT_KDR0 = *((uint32_t *)(DEVICE_SECRET_ADDRESS));
  NRF_CC_HOST_RGF->HOST_IOT_KDR1 = *((uint32_t *)(DEVICE_SECRET_ADDRESS + 0x00000004));
  NRF_CC_HOST_RGF->HOST_IOT_KDR2 = *((uint32_t *)(DEVICE_SECRET_ADDRESS + 0x00000008));
  NRF_CC_HOST_RGF->HOST_IOT_KDR3 = *((uint32_t *)(DEVICE_SECRET_ADDRESS + 0x0000000C));

  //check if the key is retained in the registers
  if (NRF_CC_HOST_RGF->HOST_IOT_KDR0 != 1UL) {
    return NRF_ERROR_INTERNAL;
  }

  NRF_CRYPTOCELL->ENABLE = 0;

  return NRF_SUCCESS;
}
