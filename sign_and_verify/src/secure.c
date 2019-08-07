/* NRF52840 Hardware Interface Library. */
#include "nrf52840.h"

/*
* Set the read back protection using Control Access Ports. By specifying it as
* an "section" we can reference it in our linkerscript and write into the
* register while flashing the hardware.
*/
#define AP_PROTECT 0xFFFFFF00
const unsigned int *approtect_set __attribute__((section("ctrlap"))) = (unsigned int *) AP_PROTECT;

#define PROTECTED_REGION_ADDRESS 0x000FE000
#define PROTECTED_REGION_SIZE 0x00001000
#define PROTECTED_REGION_PERM 0x00000006

#define KDR0_ADDRESS 0x000FE000
#define KDR1_ADDRESS 0x000FE004
#define KDR2_ADDRESS 0x000FE008
#define KDR3_ADDRESS 0x000FE00C

#define PRIVATE_KEY_0 0xDEADBEEF
#define PRIVATE_KEY_1 0xDEADBEEF
#define PRIVATE_KEY_2 0xDEADBEEF
#define PRIVATE_KEY_3 0xDEADBEEF

const unsigned int *my_private_key[4] __attribute__((section(".private_key"))) = {
  (unsigned int *) PRIVATE_KEY_0,
  (unsigned int *) PRIVATE_KEY_1,
  (unsigned int *) PRIVATE_KEY_2,
  (unsigned int *) PRIVATE_KEY_3
};

void protect_private_key() {
  //set life cycle state to secure so you can write into KDR registers only once.
  NRF_CC_HOST_RGF->HOST_IOT_LCS = 2;

  //copy key from flash to KDR registers
  NRF_CC_HOST_RGF->HOST_IOT_KDR0 = *((unsigned int *)KDR0_ADDRESS);
  NRF_CC_HOST_RGF->HOST_IOT_KDR1 = *((unsigned int *)KDR1_ADDRESS);
  NRF_CC_HOST_RGF->HOST_IOT_KDR2 = *((unsigned int *)KDR2_ADDRESS);
  NRF_CC_HOST_RGF->HOST_IOT_KDR3 = *((unsigned int *)KDR3_ADDRESS);

  //Enable ACL
  NRF_ACL->ACL[7].ADDR = PROTECTED_REGION_ADDRESS;
  NRF_ACL->ACL[7].PERM = PROTECTED_REGION_PERM;
  NRF_ACL->ACL[7].SIZE = PROTECTED_REGION_SIZE;
}
