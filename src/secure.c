/* Crypto Libraries*/
#include "crys_ecpki_build.h"
#include "crys_ecpki_kg.h" //key generation
#include "crys_ecpki_domain.h"
#include "crys_rnd.h"

/* SaSi Libraries */
#include "ssi_pal_mem.h"
#include "sns_silib.h"

/* NRF52840 Hardware Interface Library. */
#include "nrf52840.h"
#include "nrf_dfu_flash.h"

#include "nrf_error.h"

#include "secure.h"

/*
* Set the read back protection using Control Access Ports. By specifying it as
* an "section" we can reference it in our linkerscript and write into the
* register while flashing the hardware.
* Available Options:
* 1. ALLOW_DEBUGGER_ACCESS
* 2. DISALLOW_DEBUGGER_ACCESS
*/
const uint32_t approtect_set __attribute__((section(".ctrlap"))) __attribute__((used)) = DISALLOW_DEBUGGER_ACCESS;

/*
* Available Options:
* 1. Device Secret is already on flash at 0x000E0000 - ALREADY_WRITTEN
* 2. Device Secret must be generated and written on flash - GENERATE_AND_WRITE
*/
const uint32_t private_key_option __attribute__((section(".device_secrets"))) __attribute__((used)) = GENERATE_AND_WRITE;

/*
* The RND_STATE structure holds the seed, entropy and other info related to
* generating random numbers.
* The RND_WorkBuff structure holds an internal buffer which is used for re-seed
* process.
*/
CRYS_RND_State_t rnd_state;
CRYS_RND_WorkBuff_t  rnd_work_buff;

/*
* Initializes SEGGER RTT, SaSi and RNG functions. It also enables external
* interrupt requests and the hardware cryptocell.
*/
uint32_t crypto_init() {
  int ret;

  /* Enable external interrupt requests */
  NVIC_EnableIRQ(CRYPTOCELL_IRQn);

  /* Enable Hardware Cryptocell by setting the register bit */
  NRF_CRYPTOCELL->ENABLE = 1;

  /*
  * This function Perform global initialization of the ARM CryptoCell 3xx
  * runtime library; it must be called once per ARM CryptoCell for 3xx cold
  * boot cycle.
  */
  ret = SaSi_LibInit();
	if (ret != CRYS_OK) {
	  return NRF_ERROR_INTERNAL;
	}

  /*
  * Initializes RNG library
  * This function needs to be called once. It calls CRYS_RND_Instantiation to
  * initialize the TRNG and the primary RND context. An initialized RND context
  * is required for calling RND APIs and asymmetric cryptography key generation
  * and signatures. The primary context returned by this function can be used as
  * a single global context for all RND needs. Alternatively, other contexts may
  * be initialized and used with a more limited scope (for specific applications
  * or specific threads).
  */
  ret = CRYS_RndInit(&rnd_state, &rnd_work_buff);
  if (ret != CRYS_OK) {
    return NRF_ERROR_INTERNAL;
  }

  return NRF_SUCCESS;
}

/*
* This function uninstantiates the SaSi and RNG library.
* @return returns a integer with error code if the uninstantiation fails
*         returns 0 if uninstantiation was successfull
*/
uint32_t crypto_deinit() {
  int ret;

  /* unintialize the RNG library */
  ret = CRYS_RND_UnInstantiation(&rnd_state);

  if (ret != CRYS_OK) {
    return NRF_ERROR_INTERNAL;
  }

  /* unintialize the SaSi library */
  SaSi_LibFini();

  /* shut down cryptocell */
  NRF_CRYPTOCELL->ENABLE = 0;

  /* disable external interrupt requests */
  NVIC_DisableIRQ(CRYPTOCELL_IRQn);

  return NRF_SUCCESS;
}

/*
* Outputs keys to the Real time terminal in big-endioan format for debugging.
* @param key            pointer to the double-byte(uint32) array which holds the key
* @param print_message  pointer to the prefix char array (string literal)
*/
int generate_keys(
  CRYS_ECPKI_UserPrivKey_t* priv_key,
  CRYS_ECPKI_UserPublKey_t* publ_key
){
  CRYS_ECPKI_KG_TempData_t temp_buff;
  CRYS_ECPKI_KG_FipsContext_t temp_fips_buff;
  SaSiRndGenerateVectWorkFunc_t rnd_generate_func = CRYS_RND_GenerateVector;

  const CRYS_ECPKI_Domain_t *ecc_domain_p = CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_secp256k1);

  SaSi_PalMemSetZero(&temp_buff, sizeof(temp_buff));

  /* Generate a pair of ECC keys for the secp256k1 standard */
  int ret = CRYS_ECPKI_GenKeyPair (
    &rnd_state,
    rnd_generate_func,
    ecc_domain_p,
    priv_key,
    publ_key,
    &temp_buff,
    &temp_fips_buff
  );

  if (ret != CRYS_OK)
    return ret;

  return ret;
}

static uint32_t convert_to_word(uint8_t* byte_array) {
  uint32_t converted_word = byte_array[0] | (byte_array[1] << 8) | (byte_array[2] << 16) | (byte_array[3] << 24);
  return converted_word;
}

/*
* This function copies the device root key from a flash section and copies into
* the secure RAM of the cryptocell (a.k.a KDR registers). This function is
* attributed to NOT be optimized because it invovles a register read/write delay
* which must be handled with assembly code.
*/
uint32_t __attribute__((optimize("-O0"))) copy_kdr() {

  uint32_t ret_code;

  ret_code = crypto_init();

  if (ret_code != CRYS_OK) {
    return NRF_ERROR_INTERNAL;
  }

  nrf_dfu_flash_init(false);

  //set life cycle state to secure so you can write into KDR registers only once.
  NRF_CC_HOST_RGF->HOST_IOT_LCS = 2UL;

  //check until LCS_VALID_FLAG(read-only) is set
  while (!(NRF_CC_HOST_RGF->HOST_IOT_LCS & (1<<8))) {;}

  uint32_t *device_secrets = ((uint32_t *)(DEVICE_SECRET_ADDRESS));
  uint32_t secrets_flag_read = device_secrets[0];

  //check if the flash region contains a key
  if (secrets_flag_read == ALREADY_WRITTEN) {
    //copy key from flash to KDR registers
    NRF_CC_HOST_RGF->HOST_IOT_KDR0 = device_secrets[1];
    NRF_CC_HOST_RGF->HOST_IOT_KDR1 = device_secrets[2];
    NRF_CC_HOST_RGF->HOST_IOT_KDR2 = device_secrets[3];
    NRF_CC_HOST_RGF->HOST_IOT_KDR3 = device_secrets[4];

    //check if the key is retained in the registers
    while (NRF_CC_HOST_RGF->HOST_IOT_KDR0 != 1UL) {;}

    //copy the ECC key from flash to Reserved RAM
    SaSi_PalMemCopy((CRYS_ECPKI_UserPrivKey_t *)0x2003F000, &device_secrets[5], sizeof(CRYS_ECPKI_UserPrivKey_t));
  }
  else if (secrets_flag_read == GENERATE_AND_WRITE) {
    //generate random key
    uint16_t rnd_bytes_size = 16;
    uint8_t rnd_bytes[rnd_bytes_size];

    //after generating random number, we also want to change the flag
    uint32_t secrets_flag_change = ALREADY_WRITTEN;

    //ecc key structures
    CRYS_ECPKI_UserPrivKey_t private_key;
    CRYS_ECPKI_UserPublKey_t public_key;

    ret_code = CRYS_RND_GenerateVector (&rnd_state, rnd_bytes_size, rnd_bytes);

    if (ret_code != CRYS_OK) {
      return ret_code;
    }

    ret_code = generate_keys(&private_key, &public_key);

    if(ret_code != CRYS_OK) {
      return ret_code;
    }

    //TODO:ENCRYPT PRIVATE KEY
    /* IMPORTANT:
    * currently the nRF5 SDK does not support the use of device root key
    * cryptographic functions
    */

    //create a buffer which holds the new flag value and the random bytes
    uint32_t device_page_buffer_size = (uint32_t)rnd_bytes_size + sizeof(secrets_flag_change) + sizeof(private_key);
    uint8_t device_page_buffer[device_page_buffer_size];

    //copy the flag change value and the random number.
    SaSi_PalMemCopy(device_page_buffer, &secrets_flag_change, sizeof(uint32_t));
    SaSi_PalMemCopy(device_page_buffer + sizeof(secrets_flag_change), rnd_bytes, sizeof(rnd_bytes));
    SaSi_PalMemCopy(
      device_page_buffer + sizeof(secrets_flag_change) + sizeof(rnd_bytes),
      &private_key,
      sizeof(private_key));

    //copy key into KDR registers
    NRF_CC_HOST_RGF->HOST_IOT_KDR0 = convert_to_word(&rnd_bytes[0]);
    NRF_CC_HOST_RGF->HOST_IOT_KDR1 = convert_to_word(&rnd_bytes[4]);
    NRF_CC_HOST_RGF->HOST_IOT_KDR2 = convert_to_word(&rnd_bytes[8]);
    NRF_CC_HOST_RGF->HOST_IOT_KDR3 = convert_to_word(&rnd_bytes[12]);

    //check if the key is retained in the registers
    while (NRF_CC_HOST_RGF->HOST_IOT_KDR0 != 1UL) {;}

    //clear off the value in the rnd_bytes buffer
    SaSi_PalMemSetZero(rnd_bytes, sizeof(rnd_bytes));

    //copy the encrypted key onto the reserved RAM
    SaSi_PalMemCopy((CRYS_ECPKI_UserPrivKey_t *)0x2003F000, &private_key, sizeof(private_key));

    //erase the key in the general RAM
    SaSi_PalMemSetZero(&private_key, sizeof(private_key));

    //store the device secrets onto the flash. Erase and then Flash
    ret_code = nrf_dfu_flash_erase(DEVICE_SECRET_ADDRESS, 1, NULL);

    if (ret_code != NRF_SUCCESS) {
      return ret_code;
    }

    ret_code = nrf_dfu_flash_store(DEVICE_SECRET_ADDRESS, device_page_buffer, device_page_buffer_size, NULL);

    if (ret_code != NRF_SUCCESS) {
      return ret_code;
    }

    //clear off the device page buffer
    SaSi_PalMemSetZero(device_page_buffer, sizeof(device_page_buffer));
  }
  else {
    return NRF_ERROR_INTERNAL;
  }

  ret_code = crypto_deinit();

  if (ret_code != CRYS_OK) {
    return NRF_ERROR_INTERNAL;
  }

  return NRF_SUCCESS;
}
