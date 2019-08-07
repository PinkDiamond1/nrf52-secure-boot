/* Crypto Libraries*/
#include "crys_ecpki_build.h"
#include "crys_ecpki_kg.h" //key generation
#include "crys_ecpki_domain.h"
#include "crys_ecpki_ecdsa.h"
#include "crys_rnd.h"

/* SaSi Libraries */
#include "ssi_pal_mem.h"
#include "sns_silib.h"

/* SEGGER Real-Time terminal interface */
#include "SEGGER_RTT.h"

/* NRF52840 Hardware Interface Library. */
#include "nrf52840.h"

/* include sha3 library */
#include "sha3.h"

/* standard libraries */
#include <string.h>

/* TODO: explain */
#include "secure.h"

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
int crypto_init() {
  int ret = 0;

  protect_private_key();

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
    //SEGGER_RTT_printf(0, "Failed SaSi_LibInit - ret = 0x%x\n", ret);
	  return 1;
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
    //SEGGER_RTT_printf(0, "Failed CRYS_RndInit - ret = 0x%x\n", ret);
    return 1;
  }

  return ret;
}

/*
* This function uninstantiates the SaSi and RNG library.
* @return returns a integer with error code if the uninstantiation fails
*         returns 0 if uninstantiation was successfull
*/
int crypto_deinit() {

  int ret = 0;

  /* unintialize the RNG library */
  ret = CRYS_RND_UnInstantiation(&rnd_state);

  if (ret) {
    //SEGGER_RTT_printf(0, "Failure in CRYS_RND_UnInstantiation,ret = 0x%x\n", ret);
    return ret;
  }

  /* unintialize the SaSi library */
  SaSi_LibFini();

  /* shut down cryptocell */
  NRF_CRYPTOCELL->ENABLE = 0;

  /* disable external interrupt requests */
  NVIC_DisableIRQ(CRYPTOCELL_IRQn);

  return ret;
}

int generate_keys(
  const CRYS_ECPKI_Domain_t* domain,
  CRYS_ECPKI_UserPrivKey_t* priv_key,
  CRYS_ECPKI_UserPublKey_t* publ_key
){
  CRYS_ECPKI_KG_TempData_t temp_buff;
  CRYS_ECPKI_KG_FipsContext_t temp_fips_buff;
  SaSiRndGenerateVectWorkFunc_t rnd_generate_func = CRYS_RND_GenerateVector;

  SaSi_PalMemSetZero(&temp_buff, sizeof(temp_buff));

  /* Generate a pair of ECC keys for the secp256k1 standard */
  int ret = CRYS_ECPKI_GenKeyPair (
    &rnd_state,
    rnd_generate_func,
    domain,
    priv_key,
    publ_key,
    &temp_buff,
    &temp_fips_buff
  );

  if (ret != CRYS_OK)
    return ret;

  return ret;
}

int main() {
  int ret = crypto_init();

  //set the domain of Elliptic curve cryptography to be used
  const CRYS_ECPKI_Domain_t *ecc_domain_p = CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_secp256k1);

  /*
  * There are two ways to handle private keys.
  * 1. User provides a raw stream of bytes of fixed size. These bytes are used
  *    initialize the private key data structure `CRYS_ECPKI_UserPrivKey_t`.
  * 2. The private key and public key are "generated" randomly.
  */

  /*
  * Define the User private and public key data structure which will hold the
  * private key and public key in it. A pointer to this structure will be
  * passed into the private key and public key build function to store the key
  */
  CRYS_ECPKI_UserPrivKey_t private_key;
  CRYS_ECPKI_UserPublKey_t public_key;

  ret = generate_keys(
    ecc_domain_p,
    &private_key,
    &public_key
  );

  /*
  * check if the private key was built succesfully, If not print error message
  * and return.
  */
  if (ret != CRYS_OK) {
    //SEGGER_RTT_printf(0, "The public key could not be built.\nError Code: 0x%lx \n", ret);
    return ret;
  }

  /*
  * Initialize uint8_t buffer for storing uncompressed public keys. Also
  * initialize uint32_t variable representing the expected size of exported key.
  */

  uint32_t uncomp_public_key_size = 65;
  uint8_t uncomp_public_key[uncomp_public_key_size];

  ret = CRYS_ECPKI_ExportPublKey(
    &public_key,
    CRYS_EC_PointUncompressed,
    uncomp_public_key,
    &uncomp_public_key_size
  );

  /*
  * check if the public key was exported succesfully, If not print error message
  * and return.
  */
  if (ret != CRYS_OK) {
    //SEGGER_RTT_printf(0, "The public key could not be exported.\nError Code: 0x%lx \n", ret);
    return ret;
  }

  uint32_t pubk_hash_size = 32;
  uint8_t pubk_hash[pubk_hash_size];
  uint8_t eth_address[20];

  //TODO: Explain +1 and -1
  keccak_256(&uncomp_public_key[1], uncomp_public_key_size-1, pubk_hash);

  //Take the right most 20 bytes from the keccak hash
  memcpy(eth_address, &pubk_hash[12], 20);

  /*
  * Define the message size and raw message in the hexcoded byte format
  * The code is commented because we need keccak-256 hash for ethereum. So we
  * we will be pre-hasing the message and pass the hash instead of the message.
  */
  uint32_t msg_size = 22;
  uint8_t msg[] = { //GUNS DON'T KILL PEOPLE
    0x47,0x55,0x4e,0x53,0x20,0x44,0x4f,0x4e,
    0x27,0x54,0x20,0x4b,0x49,0x4c,0x4c,0x20,
    0x50,0x45,0x4f,0x50,0x4c,0x45
  };

  /* KECCAK-256 hash of the message */
  uint32_t msg_hash_size = 32;
  uint8_t msg_hash[msg_hash_size];

  keccak_256(msg, msg_size, msg_hash);

  /* signature size and init of internal buffer for storing the signature */
  uint32_t signature_size = 65;
  uint8_t signature_out[signature_size];

  /* function pointer to random vector generation function */
  SaSiRndGenerateVectWorkFunc_t rnd_generate_func = CRYS_RND_GenerateVector;

  /* Internal memory allocation for signing and verifying process data*/
  CRYS_ECDSA_SignUserContext_t    signing_context;
  CRYS_ECDSA_VerifyUserContext_t  verifying_context;

  /*
  * Call CRYS_ECDSA_Sign to create signature from input buffer using created
  * private key. The hash mode is `CRYS_ECPKI_AFTER_HASH_SHA256_mode` because we
  * pass in a pre-hashed message. We select the SHA256 mode because it matches
  * the output size of KECCAK-256.
  */
  ret = CRYS_ECDSA_Sign (
    &rnd_state,
    rnd_generate_func,
    &signing_context,
    &private_key,
    CRYS_ECPKI_AFTER_HASH_SHA256_mode,
    msg_hash,
    msg_hash_size,
    signature_out,
    &signature_size
  );

  if (ret != CRYS_OK){
    //SEGGER_RTT_printf(0, " CRYS_ECDSA_Sign failed with 0x%x \n",ret);
    return ret;
  }

  /*
  * Call CRYS_ECDSA_Verify to verify the signature using created public key
  * The hash mode is `CRYS_ECPKI_AFTER_HASH_SHA256_mode` because we pass in a
  * pre-hashed message. We select the SHA256 mode because it matches the output
  * size of KECCAK-256.
  */
  ret =  CRYS_ECDSA_Verify (
    &verifying_context,
    &public_key,
    CRYS_ECPKI_AFTER_HASH_SHA256_mode,
    signature_out,
    signature_size,
    msg_hash,
    msg_hash_size
  );

  if (ret != CRYS_OK) {
    //SEGGER_RTT_printf(0, " CRYS_ECDSA_Verify failed with 0x%x \n",ret);
    return ret;
  }

  ret = crypto_deinit();

  if (ret != CRYS_OK)
    //SEGGER_RTT_printf(0, "Couldn't deinitialize the cryptocell.\nError Code: 0x%x\n", ret);

  return ret;
}
