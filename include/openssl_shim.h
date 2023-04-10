#pragma once

#include <vector>
#include <system_error>
#include <dlfcn.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <bcrypt.h>
#else
#ifdef USE_OPENSSL
#include <openssl/hmac.h>
#else
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#endif
#endif

namespace azure {  namespace storage_lite {

  extern void* dl_handle;
  extern std::string dl_error_;
  extern unsigned long ossl_ver;

  inline void clear_dlerror() {
    dl_error_ = std::string("");
    dlerror();
  }
  
  inline void set_dlerror() {
    char *errmsg = dlerror();
    if(errmsg) {
      dl_error_.empty() ? (dl_error_ = errmsg) : 
          (dl_error_ += std::string("\n") + errmsg);
    }
  }

  void ossl_shim_init(void);
  void *get_dlopen_handle(const std::string& name, const std::string& version);
  void *get_dlopen_handle(const std::string& name); 

#define BIND_SYMBOL(H, X, Y, Z)  \
  do {                           \
    clear_dlerror();             \
    X = Z dlsym(H, Y);           \
    if (!X) {                    \
      set_dlerror();             \
      throw std::system_error(ECANCELED, std::generic_category(), dl_error_); \
    }                            \
  } while (false)


//OpenSSL1 functions redirected to call dynamically using the below functions
#define HMAC_CTX_new   HMAC_CTX_new_ossl1_shim
#define HMAC_CTX_reset HMAC_CTX_reset_ossl1_shim
#define HMAC_Init_ex   HMAC_Init_ex_ossl1_shim
#define HMAC_Update    HMAC_Update_ossl1_shim
#define HMAC_Final     HMAC_Final_ossl1_shim
#define HMAC_CTX_free  HMAC_CTX_free_ossl1_shim
  void *HMAC_CTX_new_ossl1_shim(void); 
  int HMAC_CTX_reset_ossl1_shim(void *ctx);
  int HMAC_Init_ex_ossl1_shim(void *ctx, const void *key, int key_len, 
      const void *md, void *impl);
  int HMAC_Update_ossl1_shim(void *ctx, const unsigned char *data, size_t len);
  int HMAC_Final_ossl1_shim(void *ctx, unsigned char *md, unsigned int *len);
  void HMAC_CTX_free_ossl1_shim(void *ctx);

//OpenSSL3 functions redirected to call dynamically using the below functions

struct ossl_param_ossl3_shim_st {
  const char *key;             /* the name of the parameter */
  unsigned int data_type;      /* declare what kind of content is in buffer */
  void *data;                  /* value being passed in or out */
  size_t data_size;            /* data size */
  size_t return_size;          /* returned content size */
};

typedef struct ossl_param_ossl3_shim_st OSSL_PARAM_OSSL3_SHIM;
#define OSSL_PARAM      OSSL_PARAM_OSSL3_SHIM

#define OSSL_MAC_PARAM_DIGEST              OSSL_ALG_PARAM_DIGEST_OSSL3_SHIM   /* utf8 string */
#define OSSL_MAC_PARAM_DIGEST_OSSL3_SHIM   OSSL_ALG_PARAM_DIGEST_OSSL3_SHIM   /* utf8 string */
#define OSSL_ALG_PARAM_DIGEST_OSSL3_SHIM   "digest"    /* utf8_string */

#define EVP_MAC_fetch   EVP_MAC_fetch_ossl3_shim
#define EVP_MAC_CTX_new EVP_MAC_CTX_new_ossl3_shim
#define EVP_MAC_init     EVP_MAC_init_ossl3_shim
#define EVP_MAC_update   EVP_MAC_update_ossl3_shim
#define EVP_MAC_final   EVP_MAC_final_ossl3_shim
#define OSSL_PARAM_construct_utf8_string OSSL_PARAM_construct_utf8_string_ossl3_shim
#define OSSL_PARAM_construct_end OSSL_PARAM_construct_end_ossl3_shim
  void* EVP_MAC_fetch_ossl3_shim(void *libctx, const char *algorithm, 
      const char *properties);
  void* EVP_MAC_CTX_new_ossl3_shim(void *mac);
  int EVP_MAC_init_ossl3_shim(void *ctx, const unsigned char *key, 
      size_t keylen, const OSSL_PARAM params[]);
  int EVP_MAC_update_ossl3_shim(void *ctx, const unsigned char *data, 
      size_t datalen);
  int EVP_MAC_final_ossl3_shim(void *ctx, unsigned char *out, size_t *outl, 
      size_t outsize);
  OSSL_PARAM_OSSL3_SHIM OSSL_PARAM_construct_utf8_string_ossl3_shim(
      const char *key, char *buf, size_t bsize);
  OSSL_PARAM_OSSL3_SHIM OSSL_PARAM_construct_end_ossl3_shim(void);

}}
