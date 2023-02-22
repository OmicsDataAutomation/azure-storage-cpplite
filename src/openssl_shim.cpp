#include <array>
#include <cstring>
#include <stdexcept>
#include <iostream>

#include "openssl_shim.h"


namespace azure {  namespace storage_lite {

#ifdef __APPLE__
  std::vector<std::string> dl_paths_ = {"/usr/local/Cellar/lib/", 
      "/usr/local/lib/", "/usr/lib/", ""};
#elif __linux__
  std::vector<std::string> dl_paths_ = {"/usr/lib64/", "/usr/lib/", 
      "/usr/lib/x86_64-linux-gnu", ""};
#else
#  error Platform not supported
#endif
  std::string dl_error_;
  void* dl_handle = nullptr;
  unsigned long ossl_ver = 0;

  //OpenSSL1.1 function pointers
  void* (*hmac_ctx_new_fptr)();
  int (*hmac_ctx_reset_fptr)(void *);
  int (*hmac_init_ex_fptr)(void *, const void *, int , const void *, void *);
  int (*hmac_update_fptr)(void *, const unsigned char *, size_t);
  int (*hmac_final_fptr)(void *, unsigned char *, unsigned int *);
  void (*hmac_ctx_free_fptr)(void *);
  int (*md5_init_fptr)(void *);
  int (*md5_update_fptr)(void *, const void *, size_t);
  int (*md5_final_fptr)(unsigned char *, void *);
  int (*sha256_init_fptr)(void*);
  int (*sha256_final_fptr)(unsigned char *, void*);
  int (*sha256_update_fptr)(void*, const void *, size_t);

  //OpenSSL3 function pointers
  void* (*evp_mac_fetch_fptr)(void *, const char *, const char *);
  void* (*evp_mac_ctx_new_fptr)(void *);
  void (*evp_mac_ctx_free_fptr)(void *);
  OSSL_PARAM_OSSL3_SHIM (*ossl_param_construct_utf8_string_fptr)
      (const char *, char *, size_t);
  OSSL_PARAM_OSSL3_SHIM (*ossl_param_construct_end_fptr)(void);
  int (*evp_mac_init_fptr)(void *, const unsigned char *, size_t, 
      const OSSL_PARAM_OSSL3_SHIM []);
  int (*evp_mac_update_fptr)(void *, const unsigned char *, size_t);
  int (*evp_mac_final_fptr)(void *, unsigned char *, size_t *, size_t);
  int (*evp_md_get_size_fptr)(const void *);
  int (*evp_digestinit_ex_fptr)(void *, const void *, void *);
  int (*evp_digestupdate_fptr)(void *, const void *, size_t );
  int (*evp_digestfinal_ex_fptr)(void *, unsigned char *, unsigned int *);
  void (*evp_md_ctx_free_fptr)(void *);
  const void* (*evp_md5_fptr)(void);
  void* (*evp_md_ctx_new_fptr)(void);
  const void* (*evp_sha256_fptr)(void);


  void *get_dlopen_handle(const std::string& name, const std::string& version) {
    void *handle = NULL;
    std::string prefix("lib");
#ifdef __APPLE__
    std::string suffix(".dylib");
#elif __linux__
    std::string suffix(".so");
#else
#  error Platform not supported
#endif
    
    clear_dlerror();
    for (std::string dl_path : dl_paths_) {
      std::string path = dl_path + prefix + name;
      if (version.empty()) {
        handle = dlopen( (path + suffix).c_str(), RTLD_GLOBAL|RTLD_NOW);
      } else {
#ifdef __APPLE__
        handle = dlopen((path+"."+version+suffix).c_str(), RTLD_GLOBAL|RTLD_NOW);
#else
        handle = dlopen((path+suffix+"."+version).c_str(), RTLD_GLOBAL|RTLD_NOW);
#endif
      }   
      if (handle) {
        clear_dlerror();
        return handle;
      } else {
        set_dlerror();
      }   
    }   
  
    return handle;
  }
  
  void *get_dlopen_handle(const std::string& name) {
    return get_dlopen_handle(name, "");
  }


  void ossl_shim_init(void) {
    if(dl_handle == nullptr) {
      dl_handle = get_dlopen_handle("crypto");
      if(!dl_handle) {
        throw std::runtime_error("libcrypto is not present in the system");
      }
      ossl_ver = OpenSSL_version_num();
      if(ossl_ver < 0x30000000L) {
        BIND_SYMBOL(dl_handle, hmac_ctx_new_fptr, "HMAC_CTX_new", 
            (void*(*)(void)) );
        BIND_SYMBOL(dl_handle, hmac_ctx_reset_fptr, "HMAC_CTX_reset", 
            (int(*)(void*)) );
        BIND_SYMBOL(dl_handle, hmac_init_ex_fptr, "HMAC_Init_ex", 
            (int(*)(void *, const void *, int , const void *, void *)) );
        BIND_SYMBOL(dl_handle, hmac_update_fptr, "HMAC_Update", 
            (int(*)(void *, const unsigned char *, size_t)) );
        BIND_SYMBOL(dl_handle, hmac_final_fptr, "HMAC_Final", 
            (int(*)(void *, unsigned char *, unsigned int *)) );
        BIND_SYMBOL(dl_handle, hmac_ctx_free_fptr, "HMAC_CTX_free", 
            (void(*)(void *)) );
        BIND_SYMBOL(dl_handle, md5_init_fptr, "MD5_Init", (int(*)(void *)) );
        BIND_SYMBOL(dl_handle, md5_update_fptr, "MD5_Update", 
            (int(*)(void *, const void *, size_t)) );
        BIND_SYMBOL(dl_handle, md5_final_fptr, "MD5_Final", 
            (int(*)(unsigned char *, void *)) );
        BIND_SYMBOL(dl_handle, sha256_init_fptr, "SHA256_Init", 
            (int (*)(void*)));
        BIND_SYMBOL(dl_handle, sha256_final_fptr, "SHA256_Final", 
            (int (*)(unsigned char *, void*)));
        BIND_SYMBOL(dl_handle, sha256_update_fptr, "SHA256_Update",  
            (int (*)(void*, const void *, size_t)));
      } else {
        BIND_SYMBOL(dl_handle, evp_mac_fetch_fptr, "EVP_MAC_fetch", 
            (void*(*)(void *, const char *, const char *)) );
        BIND_SYMBOL(dl_handle, evp_mac_ctx_new_fptr, "EVP_MAC_CTX_new", 
            (void*(*)(void *)) );
        BIND_SYMBOL(dl_handle, ossl_param_construct_utf8_string_fptr, 
            "OSSL_PARAM_construct_utf8_string", 
            (OSSL_PARAM_OSSL3_SHIM(*)(const char *, char *, size_t)) );
        BIND_SYMBOL(dl_handle, ossl_param_construct_end_fptr, 
            "OSSL_PARAM_construct_end", (OSSL_PARAM_OSSL3_SHIM(*)(void)) );
        BIND_SYMBOL(dl_handle, evp_mac_init_fptr, "EVP_MAC_init", 
            (int(*)(void *, const unsigned char *, size_t, 
            const OSSL_PARAM_OSSL3_SHIM [])) );
        BIND_SYMBOL(dl_handle, evp_mac_update_fptr, "EVP_MAC_update", 
            (int(*)(void *, const unsigned char *, size_t)) );
        BIND_SYMBOL(dl_handle, evp_mac_final_fptr, "EVP_MAC_final", 
            (int(*)(void *, unsigned char *, size_t *, size_t)) );
        BIND_SYMBOL(dl_handle, evp_md_get_size_fptr, "EVP_MD_get_size", 
            (int (*)(const void *)));
        BIND_SYMBOL(dl_handle, evp_digestinit_ex_fptr, "EVP_DigestInit_ex", 
            (int (*)(void *, const void *, void *)) );
        BIND_SYMBOL(dl_handle, evp_digestupdate_fptr, "EVP_DigestUpdate", 
            (int (*)(void *, const void *, size_t)) );
        BIND_SYMBOL(dl_handle, evp_digestfinal_ex_fptr, "EVP_DigestFinal_ex", 
            (int (*)(void *, unsigned char *, unsigned int *)) );
        BIND_SYMBOL(dl_handle, evp_md_ctx_free_fptr, "EVP_MD_CTX_free", 
            (void (*)(void *)) );
        BIND_SYMBOL(dl_handle, evp_md5_fptr, "EVP_md5", (const void*(*)(void)));
        BIND_SYMBOL(dl_handle, evp_md_ctx_new_fptr, "EVP_MD_CTX_new", 
            (void* (*)(void)) );
        BIND_SYMBOL(dl_handle, evp_sha256_fptr, "EVP_sha256", 
            (const void* (*)(void)));
      }
    }
  }

  void *HMAC_CTX_new_ossl1_shim(void) {
    return ((*hmac_ctx_new_fptr)());
  }

  int HMAC_CTX_reset_ossl1_shim(void *ctx) {
    return (*hmac_ctx_reset_fptr)(ctx);
  }

  int HMAC_Init_ex_ossl1_shim(void *ctx, const void *key, int key_len, 
      const void *md, void *impl) {
    return ((*hmac_init_ex_fptr)(ctx, key, key_len, md, impl));
  }

  int HMAC_Update_ossl1_shim(void *ctx, const unsigned char *data, size_t len) {
    return ((*hmac_update_fptr)(ctx, data, len));
  }

  int HMAC_Final_ossl1_shim(void *ctx, unsigned char *md, unsigned int *len) {
    return ((*hmac_final_fptr)(ctx, md, len));
  }

  void HMAC_CTX_free_ossl1_shim(void *ctx) {
    return ((*hmac_ctx_free_fptr)(ctx));
  }

  int MD5_Init_ossl1_shim(void *c) {
    return ((*md5_init_fptr)(c));
  }

  int MD5_Update_ossl1_shim(void *c, const void *data, size_t len) {
    return ((*md5_update_fptr)(c, data, len));
  }

  int MD5_Final_ossl1_shim(unsigned char *md, void *c) {
    return ((*md5_final_fptr)(md, c));
  }

  int SHA256_Init_ossl1_shim(void *c) {
    return ((*sha256_init_fptr)(c));
  }

  int SHA256_Final_ossl1_shim(unsigned char *md, void *c) {
    return ((*sha256_final_fptr)(md, c));
  }

  int SHA256_Update_ossl1_shim(void *c, const void *data, size_t len) {
    return ((*sha256_update_fptr)(c, data, len));
  }


  //OpenSSL3 wrapper functions
  void* EVP_MAC_fetch_ossl3_shim(void *libctx, const char *algorithm, 
      const char *properties) {
    return ((*evp_mac_fetch_fptr)(libctx, algorithm, properties));
  }

  void* EVP_MAC_CTX_new_ossl3_shim(void *mac) {
    return ((*evp_mac_ctx_new_fptr)(mac));
  }

  void EVP_MAC_CTX_free_ossl3_shim(void *mac) {
    ((*evp_mac_ctx_free_fptr)(mac));
  }

  OSSL_PARAM_OSSL3_SHIM OSSL_PARAM_construct_utf8_string_ossl3_shim
      (const char *key, char *buf, size_t bsize) {
    return ((*ossl_param_construct_utf8_string_fptr)(key, buf, bsize));
  }

  OSSL_PARAM_OSSL3_SHIM OSSL_PARAM_construct_end_ossl3_shim(void) {
    return ((*ossl_param_construct_end_fptr)());
  }

  int EVP_MAC_init_ossl3_shim(void *ctx, const unsigned char *key, 
      size_t keylen, const OSSL_PARAM_OSSL3_SHIM params[]) {
    return ((*evp_mac_init_fptr)(ctx, key, keylen, params));
  }

  int EVP_MAC_update_ossl3_shim(void *ctx, const unsigned char *data, 
      size_t datalen) {
    return ((*evp_mac_update_fptr)(ctx, data, datalen));
  }

  int EVP_MAC_final_ossl3_shim(void *ctx, unsigned char *out, size_t *outl, 
        size_t outsize) {
    return ((*evp_mac_final_fptr)(ctx, out, outl, outsize));
  }

  int EVP_MD_get_size_ossl3_shim(const void *md) {
    return ((*evp_md_get_size_fptr)(md));
  }

  int EVP_DigestInit_ex_ossl3_shim(void *ctx, const void *type, void *impl) {
    return ((*evp_digestinit_ex_fptr)(ctx, type, impl));
  }

  int EVP_DigestUpdate_ossl3_shim(void *ctx, const void *d, size_t cnt) {
    return ((*evp_digestupdate_fptr)(ctx, d, cnt));
  }

  int EVP_DigestFinal_ex_ossl3_shim(void *ctx, unsigned char *md, 
        unsigned int *s) {
    return ((*evp_digestfinal_ex_fptr)(ctx, md, s));
  }

  void EVP_MD_CTX_free_ossl3_shim(void *ctx) {
    return ((*evp_md_ctx_free_fptr)(ctx));
  }

  const void* EVP_md5_ossl3_shim(void) {
    return ((*evp_md5_fptr)());
  }

  void* EVP_MD_CTX_new_ossl3_shim(void) {
    return ((*evp_md_ctx_new_fptr)());
  }

  const void* EVP_sha256_ossl3_shim(void) {
    return ((*evp_sha256_fptr)());
  }


}}  // azure::storage_lite
