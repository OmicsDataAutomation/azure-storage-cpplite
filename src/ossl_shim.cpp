#include <array>
#include <cstring>
#include <stdexcept>

#include "ossl_shim.h"


namespace azure {  namespace storage_lite {

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
		    std::string path = dl_path+prefix+name;
		    if (version.empty()) {
		      handle = dlopen((path+suffix).c_str(), RTLD_GLOBAL|RTLD_NOW);
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
		

typedef void*(*hmac_ctx_new_temp)();
typedef int(*hmac_ctx_reset_temp)(void *ctx);
typedef int(*hmac_init_ex_temp)(void *ctx, const void *key, int key_len, const void *md, void *impl);
typedef int(*hmac_update_temp)(void *ctx, const unsigned char *data, size_t len);
typedef int(*hmac_final_temp)(void *ctx, unsigned char *md, unsigned int *len);
typedef void(*hmac_ctx_free_temp)(void *ctx);
typedef void*(*evp_mac_fetch_temp)(void *libctx, const char *algorithm, const char *properties);
typedef	void*(*evp_mac_ctx_new_temp)(void *mac);
typedef OSSL_PARAM_OSSL3_SHIM(*ossl_param_construct_utf8_string_temp)(const char *key, char *buf, size_t bsize);
typedef OSSL_PARAM_OSSL3_SHIM(*ossl_param_construct_end_temp)(void);
typedef	int(*evp_mac_init_temp)(void *ctx, const unsigned char *key, size_t keylen, const OSSL_PARAM_OSSL3_SHIM params[]);
typedef	int(*evp_mac_update_temp)(void *ctx, const unsigned char *data, size_t datalen);
typedef	int (*evp_mac_final_temp)(void *ctx, unsigned char *out, size_t *outl, size_t outsize);

		void *HMAC_CTX_new_ossl1_shim(void) {
		  void* retFunPtr = nullptr;
			if((retFunPtr = api_exists(dl_handle, "HMAC_CTX_new"))) {
				hmac_ctx_new_temp my_hmac_ctx_new_temp = reinterpret_cast<hmac_ctx_new_temp>(reinterpret_cast<long>(retFunPtr)) ;
				void *temp = (void*) (*my_hmac_ctx_new_temp)();
				return temp;
			}
			else {
        throw std::runtime_error("libcrypto.so version 1.1. doesn't have HMAC_CTX_new() function. This wasn't expected");
			}
		}


    int HMAC_CTX_reset_ossl1_shim(void *ctx)
		{
		  void* retFunPtr = nullptr;
			if((retFunPtr = api_exists(dl_handle, "HMAC_CTX_reset"))) {
				hmac_ctx_reset_temp my_hmac_ctx_reset_temp = reinterpret_cast<hmac_ctx_reset_temp>(reinterpret_cast<long>(retFunPtr)) ;
				return (*my_hmac_ctx_reset_temp)(ctx);
			}
			else {
        throw std::runtime_error("libcrypto.so version 1.1. doesn't have HMAC_CTX_reset() function. This wasn't expected");
			}

		}

    int HMAC_Init_ex_ossl1_shim(void *ctx, const void *key, int key_len, const void *md, void *impl)
		{
		  void* retFunPtr = nullptr;
			if((retFunPtr = api_exists(dl_handle, "HMAC_Init_ex"))) {
				hmac_init_ex_temp my_hmac_init_ex_temp = reinterpret_cast<hmac_init_ex_temp>(reinterpret_cast<long>(retFunPtr)) ;
				return ((*my_hmac_init_ex_temp)(ctx, key, key_len, md, impl));
			}
			else {
        throw std::runtime_error("libcrypto.so version 1.1. doesn't have HMAC_Init_ex() function. This wasn't expected");
			}
		}

    int HMAC_Update_ossl1_shim(void *ctx, const unsigned char *data, size_t len)
		{
		  void* retFunPtr = nullptr;
			if((retFunPtr = api_exists(dl_handle, "HMAC_Update"))) {
				hmac_update_temp my_hmac_update_temp = reinterpret_cast<hmac_update_temp>(reinterpret_cast<long>(retFunPtr)) ;
				return ((*my_hmac_update_temp)(ctx, data, len));
			}
			else {
        throw std::runtime_error("libcrypto.so version 1.1. doesn't have HMAC_Update() function. This wasn't expected");
			}
		}

    int HMAC_Final_ossl1_shim(void *ctx, unsigned char *md, unsigned int *len)
		{
		  void* retFunPtr = nullptr;
			if((retFunPtr = api_exists(dl_handle, "HMAC_Final"))) {
				hmac_final_temp my_hmac_final_temp = reinterpret_cast<hmac_final_temp>(reinterpret_cast<long>(retFunPtr)) ;
				return ((*my_hmac_final_temp)(ctx, md, len));
			}
			else {
        throw std::runtime_error("libcrypto.so version 1.1. doesn't have HMAC_Final() function. This wasn't expected");
			}
		}

    void HMAC_CTX_free_ossl1_shim(void *ctx)
		{
		  void* retFunPtr = nullptr;
			if((retFunPtr = api_exists(dl_handle, "HMAC_CTX_free"))) {
				hmac_ctx_free_temp my_hmac_ctx_free_temp = reinterpret_cast<hmac_ctx_free_temp>(reinterpret_cast<long>(retFunPtr)) ;
				return ((*my_hmac_ctx_free_temp)(ctx));
			}
			else {
        throw std::runtime_error("libcrypto.so version 1.1. doesn't have HMAC_CTX_free() function. This wasn't expected");
			}
		}

		void* EVP_MAC_fetch_ossl3_shim(void *libctx, const char *algorithm, const char *properties)
    {
		  void* retFunPtr = nullptr;
			if((retFunPtr = api_exists(dl_handle, "EVP_MAC_fetch"))) {
				evp_mac_fetch_temp my_evp_mac_fetch_temp = reinterpret_cast<evp_mac_fetch_temp>(reinterpret_cast<long>(retFunPtr)) ;
				return ((*my_evp_mac_fetch_temp)(libctx, algorithm, properties));
			}
			else {
        throw std::runtime_error("libcrypto.so version 3, doesn't have EVP_MAC_fetch() function. This wasn't expected");
			}
    }

		void* EVP_MAC_CTX_new_ossl3_shim(void *mac)
    {
		  void* retFunPtr = nullptr;
			if((retFunPtr = api_exists(dl_handle, "EVP_MAC_CTX_new"))) {
				evp_mac_ctx_new_temp my_evp_mac_ctx_new_temp = reinterpret_cast<evp_mac_ctx_new_temp>(reinterpret_cast<long>(retFunPtr)) ;
				return ((*my_evp_mac_ctx_new_temp)(mac));
			}
			else {
        throw std::runtime_error("libcrypto.so version 3, doesn't have EVP_MAC_CTX_new() function. This wasn't expected");
			}
    }

	  OSSL_PARAM_OSSL3_SHIM OSSL_PARAM_construct_utf8_string_ossl3_shim(const char *key, char *buf, size_t bsize)
    {
		  void* retFunPtr = nullptr;
			if((retFunPtr = api_exists(dl_handle, "OSSL_PARAM_construct_utf8_string"))) {
				ossl_param_construct_utf8_string_temp my_ossl_param_construct_utf8_string_temp 
          = reinterpret_cast<ossl_param_construct_utf8_string_temp>(reinterpret_cast<long>(retFunPtr)) ;
				return ((*my_ossl_param_construct_utf8_string_temp)(key, buf, bsize));
			}
			else {
        throw std::runtime_error("libcrypto.so version 3, doesn't have OSSL_PARAM_construct_utf8_string() function. This wasn't expected");
			}
    }

	  OSSL_PARAM_OSSL3_SHIM OSSL_PARAM_construct_end_ossl3_shim(void)
    {
		  void* retFunPtr = nullptr;
			if((retFunPtr = api_exists(dl_handle, "OSSL_PARAM_construct_end"))) {
				ossl_param_construct_end_temp my_ossl_param_construct_end = reinterpret_cast<ossl_param_construct_end_temp>(reinterpret_cast<long>(retFunPtr)) ;
				return ((*my_ossl_param_construct_end)());
			}
			else {
        throw std::runtime_error("libcrypto.so version 3, doesn't have OSSL_PARAM_construct_end() function. This wasn't expected");
			}
    }

		int EVP_MAC_init_ossl3_shim(void *ctx, const unsigned char *key, size_t keylen, const OSSL_PARAM_OSSL3_SHIM params[])
    {
		  void* retFunPtr = nullptr;
			if((retFunPtr = api_exists(dl_handle, "EVP_MAC_init"))) {
				evp_mac_init_temp my_evp_mac_init_temp = reinterpret_cast<evp_mac_init_temp>(reinterpret_cast<long>(retFunPtr)) ;
				return ((*my_evp_mac_init_temp)(ctx, key, keylen, params));
			}
			else {
        throw std::runtime_error("libcrypto.so version 3, doesn't have EVP_MAC_init() function. This wasn't expected");
			}
    }

		int EVP_MAC_update_ossl3_shim(void *ctx, const unsigned char *data, size_t datalen)
    {
		  void* retFunPtr = nullptr;
			if((retFunPtr = api_exists(dl_handle, "EVP_MAC_update"))) {
				evp_mac_update_temp my_evp_mac_update_temp = reinterpret_cast<evp_mac_update_temp>(reinterpret_cast<long>(retFunPtr)) ;
				return ((*my_evp_mac_update_temp)(ctx, data, datalen));
			}
			else {
        throw std::runtime_error("libcrypto.so version 3, doesn't have EVP_MAC_update() function. This wasn't expected");
			}
    }
		int EVP_MAC_final_ossl3_shim(void *ctx, unsigned char *out, size_t *outl, size_t outsize)
    {
		  void* retFunPtr = nullptr;
			if((retFunPtr = api_exists(dl_handle, "EVP_MAC_final"))) {
				evp_mac_final_temp my_evp_mac_final_temp = reinterpret_cast<evp_mac_final_temp>(reinterpret_cast<long>(retFunPtr)) ;
				return ((*my_evp_mac_final_temp)(ctx, out, outl, outsize));
			}
			else {
        throw std::runtime_error("libcrypto.so version 3, doesn't have EVP_MAC_final() function. This wasn't expected");
			}
    }
}}  // azure::storage_lite
