#pragma once

#include "../include/blob/blob_client.h"

#include <string>

namespace as_test {

    std::string get_random_string(size_t size);
    std::istringstream get_istringstream_with_random_buffer(size_t size);
    char* get_random_buffer(size_t size);
    std::string to_base64(const char* base, size_t length);

    class base {
    public:
        static azure::storage_lite::blob_client& test_blob_client(int size = 1);

        static const std::string& standard_storage_connection_string() {
          // see https://learn.microsoft.com/en-us/azure/storage/common/storage-configure-connection-string
          static std::string sscs;
          if (sscs.empty()) {
            char *connection_string = getenv("TEST_CONNECTION_STRING");
            if (connection_string) {
              sscs = std::string(connection_string);
            } else {
              // connection string for azurite
              sscs = "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1";
            }
          }
          return sscs;
        }

    protected:
        static const std::shared_ptr<azure::storage_lite::storage_account> init_account(const std::string& connection_string);
        static std::map<std::string, std::string> parse_string_into_settings(const std::string& connection_string);
    };
}
