#pragma once

#include "../test/test_base.h"
#include "adls_client.h"

#include <cerrno>

namespace as_test {

class adls_base : public base
{
public:
    static azure::storage_adls::adls_client test_adls_client(bool exception_enabled)
    {
        azure::storage_adls::adls_client client(init_account(standard_storage_connection_string()), 1, exception_enabled);
        return client;
    }

    static const std::string& standard_storage_connection_string() {
          // see https://learn.microsoft.com/en-us/azure/storage/common/storage-configure-connection-string
          static std::string sscs;
          if (sscs.empty()) {
            char *connection_string = getenv("TEST_ADLS_CONNECTION_STRING");
            if (connection_string) {
              sscs = std::string(connection_string);
            } else {
              throw std::runtime_error("Specify env variable TEST_ADLS_CONNECTION_STRING and rerun test");
            }
          }
          return sscs;
    }

    static std::string create_random_filesystem(azure::storage_adls::adls_client& client)
    {
        std::string fs_name = as_test::get_random_string(10);
        client.create_filesystem(fs_name);
        if (!client.exception_enabled() && errno != 0)
        {
            fs_name.clear();
        }
        return fs_name;
    }
};

}  // as_test
