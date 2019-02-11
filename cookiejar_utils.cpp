/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2016 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
#include "cookiejar_utils.h"
#include "logger.h"

#include <sstream>
#include <iterator>
#include <mutex>
#include <string.h>
#include <glib.h>
#include <zlib.h>
#include <openssl/err.h>
#include <openssl/evp.h>

namespace CookieJarUtils
{

/**
 * Names of fields that stored in cookieJar.
 */
const char* kFieldVersion = "version";
const char* kFieldChecksum = "md5sum";
const char* kFieldCookies = "cookies";

static const int kKeyLen = 32;
static unsigned char g_KeyV3[kKeyLen] = {0};
static bool g_KeyV3loaded = false;

template<>
std::string serialize<kDefaultCookieJarVersion>(const std::vector<std::string>& cookies)
{
    std::ostringstream os;
    std::copy(cookies.begin(), cookies.end(), std::ostream_iterator<std::string>(os, "\n"));

    return os.str();
}

template<>
void unserialize<kDefaultCookieJarVersion>(const std::string& cookies, std::vector<std::string>& result)
{
    std::string cookie;
    std::stringstream ss(cookies);
    while(ss.good())
    {
        getline(ss, cookie, '\n');
        if (!cookie.empty())
            result.push_back(cookie);
    }
}

std::string toBase64(const std::string& str)
{
    gchar* encoded = g_base64_encode((const unsigned char*) str.c_str(), str.size());
    std::string result(encoded);
    g_free(encoded);

    return result;
}

std::string fromBase64(const std::string& str)
{
    gsize outlen;
    guint8* decoded = g_base64_decode(str.c_str(), &outlen);
    std::string result((const char*) decoded, outlen);
    g_free(decoded);

    return result;
}

std::string compress(const std::string& str)
{
    std::string result;
    size_t nbytes = str.size();
    if (nbytes == 0)
    {
        result.append(4, '\0');
        return result;
    }

    const int compressionLevel = 1;
    unsigned long len = nbytes + nbytes / 100 + 13;
    int status;

    do
    {
        result.resize(len + 4);
        status = ::compress2((unsigned char*)result.data() + 4, &len,
            (const unsigned char*)str.c_str(), nbytes, compressionLevel);
        switch (status)
        {
        case Z_OK:
            result.resize(len + 4);
            result[0] = (nbytes & 0xff000000) >> 24;
            result[1] = (nbytes & 0x00ff0000) >> 16;
            result[2] = (nbytes & 0x0000ff00) >> 8;
            result[3] = (nbytes & 0x000000ff);
            break;
        case Z_MEM_ERROR:
            RDKLOG_ERROR("Z_MEM_ERROR: Not enough memory");
            result.resize(0);
            break;
        case Z_BUF_ERROR:
            len *= 2;
            break;
        }
    }
    while (status == Z_BUF_ERROR);

    return result;
}

std::string uncompress(const std::string& str)
{
    std::string result;
    size_t nbytes = str.size();
    if (nbytes <= 4)
    {
        if (str != std::string(4, '\0'))
        {
            RDKLOG_ERROR("Input data is corrupted");
        }

        return result;
    }

    const unsigned char* data = (const unsigned char*) str.data();
    unsigned long expectedSize = (unsigned long)(
        (data[0] << 24) | (data[1] << 16) |
        (data[2] <<  8) | (data[3]));
    unsigned long len = std::max(expectedSize, 1ul);
    int status;

    do
    {
        result.resize(len);
        status = ::uncompress((unsigned char*)result.data(), &len, data + 4, nbytes - 4);
        switch (status)
        {
        case Z_BUF_ERROR:
            len *= 2;
            break;
        case Z_MEM_ERROR:
            RDKLOG_ERROR("Z_MEM_ERROR: Not enough memory");
            result.resize(0);
            break;
        case Z_DATA_ERROR:
            RDKLOG_ERROR("Z_DATA_ERROR: Input data is corrupted");
            result.resize(0);
            break;
        }
    }
    while (status == Z_BUF_ERROR);

    return result;
}

int checksum(const std::string& str)
{
    static const unsigned short crc_tbl[16] = {
        0x0000, 0x1081, 0x2102, 0x3183,
        0x4204, 0x5285, 0x6306, 0x7387,
        0x8408, 0x9489, 0xa50a, 0xb58b,
        0xc60c, 0xd68d, 0xe70e, 0xf78f
    };

    unsigned short crc = 0xffff;
    unsigned char c = 0;
    const unsigned char *p = (const unsigned char*) str.data();
    size_t len = str.size();
    while (len--)
    {
        c = *p++;
        crc = ((crc >> 4) & 0x0fff) ^ crc_tbl[((crc ^ c) & 15)];
        c >>= 4;
        crc = ((crc >> 4) & 0x0fff) ^ crc_tbl[((crc ^ c) & 15)];
    }

    return ~crc & 0xffff;
}

#define CHECK_EVP_STATUS(r)                              \
if (r == 0)                                              \
{                                                        \
    RDKLOG_ERROR("Crypt failed");                        \
    while (ERR_peek_error() != 0)                        \
    {                                                    \
        RDKLOG_ERROR("Openssl %s",                       \
            ERR_error_string(ERR_get_error(), nullptr)); \
    }                                                    \
                                                         \
    return "";                                           \
}

static inline bool loadKeyV3(const char* logPrefix, unsigned char *key, unsigned int keyLen)
{
    // command in the binary.
    std::string cmd = "/usr/bin/GetConfigFile cookie.jar stdout";
    FILE *p = popen(cmd.c_str(), "r");

    if(p)
    {
        char buf[64];
        std::string s;
        while(fgets(buf, sizeof(buf), p) != NULL)
            s.append(buf);

        pclose(p);

        s = fromBase64(s);

        if (s.size() == keyLen)
        {
            memcpy(key, s.c_str(), keyLen);
            return true;
        }
        else
            RDK::log(RDK::ERROR_LEVEL, logPrefix, __FILE__, __LINE__, 0, "Unexpected data length for config: %d instead of %d", s.size(), keyLen);
    }

    RDK::log(RDK::ERROR_LEVEL, logPrefix, __FILE__, __LINE__, 0, "Failed to run cfgp");
    return false;
}

static inline std::string crypt(const std::string& in, bool encrypt, unsigned int &version)
{
    static unsigned char keyV2[kKeyLen] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
        0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
        0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x18
    };

    static unsigned char iv[]  = {
        0x58, 0x52, 0x45, 0x4E, 0x61, 0x74, 0x69, 0x76,
        0x65, 0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65
    };

    unsigned char *key = keyV2;
    if (3 == version)
    {
        // If failed at initialization try one more time again
        if (!g_KeyV3loaded)
        {
            static std::once_flag flag;
            std::call_once(flag, [] () {
                g_KeyV3loaded = loadKeyV3("processCookies", g_KeyV3, kKeyLen);
            });
        }

        if (!g_KeyV3loaded)
        {
            if (!encrypt)
            {
                RDK::log(RDK::ERROR_LEVEL, "processCookies", __FILE__, __LINE__, 0, "Failed get parameters.");
                return "";
            }
            RDK::log(RDK::ERROR_LEVEL, "processCookies", __FILE__, __LINE__, 0, "Failed get parameters, falling back to version 2");
            key = keyV2;
            version = 2;
        }
        else
        {
            RDK::log(RDK::INFO_LEVEL, "processCookies", __FILE__, __LINE__, 0, "Using cookiejar version 3");
            key = g_KeyV3;
        }
    }

    ERR_load_crypto_strings();
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    const EVP_CIPHER* cipher = EVP_aes_256_cbc();

    int status = 0;
    auto init = encrypt ? EVP_EncryptInit_ex : EVP_DecryptInit_ex;
    status = init(&ctx, cipher, 0, 0, 0);
    CHECK_EVP_STATUS(status);
    status = EVP_CIPHER_CTX_set_key_length(&ctx, kKeyLen);
    CHECK_EVP_STATUS(status);
    status = init(&ctx, 0, 0, key, iv);
    CHECK_EVP_STATUS(status);

    status = EVP_CIPHER_CTX_set_padding(&ctx, 1);
    CHECK_EVP_STATUS(status);

    int outl = 0;
    int inl = in.size();

    std::string result;
    result.resize(inl + EVP_CIPHER_CTX_block_size(&ctx));

    auto update = encrypt ? EVP_EncryptUpdate : EVP_DecryptUpdate;
    status = update(&ctx, (unsigned char*)result.data(), &outl, (unsigned char*) in.data(), inl);
    CHECK_EVP_STATUS(status);

    inl = outl;
    result.resize(inl + EVP_CIPHER_CTX_block_size(&ctx));

    auto final = encrypt ? EVP_EncryptFinal_ex : EVP_DecryptFinal_ex;
    status = final(&ctx, (unsigned char*)(result.data() + inl), &outl);
    CHECK_EVP_STATUS(status);

    result.resize(inl + outl);

    ERR_free_strings();
    EVP_cleanup();

    return result;
}

std::pair <std::string, unsigned int> encrypt(const std::string& str)
{
    unsigned int version = kDefaultCookieJarVersion;
    return std::pair<std::string, unsigned int> (crypt(str, true, version), version);
}

std::string decrypt(const std::string& str, unsigned int version)
{
    unsigned int vers = version;
    return crypt(str, false, vers);
}

void initialize()
{
    static std::once_flag flag;
    std::call_once(flag, [] () {
        g_KeyV3loaded = loadKeyV3("initialize", g_KeyV3, kKeyLen);
    });
}

} // namespace CookieJarUtils



