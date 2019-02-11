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
#ifndef COOKIEJAR_UTILS_H
#define COOKIEJAR_UTILS_H

#include <string>
#include <vector>

/**
 * CookieJar utils are supposed to be used
 * to parse, decrypt, unserialize cookies that are stored in a cloud
 * in specific format:
 *
 * All cookies are joined to one string
 *  To serialize cookies:
 *    1. Compress
 *    2. Encrypt
 *    3. Base64 encode
 *  To unserialize cookies:
 *    1. Base64 decode
 *    2. Decrypt
 *    3. Uncompress
 */
namespace CookieJarUtils
{

/**
 * Defines current supported version of cookies
 * that stored in cookieJar as strings.
 */
static const unsigned kDefaultCookieJarVersion = 3;

/**
 * Names of fields that stored in cookieJar.
 */
extern const char* kFieldVersion; // "version"
extern const char* kFieldChecksum; // "md5sum"
extern const char* kFieldCookies; // "cookies"

/**
 * Serializes cookies in proper version.
 * @param Version to serialize. Currently only 2nd is supported.
 * @param Vector of string cookies.
 * @return String with joined cookies.
 */
template<unsigned Version>
std::string serialize(const std::vector<std::string>& cookies);

/**
 * Unserializes cookies in proper version.
 * @param Version to serialize. Currently only 2nd is supported.
 * @param Serialized string of cookies.
 * @param[out] Vector to keep unparsed string cookies.
 */
template<unsigned Version>
void unserialize(const std::string& serialized, std::vector<std::string>& result);

/**
 * Encodes string to base64 format.
 * @param Input string.
 */
std::string toBase64(const std::string& str);

/**
 * Decodes string in base64 format to plain text.
 * @param Input encoded string.
 */
std::string fromBase64(const std::string& str);

/**
 * Compresses string.
 * @param Input string.
 */
std::string compress(const std::string& str);

/**
 * Decompresses string.
 * @param Input compressed string.
 */
std::string uncompress(const std::string& str);

/**
 * Returns CRC-16 checksum of a string.
 * The checksum is independent of the byte order (endianness).
 * @param Input string.
 */
int checksum(const std::string& str);

/**
 * Encrypts string.
 * @param Input string.
 */
std::pair <std::string, unsigned int> encrypt(const std::string& str);

/**
 * Decrypts string.
 * @param Input string.
 * @param Version.
 */
std::string decrypt(const std::string& str, unsigned int version);

/**
 * Initialize the encryption/decryption key
 */
void initialize();

} // namespace CookieJarUtils

#endif // COOKIEJAR_UTILS_H
