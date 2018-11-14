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
#ifndef RDKBROWSER_TEST_CONV_H
#define RDKBROWSER_TEST_CONV_H

#include <rtObject.h>
#include <rtValue.h>

#include <string>

namespace RDKTest
{

std::string toJSON(const rtString& string);
std::string toJSON(const rtObjectRef& object);
std::string toJSON(const rtValue& value);

std::string addQuotes(const std::string& text);


uint32_t cookieVersion();

/**
 * Returns CRC-16 checksum of a string.
 * The checksum is independent of the byte order (endianness).
 * @param Input string.
 * @return Checksum.
 */
int cookieChecksum(const std::string& str);

/**
 * Encodes multiline string to cookie format.
 * @param cookies Input string to encode.
 * @return Encoded string.
 */
std::string cookieEncode(const std::string& cookies);

/**
 * Encodes array of strings to cookie format.
 * @param cookies Input array of strings to encode.
 * @return Encoded string.
 */
std::string cookieEncode(const std::vector<std::string>& cookies);

/**
 * Decodes string from cookie format.
 * @param text Input string to decode.
 * @return Decoded multiline string.
 */
std::string cookieDecode(const std::string& text);

/**
 * Decodes array of strings from cookie format.
 * @param text Input string to decode.
 * @param[out] cookies Output array of strings.
 */
void cookieDecode(const std::string& text, std::vector<std::string>& cookies);

} // namespace RDKTest

#endif // RDKBROWSER_TEST_CONV_H
