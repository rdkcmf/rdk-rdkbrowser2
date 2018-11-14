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
#include <gtest/gtest.h>
#include "cookiejar_utils.h"

using namespace CookieJarUtils;

TEST(cookiejar_utils_test, testSerialize)
{
    std::vector<std::string> v {"1","2","3"};
    std::string s = serialize<2>(v);

    EXPECT_EQ("1\n2\n3\n", s);
}

TEST(cookiejar_utils_test, testSerializeCookie)
{
    std::vector<std::string> v {
        "RMID=732423sdfs73242; expires=Fri, 31 Dec 2010 23:59:59 GMT; path=/; domain=.example.net",
        "name=value; expires=Fri, 31 Dec 2020 23:59:59 GMT; path=/; domain=.comcast.net"};

    std::string s = serialize<2>(v);
    std::string r = v[0] + "\n" + v[1] + "\n";
    EXPECT_EQ(r, s);
}

TEST(cookiejar_utils_test, testUnserializeEndLine)
{
    std::string s = "1\n2\n3\n";
    std::vector<std::string> v;
    unserialize<2>(s, v);

    EXPECT_EQ(3, v.size());
    EXPECT_EQ("1", v[0]);
    EXPECT_EQ("2", v[1]);
    EXPECT_EQ("3", v[2]);
}

TEST(cookiejar_utils_test, testUnserialize)
{
    std::string s = "1\n2\n3";
    std::vector<std::string> v;
    unserialize<2>(s, v);

    EXPECT_EQ(3, v.size());
    EXPECT_EQ("1", v[0]);
    EXPECT_EQ("2", v[1]);
    EXPECT_EQ("3", v[2]);
}

TEST(cookiejar_utils_test, testUnserializeWhitespaces)
{
    std::string c1 = "name=ex; expires=Wed, 31-Oct-2018 20:24:32 GMT; domain=.192.168.211.67; path=/";
    std::string c2 = "\"name=ex; expires=Wed, 31-Oct-2018 20:24:32 GMT; domain=.192.168.211.67; path=/";
    std::string c3 = "name=val; expires=Tue, 31-Oct-2028 20:24:32 GMT; domain=192.168.211.67; path=/cgi-bin/";

    std::vector<std::string> v;
    unserialize<2>(c1 + "\n" + c2 + "\n" + c3, v);

    EXPECT_EQ(3, v.size());
    EXPECT_EQ(c1, v[0]);
    EXPECT_EQ(c2, v[1]);
    EXPECT_EQ(c3, v[2]);
}

TEST(cookiejar_utils_test, testBase64)
{
    std::string d = "COMmunications and broadCASTing";
    std::string e = "Q09NbXVuaWNhdGlvbnMgYW5kIGJyb2FkQ0FTVGluZw==";
    EXPECT_EQ(e, toBase64(d));
    EXPECT_EQ(d, fromBase64(e));
}

TEST(cookiejar_utils_test, testBase64Empty)
{
    EXPECT_EQ("", toBase64(""));
    EXPECT_EQ("", fromBase64(""));
}

TEST(cookiejar_utils_test, testBase64Binary)
{
    {
        const char d[] = {'\13', '\10', '\0'};
        std::string e = "Cwg=";
        EXPECT_EQ(e, toBase64(d));
        EXPECT_EQ(d, fromBase64(e));
    }
    {
        const char d[] = {'\1', '\2', '\3', '\4', '\5', '\6', '\7', '\0'};
        std::string e = "AQIDBAUGBw==";
        EXPECT_EQ(e, toBase64(d));
        EXPECT_EQ(d, fromBase64(e));
    }
}

TEST(cookiejar_utils_test, testChecksum)
{
    EXPECT_EQ(0, checksum(""));
    EXPECT_EQ(55349, checksum("test1"));
    EXPECT_EQ(60078, checksum("test2"));
    EXPECT_EQ(51643, checksum("Ralph Joel Roberts, Daniel Aaron "
        "and Julian A. Brodsky purchased American Cable Systems"));
}

TEST(cookiejar_utils_test, testCompress)
{
    std::string s = "They incorporated in 1969 as Comcast Corporation,"
        "a name Ralph invented by combining the words communications and broadcasting";
    EXPECT_EQ(s, uncompress(compress(s)));
}

TEST(cookiejar_utils_test, testCompressBase64)
{
    std::string s = "The Free Lunch Is Over";
    std::string b64 = "AAAAFngBC8lIVXArSk1V8CnNS85Q8CxW8C9LLQIAVFYHdg==";
    EXPECT_EQ(b64, toBase64(compress(s)));
    EXPECT_EQ(s, uncompress(fromBase64(b64)));
}

TEST(cookiejar_utils_test, testCompressBinary)
{
    const unsigned char e[] = {
        0, 0, 0, 15, 120, 1, 115, 247, 11, 85, 200, 44, 86, 240,
        203, 47, 81, 8, 205, 203, 172, 0, 0, 37, 39, 4, 252,
    };
    EXPECT_EQ(std::string((const char*) e, sizeof(e)/sizeof(e[0])), compress("GNU is Not Unix"));
}

TEST(cookiejar_utils_test, testCompressEmpty)
{
    EXPECT_EQ(4, compress("").size());
    EXPECT_EQ(std::string(4, '\0'), compress(""));
    EXPECT_EQ("", uncompress(compress("")));
}

TEST(cookiejar_utils_test, testCrypt)
{
    std::string s = "The word 'free' does not refer to price; it refers to freedom.";
    EXPECT_EQ(s, decrypt(encrypt(s)));
}

TEST(cookiejar_utils_test, testCryptBinary)
{
    const unsigned char e[] = {
        94, 94, 255, 159, 10, 132, 92, 109, 105, 62, 242, 29, 186, 246, 75, 196,
    };
    EXPECT_EQ(std::string((const char*) e, sizeof(e)/sizeof(e[0])), encrypt("Comcast"));
}

TEST(cookiejar_utils_test, testUnpackCookies)
{
    std::string b64 = "BOxCKUR9LPEJDWE3S+KZeKnleMWTaxapV+4gBTUF2fXzEn3c0BtAhfuOyW29p0lR76OQBEyrcw1M0OgmIFgl/+q2WewtjJcHVWjhv5yGDLtau6hrSNOcMSPB0fMzguRDhteCenb0KvSQ+bZMJOzfUTdeFgKhcooWTxMIDa8kvDoVgiEm9+IpDxJF7gKszrcq9z2/aUiNxuYZhXl7cmFcuaHRuZizArmJnZgTJuXkvtxjroGnPvypPb/ErjmZb3r/hd+vDdoGzyV7ijFzl3EMAi9uPcTorJ5PsYKJ9kOXSPXTUmT1gEml49ngpuG02du2U3VwTojnBMAJRjammTofLCgqZGvDTEjJybHQZqJb7+eKhCVCmssjgwTiyyAv2/I4NDR6aZhRNsytxKUVQMdLQD1pcDPtpjyXC51Lorph8heK4i29ci/TtF/ryscNlj1XB/lcxWX+Xk5TJC3mRHm1F29muFz48oGBHHs9QxX8cZ08CP17AVttX8CKmwrL4XXQhxNqZEzCv/Rb82t9ie5/3vZ7I87Ww0BFVDkR22HMC57qbOiOgpvcWZFIC2LqHf1e01HcJedhb8UvSGRI9mbpCXxLBeGBREOb/MlCnZMrb2yGVgI63f0XU8tFoG9RVwljLUaB8c23b2u7VN+cXSgXtdJVmghLnZVh/4pVlTXPNfh9ACAw8NKIWU5LSM1hNH2ckMui+R9fahKTW5VeH+nm5DkU84nXL2DwK+OqsfGJcf+QVZG/RpwejRAi5WLXifSPCVX7K2dMehqTN0eIanphhPbiB/3/1gxznkPXzX00sPHJvMS1HL5Zcw9D3J7MmEk9PuI1tzwnxubBR2pJwIw9s4bb2kSGVPN2/ws5WbCIus0Po10S2iyzkTcViB0AEQrOBwyw1He4ZnPrOf9p0+VKiZ+fmkxgdGik5x5gldYxxDB42uLVRWBA3OUmBLEYaNYDLrmsPFh7rZLaIRcNSIN3CVh11VE6gILH7antkBkN1hpEB2jcQ5IqtG3t60Pp/0oeneDQKakDOdEKWnbF8Y3cjT42cfjxiZowkR4Hr+RpqTiMmGlskMglaGlGBpNNgFFDIFN5hXtTajQPm0cO21QG2Q==";
    std::string e = "__cfduid=de83f07acafee2aae6d7b6be4870985bd1455643174; HttpOnly; expires=Wed, 15-Feb-2017 17:19:34 GMT; domain=.startpki.net; path=/\n"
        "VISITOR_INFO1_LIVE=IZodpQNgZtw; HttpOnly; expires=Thu, 30-Mar-2017 04:05:28 GMT; domain=.youtube.com; path=/\n"
        "id=22e8bde1500a00dd||t=1469808763|et=730|cs=002213fd48935eece0dd17ae48; expires=Sun, 29-Jul-2018 16:12:43 GMT; domain=.doubleclick.net; path=/\n"
        "IDE=AHWqTUlkgW65ut23Sua4zHZAHkp9lWY-Fiy2YXtBbrzVP7_za07aKm5l8Q; HttpOnly; expires=Sun, 29-Jul-2018 16:12:43 GMT; domain=.doubleclick.net; path=/\n"
        "PREF=f5=30; expires=Sun, 29-Jul-2018 16:12:46 GMT; domain=.youtube.com; path=/\n"
        "NID=83=XRcoEZmRBcYk8E2_v1iSFYNYwyziaR8jn9BsaOX9w6ev3NKYbtsmTGfUgCQvBqsh2IFd8Zf2N0MhfbY9Rj-jYwz4haHiNbHkPRMrHxESC6f_0ImE1dLM6BNVfZ16mZdb; HttpOnly; expires=Sat, 28-Jan-2017 16:13:07 GMT; domain=.google.com; path=/\n"
        "AWSELB=D199BB1F0A44EFEBA3565607A69958A5D4BA9FA8990C68B2D89CF097FC687DF4C3A19D2A3E6836598D40714AE24D8F2BA515870CFB3EA2C8AA99C58DD2EB05700A8AAE72D6; expires=Fri, 29-Jul-2016 17:15:59 GMT; domain=watchablex1appserver-prod.xidio.com; path=/\n"
        "zipcode=94127; expires=Sat, 29-Jul-2017 16:16:04 GMT; domain=watchablex1appserver-prod.xidio.com; path=/channelstore-webapp/\n"
        "timezone=-240; expires=Sat, 29-Jul-2017 16:16:04 GMT; domain=watchablex1appserver-prod.xidio.com; path=/channelstore-webapp/\n"
        "deviceType=pace_XG1v3; expires=Sat, 29-Jul-2017 16:16:04 GMT; domain=watchablex1appserver-prod.xidio.com; path=/channelstore-webapp/\n"
        "ipAddress=-1; expires=Fri, 05-Aug-2016 16:16:07 GMT; domain=watchablex1appserver-prod.xidio.com; path=/\n"
        "deviceId=bc08b42e-04d8-4fa5-b04d-acb5b901b696; expires=Wed, 25-Jan-2017 16:16:07 GMT; domain=watchablex1appserver-prod.xidio.com; path=/\n"
        "trackingSessionIdTimeout=1469830567876; expires=Sun, 28-Aug-2016 16:16:07 GMT; domain=watchablex1appserver-prod.xidio.com; path=/";

    EXPECT_EQ(e, uncompress(decrypt(fromBase64(b64))));
    EXPECT_EQ(b64, toBase64(encrypt(compress(e))));
}
