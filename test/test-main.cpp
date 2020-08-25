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
#include "testapp.h"
#include "testfile.h"
#include "testconv.h"
#include "testlog.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>

using namespace RDKTest;

/// Quotation

static inline std::string q(const std::string& s)
{
    return addQuotes(s);
}

/// Main entry point

int main(int, char** argv)
{
    RBTLOGN("Main - enter");

    setvbuf(stdout, NULL, _IOLBF, 0);
    setenv("SYNC_STDOUT", "1", 1);
    setenv("WESTEROS_CLIENT_FORWARD_STDOUT", "1", 1);
    //rtLogSetLevel(RT_LOG_DEBUG);

    App::app.loadConf(std::string(*argv) + ".conf");
    const Conf& conf = App::app.conf();

    if (conf.use("init"))
    {
        /// Initialize rdkbrowser2 to speed-up execution of the following items
        App::app.add(new ItemLoadURL("init-clear", ""));
    }

    //export XRE_HOST=<url> to set url to urlSuiteDomain (export XRE_HOST=xre.poc8.xcal.tv )
    const std::string urlSuiteDomain(getenv("XRE_HOST"));
    const std::string urlSuitePath("/com/comcast/samples/suite");
    const std::string urlSuiteJSTest("http://" + urlSuiteDomain + ":10004" + urlSuitePath + "/jsevaluation.html");

    // Test an Item timeout (disabled by default)
    if (conf.use("timeout", false))
    {
        /// Explore how the termination by timeout works
        App::app.add(new ItemLoadURL("timeout-test", urlSuiteJSTest, 1));
    }

    // Test a custom item (disabled by default)
    if (conf.use("custom", false))
    {
        /// Load a remote page in the browser using the ItemCustom class
        App::app.add(new ItemCustom
        (
            "custom-setUrl",
            [urlSuiteJSTest]()
            {
                return (RT_OK == App::app.setProperty("url", urlSuiteJSTest.c_str()));
            },
            [](rtString name, const rtObjectRef& event)
            {
                return Item::checkDocumentLoaded(name, event, "ItemCustom(set URL) checkEvent");
            }
        ));

        /// Clear the currently loaded page in the browser
        App::app.add(new ItemCustomLoadURL("custom-clear", ""));
    }

    // Test a JavaScript using the standard test from 'suite' remote app
    if (conf.use("jstest"))
    {
        /// Execute the standard JavaScript test
        App::app.add(new ItemLoadURL("jstest-loadUrl", urlSuiteJSTest));
        App::app.add(new ItemEvalJS("jstest-evalJS1", "replace()"));
        App::app.add(new ItemCallJS("jstest-callJS1", "hello()", "\"Result of callJavaScriptWithResult\""));

        /// Clear the currently loaded page in the browser
        App::app.add(new ItemLoadURL("jstest-clear", ""));
    }

    // Test the direct HTML setting using local resources
    File fileCss0, fileJs0;
    if (conf.use("inline"))
    {
        /// Execute the test for setHTML() method
        if (!fileCss0.create("file0.css", "body { text-align:center; }"))
            exit(1);
        if (!fileJs0.create("file0.js", "function hrefExt0() { return document.location.href; }"))
            exit(1);
        const std::string html =
            "<html>\n"
            "<head>\n"
            "<link rel='stylesheet' type='text/css' href='" + fileCss0.url() + "'>\n"
            "<script type='text/javascript' src='" + fileJs0.url() + "'></script>\n"
            "<script>\n"
            "function hrefInt0()\n"
            "{\n"
            " return {n:null,b:true,n:123,s:\"QWE\",arr:[false,0,'\"',{ok:1}]};\n"
            "}\n"
            "</script>\n"
            "</head>\n"
            "<body>\n"
            "</body>\n"
            "</html>\n";

        // Disable WebSecurity
        std::vector<rtValue> wsParams;
        wsParams.push_back(false);
        App::app.add(new ItemMethodNoResult("inline-ws-off", "setWebSecurityEnabled", wsParams));

        App::app.add(new ItemSetHTML("inline-setHtml", html));
        //App::app.add(new ItemCallJS("inline-callJS-styleBODY", "getComputedStyle(document.getElementsByTagName('BODY')[0]).textAlign", q("center")));
        App::app.add(new ItemCallJS("inline-callJS-hrefInt", "hrefInt0()", "{\"n\":123,\"b\":true,\"s\":\"QWE\",\"arr\":[false,0,\"\\\"\",{\"ok\":1}]}"));
        //App::app.add(new ItemCallJS("inline-callJS-hrefExt", "hrefExt0()", q("about:blank")));

        // Enable WebSecurity back
        wsParams[0] = true;
        App::app.add(new ItemMethodNoResult("inline-ws-on", "setWebSecurityEnabled", wsParams));

        /// Clear the currently loaded page in the browser
        App::app.add(new ItemLoadURL("inline-clear", ""));
    }

    // Test a page loading from a local file using other local resources
    File fileHtml1, fileCss1, fileJs1;
    if (conf.use("file1"))
    {
        /// Use scheme "file" for direct opening file with external JS resource
        if (!fileCss1.create("file1.css", "h1 { text-align:center; }"))
            exit(1);
        if (!fileJs1.create("file1.js", "function hrefExt1() { return document.location.href; }"))
            exit(1);
        if (!fileHtml1.create("file1.html",
            "<html>\n"
            "<head>\n"
            "<link rel='stylesheet' type='text/css' href='" + fileCss1.name() + "'>\n"
            "<script type='text/javascript' src='" + fileJs1.name() + "'></script>\n"
            "<script type='text/javascript'>\n"
            "function hrefInt1()\n"
            "{\n"
            " return document.location.href;\n"
            "}\n"
            "</script>\n"
            "</head>\n"
            "<body>\n"
            "<h1>Local file 1</h1>\n"
            "</body>\n"
            "</html>\n"
        ))
            exit(1);

        // Disable WebSecurity
        std::vector<rtValue> wsParams;
        wsParams.push_back(false);
        App::app.add(new ItemMethodNoResult("file1-ws-off", "setWebSecurityEnabled", wsParams));

        App::app.add(new ItemLoadURL("file1-loadUrl", fileHtml1.url()));
        App::app.add(new ItemCheckUrl("file1-checkUrl", fileHtml1.url()));
        App::app.add(new ItemCallJS("file1-callJS-styleH1", "getComputedStyle(document.getElementsByTagName('H1')[0]).textAlign", q("center")));
        App::app.add(new ItemCallJS("file1-callJS-hrefInt", "hrefInt1()", q(fileHtml1.url())));
        App::app.add(new ItemCallJS("file1-callJS-hrefExt", "hrefExt1()", q(fileHtml1.url())));

        // Enable WebSecurity back
        wsParams[0] = true;
        App::app.add(new ItemMethodNoResult("file1-ws-on", "setWebSecurityEnabled", wsParams));

        /// Clear the currently loaded page in the browser
        App::app.add(new ItemLoadURL("file1-clear", ""));
    }

    // Test a JS-initiated page loading from a local file using other local resources
    File fileHtml2, fileCss2, fileJs2;
    if (conf.use("file2"), false)
    {
        /// Use scheme "file" for JS-initiated opening file with external JS resource
        if (!fileCss2.create("file2.css", "h2 { text-align:center; }"))
            exit(1);
        if (!fileJs2.create("file2.js", "function hrefExt2() { return document.location.href; }"))
            exit(1);
        if (!fileHtml2.create("file2.html",
            "<html>\n"
            "<head>\n"
            "<link rel='stylesheet' type='text/css' href='" + fileCss2.name() + "'>\n"
            "<script type='text/javascript' src='" + fileJs2.name() + "'></script>\n"
            "<script type='text/javascript'>\n"
            "function hrefInt2()\n"
            "{\n"
            " return document.location.href;\n"
            "}\n"
            "</script>\n"
            "</head>\n"
            "<body>\n"
            "<h2>Local file 2</h2>\n"
            "</body>\n"
            "</html>\n"
        ))
            exit(1);

        // Disable WebSecurity
        std::vector<rtValue> wsParams;
        wsParams.push_back(false);
        App::app.add(new ItemMethodNoResult("file2-ws-off", "setWebSecurityEnabled", wsParams));

        App::app.add(new ItemEvalJS("file2-evalJS-setUrl", "document.location.href=" + q(fileHtml2.url())));
        App::app.add(new ItemCheckUrl("file2-checkUrl", fileHtml2.url()));
        App::app.add(new ItemCallJS("file2-callJS-styleH2", "getComputedStyle(document.getElementsByTagName('H2')[0]).textAlign", q("center")));
        App::app.add(new ItemCallJS("file2-callJS-hrefInt", "hrefInt2()", q(fileHtml2.url())));
        App::app.add(new ItemCallJS("file2-callJS-hrefExt", "hrefExt2()", q(fileHtml2.url())));

        // Enable WebSecurity back
        wsParams[0] = true;
        App::app.add(new ItemMethodNoResult("file2-ws-on", "setWebSecurityEnabled", wsParams));

        /// Clear the currently loaded page in the browser
        App::app.add(new ItemLoadURL("file2-clear", ""));
    }

    // Test an XmlHttpRequest to a local text file
    File file3Txt;
    if (conf.use("file3", false))
    {
        /// Use scheme "file" in AJAX request
        if (!file3Txt.create("file3.txt", "AJAX response data"))
            exit(1);

        // Disable WebSecurity
        std::vector<rtValue> wsParams;
        wsParams.push_back(false);
        App::app.add(new ItemMethodNoResult("file3-ws-off", "setWebSecurityEnabled", wsParams));

        const std::string ajax =
            "(function(url){"
            "var r=new XMLHttpRequest();"
            "r.open('GET',url,false);"
            "r.send(null);"
            "return r.responseText;"
            "})('" + file3Txt.url() + "');";
        App::app.add(new ItemCallJS("file3-callJS-ajax", ajax.c_str(), q(file3Txt.content())));

        // Enable WebSecurity back
        wsParams[0] = true;
        App::app.add(new ItemMethodNoResult("file3-ws-on", "setWebSecurityEnabled", wsParams));

        /// Clear the currently loaded page in the browser
        App::app.add(new ItemLoadURL("file3-clear", ""));
    }

    // Test the cookieJar property
    if (conf.use("cookiejar"))
    {
        App::app.add(new ItemLoadURL("cookiejar-loadUrl", urlSuiteJSTest));
        App::app.add(new ItemCheckUrl("cookiejar-checkUrl", urlSuiteJSTest));

        std::string cookie("document.cookie");
        if (conf.use("cookiejar-empty"))
        {
            App::app.add(new ItemCallJS("cookiejar-empty-checkJS", cookie, q("")));
            App::app.add(new ItemCheckPropCookieJar("cookiejar-empty-checkProp", ""));
        }

        std::string cookieInit, cookieInitProp;
        if (conf.use("cookiejar-init"))
        {
            cookieInit = "init=INIT COOKIE";
            cookieInitProp = cookieInit + "; path=" + urlSuitePath + "; domain=" + urlSuiteDomain + "\n";
            App::app.add(new ItemSetPropCookieJar("cookiejar-init-setProp", cookieInitProp));
            App::app.add(new ItemCallJS("cookiejar-init-checkJS", cookie, q(cookieInit)));
            App::app.add(new ItemCheckPropCookieJar("cookiejar-init-checkProp", cookieInitProp));
        }

        if (conf.use("cookiejar-test"))
        {
            std::string cookieTest("test=TEST COOKIE");
            std::string cookieTestJS(cookieTest);
            std::string cookieTestProp(cookieTest + "; path=" + urlSuitePath + "; domain=" + urlSuiteDomain + "\n");
            if (conf.use("cookiejar-init"))
            {
                cookieTestJS = cookieInit + "; " + cookieTest;
                cookieTestProp = cookieTestProp + cookieInitProp;
            }
            App::app.add(new ItemEvalJS("cookiejar-test-addJS", cookie + "='" + cookieTest + "'"));
            App::app.add(new ItemCallJS("cookiejar-test-checkJS", cookie, q(cookieTestJS)));
            App::app.add(new ItemCheckPropCookieJar("cookiejar-test-checkProp", cookieTestProp));
        }

        /// Clear the currently loaded page in the browser
        App::app.add(new ItemCustomLoadURL("cookiejar-clear", ""));
    }

    // Test the startup page loading from a local file with local resources
    if (conf.use("startup"))
    {
        // Disable WebSecurity
        std::vector<rtValue> wsParams;
        wsParams.push_back(false);
        App::app.add(new ItemMethodNoResult("startup-ws-off", "setWebSecurityEnabled", wsParams));

        std::string url("file:///home/root/startupScreen.html");
        App::app.add(new ItemLoadURL("startup-loadUrl", url));
        App::app.add(new ItemCheckUrl("startup-checkUrl", url));
        App::app.add(new ItemCallJS("startup-callJS-isLoaded", "is_loaded", "true"));
        App::app.add(new ItemEvalJS("startup-evalJS-onUpdate", "onStartupUpdate(0)"));
        App::app.add(new ItemEvalJS("startup-evalJS-animTick", "onAnimationTick()"));

        // Enable WebSecurity back
        wsParams[0] = true;
        App::app.add(new ItemMethodNoResult("startup-ws-on", "setWebSecurityEnabled", wsParams));

        /// Clear the currently loaded page in the browser
        App::app.add(new ItemLoadURL("startup-clear", ""));
    }

    RBTLOGD("Main - items added");

    App::app.run();

    RBTLOGD("Main - exit");
    return 0;
}
