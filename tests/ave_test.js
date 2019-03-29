/*
 * If not stated otherwise in this file or this component's Licenses.txt file the 
 * following copyright and licenses apply:
 *
 * Copyright 2016 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the License);
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
function onReady()
{
    b.evaluateJavaScript("XREReceiver.emit('callMethod','setVolume',[100])")
    b.evaluateJavaScript("XREReceiver.emit('callMethod','enableAutoPlay',[true])")
    b.evaluateJavaScript("XREReceiver.emit('callMethod','setContentOptions',[JSON.stringify({'rawURL':'http://cdn.theoplayer.com/video/big_buck_bunny/big_buck_bunny_metadata.m3u8'})])")
    b.evaluateJavaScript("XREReceiver.emit('callMethod','setContentUrl',['http://cdn.theoplayer.com/video/big_buck_bunny/big_buck_bunny_metadata.m3u8'])")
}
function onJavaScriptBridgeRequest(e)
{
    print("got message: " + e.message)
    var msg = JSON.parse(e.message);
    var type = msg.arg[0];
    if (type == 'onReady')
        onReady();
    else if (type == 'getRedirectionURL')
        b.evaluateJavaScript("XREReceiver.emit('gotRedirectionURL','http://cdn.theoplayer.com/video/big_buck_bunny/big_buck_bunny_metadata.m3u8')")
}
mac = rt.estbmac()
b = rt.locate()
b.on('onHTMLDocumentLoaded', () => { b.evaluateJavaScript("onXREReady('"+ mac +"')") })
b.on('onJavaScriptBridgeRequest', onJavaScriptBridgeRequest)
b.url = 'https://ccr.player-platform-stage.xcr.comcast.net/index.html?receiverVersion=3.0d1&receiverType=Native&receiverPlatform=arris_XG1v3_3.0d1EXP&protocolVersion=2.15.0.0&deviceType=ipstb&estbMacAddress='+mac+'&partnerId=comcast'
