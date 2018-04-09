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
