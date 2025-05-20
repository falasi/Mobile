// frida -U -l frida-clipboard-monitor.js -f com.example.app
console.log('[+] Clipboard monitoring script loaded');

Java.perform(function() {
    console.log('[+] Java context initialized');
    
    var clipboardManager = Java.use('android.content.ClipboardManager');
    console.log('[+] ClipboardManager class hooked');
    
    clipboardManager.setPrimaryClip.implementation = function(clipData) {
        console.log('[+] Clipboard content changed');
        
        try {
            if (clipData !== null) {
                var itemCount = clipData.getItemCount();
                console.log('[+] ClipData contains ' + itemCount + ' items');
                
                if (itemCount > 0) {
                    for (var i = 0; i < itemCount; i++) {
                        var item = clipData.getItemAt(i);
                        if (item !== null) {
                            var text = item.getText();
                            if (text !== null) {
                                console.log('[+] Clipboard item ' + i + ' content: "' + text.toString() + '"');
                            } else {
                                // If text is null, try other data types
                                var uri = item.getUri();
                                if (uri !== null) {
                                    console.log('[+] Clipboard item ' + i + ' contains URI: ' + uri.toString());
                                } else {
                                    console.log('[+] Clipboard item ' + i + ' contains no text or URI');
                                }
                            }
                        }
                    }
                }
                
                // Also log the raw description of the ClipData
                console.log('[+] Raw ClipData description: ' + clipData.toString());
            }
        } catch (e) {
            console.log('[!] Error processing clipboard data: ' + e + '\n' + e.stack);
        }
        
        return this.setPrimaryClip(clipData);
    };
    
    console.log('[+] Clipboard monitoring successfully set up');
});
