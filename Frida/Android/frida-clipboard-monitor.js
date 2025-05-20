// Usage: frida -U -l frida-clipboard-monitor.js -f com.example.app
Java.perform(function() {
    console.log("[+] Clipboard Security PoC Started");
    
    // For logging to file (optional)
    var File = Java.use("java.io.File");
    var FileOutputStream = Java.use("java.io.FileOutputStream");
    var OutputStreamWriter = Java.use("java.io.OutputStreamWriter");
    var logPath = "/sdcard/clipboard_log.txt"; // Requires storage permission
    
    // Format timestamp
    function getTimestamp() {
        var date = new Date();
        return date.toISOString();
    }
    
    // Log to both console and file
    function logData(message) {
        console.log(message);
        
        // Uncomment to enable file logging (requires permissions)
        /*
        try {
            var file = File.$new(logPath);
            var fileOutputStream = FileOutputStream.$new(file, true);
            var outputStreamWriter = OutputStreamWriter.$new(fileOutputStream);
            outputStreamWriter.write(getTimestamp() + ": " + message + "\n");
            outputStreamWriter.close();
        } catch (e) {
            console.log("[!] Error writing to log file: " + e);
        }
        */
    }
    
    // Hook clipboard manager
    var clipboardManager = Java.use("android.content.ClipboardManager");
    
    // Monitor write operations
    clipboardManager.setPrimaryClip.implementation = function(clipData) {
        logData("[!] SECURITY ALERT: Clipboard write detected");
        
        try {
            if (clipData !== null) {
                var itemCount = clipData.getItemCount();
                
                // Log details about the process that's accessing the clipboard
                var Process = Java.use("android.os.Process");
                var myPid = Process.myPid();
                var ActivityThread = Java.use("android.app.ActivityThread");
                var currentApplication = ActivityThread.currentApplication();
                var context = currentApplication.getApplicationContext();
                var packageName = context.getPackageName();
                
                logData("[+] Process: " + packageName + " (PID: " + myPid + ")");
                
                for (var i = 0; i < itemCount; i++) {
                    var item = clipData.getItemAt(i);
                    if (item !== null) {
                        // Try to get text
                        var text = item.getText();
                        if (text !== null) {
                            logData("[!] CLIPBOARD DATA: " + text.toString());
                            
                            // Check for sensitive data patterns
                            var textStr = text.toString();
                            if (textStr.match(/[0-9]{16}/)) {
                                logData("[!!!] DETECTED POSSIBLE CREDIT CARD NUMBER");
                            }
                            if (textStr.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/)) {
                                logData("[!!!] DETECTED POSSIBLE EMAIL ADDRESS");
                            }
                            if (textStr.match(/password|passwd|pwd|pass/i)) {
                                logData("[!!!] DETECTED POSSIBLE PASSWORD");
                            }
                        }
                        
                        // Try to get URI
                        var uri = item.getUri();
                        if (uri !== null) {
                            logData("[!] CLIPBOARD URI: " + uri.toString());
                        }
                        
                        // Try to get intent
                        var intent = item.getIntent();
                        if (intent !== null) {
                            logData("[!] CLIPBOARD INTENT: " + intent.toString());
                        }
                    }
                }
                
                // Get current app in foreground (requires more permissions)
                try {
                    var activityManager = Java.use("android.app.ActivityManager");
                    var getRunningTasksMethod = activityManager.getRunningTasks;
                    if (getRunningTasksMethod) {
                        var runningTasks = activityManager.getRunningTasks(1);
                        if (runningTasks.size() > 0) {
                            var topActivity = runningTasks.get(0).topActivity;
                            logData("[+] Foreground app: " + topActivity.getPackageName());
                        }
                    }
                } catch (e) {
                    console.log("[!] Error getting foreground app: " + e);
                }
            }
        } catch (e) {
            console.log("[!] Error in clipboard hook: " + e + "\n" + e.stack);
        }
        
        return this.setPrimaryClip(clipData);
    };
    
    // Monitor read operations
    clipboardManager.getPrimaryClip.implementation = function() {
        var clip = this.getPrimaryClip();
        
        logData("[!] SECURITY ALERT: Clipboard read detected");
        
        try {
            if (clip !== null) {
                var itemCount = clip.getItemCount();
                
                var Process = Java.use("android.os.Process");
                var myPid = Process.myPid();
                var ActivityThread = Java.use("android.app.ActivityThread");
                var currentApplication = ActivityThread.currentApplication();
                var context = currentApplication.getApplicationContext();
                var packageName = context.getPackageName();
                
                logData("[+] Process reading clipboard: " + packageName + " (PID: " + myPid + ")");
                
                if (itemCount > 0) {
                    for (var i = 0; i < itemCount; i++) {
                        var item = clip.getItemAt(i);
                        if (item !== null) {
                            var text = item.getText();
                            if (text !== null) {
                                logData("[+] Data being read: " + text.toString());
                            }
                        }
                    }
                }
            }
        } catch (e) {
            console.log("[!] Error in getPrimaryClip hook: " + e);
        }
        
        return clip;
    };
    
    // Also hook hasPrimaryClip
    clipboardManager.hasPrimaryClip.implementation = function() {
        var result = this.hasPrimaryClip();
        logData("[+] App checked if clipboard has content: " + result);
        return result;
    };
    
    logData("[+] Clipboard Security PoC successfully initialized");
});
