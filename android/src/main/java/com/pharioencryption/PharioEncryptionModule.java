package com.pharioencryption;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.module.annotations.ReactModule;

@ReactModule(name = PharioEncryptionModule.NAME)
public class PharioEncryptionModule extends ReactContextBaseJavaModule {
    public static final String NAME = "PharioEncryption";

    private native void installPharioEncryption(long jsiPtr);

    public PharioEncryptionModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    @NonNull
    public String getName() {
        return NAME;
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    public boolean install() {
        try {
            System.loadLibrary("cpp");

            ReactApplicationContext context = getReactApplicationContext();
            installPharioEncryption(
                context.getJavaScriptContextHolder().get()
            );
            return true;
        } catch (Exception exception) {
            return false;
        }
    }
}
