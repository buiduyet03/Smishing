package kma.hvktmm.smishguard;

import android.app.Application;
import android.content.Context;

public class SmishGuard extends Application {
    private static Context context;

    public void onCreate() {
        super.onCreate();
        SmishGuard.context = getApplicationContext();
    }

    public static Context getAppContext() {
        return SmishGuard.context;
    }
}
