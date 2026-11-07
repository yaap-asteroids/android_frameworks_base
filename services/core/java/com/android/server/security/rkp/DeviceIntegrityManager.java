/*
 * Copyright (C) 2025-2026 AxionOS
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lifecycle and client restart handling adapted from PenguinOS AxSpoofManagerService.
 */
package com.android.server.security.rkp;

import android.content.Context;
import android.database.ContentObserver;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.Handler;
import android.os.Process;
import android.os.UserHandle;
import android.provider.Settings;
import android.security.trickystore.TrickyStoreService;
import android.util.Log;

import com.android.internal.os.BackgroundThread;
import com.android.server.SystemService;

import org.json.JSONObject;


/** Owns the opt-in integrity configuration and the device provisioning lifecycle. */
public final class DeviceIntegrityManager extends SystemService {
    private static final String TAG = "DeviceIntegrity";
    private static final String MASTER = "spoof_trickystore_enabled";
    private static final String TARGETS = "spoof_trickystore_target";
    private static final String PATCH = "spoof_trickystore_patch";
    private static final String PIF = "spoof_pif_config";
    private static final int CONFIG_LIMIT = 64 * 1024;
    private final Context mContext;
    private final Handler mHandler;
    private volatile DuckRkpManager mDuck;

    public DeviceIntegrityManager(Context context) {
        super(context);
        mContext = context;
        mHandler = BackgroundThread.getHandler();
    }

    @Override public void onStart() {
        publishLocalService(DeviceIntegrityManager.class, this);
    }

    @Override public void onBootPhase(int phase) {
        if (phase != PHASE_ACTIVITY_MANAGER_READY) return;
        Context context = mContext;
        Handler handler = mHandler;
        mDuck = new DuckRkpManager(context, handler, this::changed);
        ContentObserver observer = new ContentObserver(handler) {
            @Override public void onChange(boolean selfChange, Uri uri) {
                mDuck.onSettingsChanged(uri != null && MASTER.equals(uri.getLastPathSegment()));
                changed();
            }
        };
        for (String key : new String[] {TARGETS, PATCH, PIF,
                Settings.Secure.SPOOF_DUCK_RKP_ENABLED, Settings.Secure.SPOOF_TRICKYSTORE_KEYBOX}) {
            context.getContentResolver().registerContentObserver(
                    Settings.Secure.getUriFor(key), false, observer, UserHandle.USER_SYSTEM);
        }
        context.getContentResolver().registerContentObserver(Settings.Secure.getUriFor(MASTER),
                false, observer, UserHandle.USER_SYSTEM);
        handler.post(this::applyProperties);
    }

    public DuckRkpManager duck() {
        if (mDuck == null) throw new IllegalStateException("Device provisioning is starting");
        return mDuck;
    }

    @Override public void onUserSwitching(TargetUser from, TargetUser to) {
        // Profiles do not share keyboxes. Restart only the PIF clients of the new user.
        mHandler.post(() -> restartPifTargets(to.getUserIdentifier()));
    }

    public boolean enabled() {
        return Settings.Secure.getIntForUser(mContext.getContentResolver(), MASTER, 0,
                UserHandle.USER_SYSTEM) != 0;
    }

    private String read(String key) {
        return Settings.Secure.getStringForUser(mContext.getContentResolver(), key,
                UserHandle.USER_SYSTEM);
    }

    private void changed() {
        mHandler.removeCallbacks(mApply);
        mHandler.postDelayed(mApply, 500);
    }

    private final Runnable mApply = this::applyChanges;

    private void applyChanges() {
        applyProperties();
        android.security.pif.PlayIntegritySpoofService.getInstance().invalidateConfig();
        restartPifTargets(UserHandle.USER_SYSTEM);
    }

    private void applyProperties() {
        android.os.SystemProperties.set("persist.sys.integrity.enabled", enabled() ? "1" : "0");
    }

    // Adapted from PenguinOS AxSpoofManagerService: do not force-stop all of GMS.
    private void restartPifTargets(int userId) {
        try {
            android.app.ActivityManager am = mContext.getSystemService(android.app.ActivityManager.class);
            if (am == null) return;
            am.forceStopPackageAsUser("com.android.vending", userId);
            var processes = am.getRunningAppProcesses();
            if (processes == null) return;
            for (var process : processes) {
                if (UserHandle.getUserId(process.uid) == userId
                        && "com.google.android.gms.unstable".equals(process.processName)) {
                    Process.killProcess(process.pid);
                }
            }
        } catch (RuntimeException e) {
            Log.w(TAG, "Cannot restart integrity clients", e);
        }
    }

    public Bundle configuration() {
        Bundle result = new Bundle();
        result.putBoolean("master_enabled", enabled());
        result.putString("targets", targets());
        result.putString("pif", read(PIF));
        result.putString("patch", read(PATCH));
        return result;
    }

    public void configure(Bundle config) {
        if (config == null) throw new IllegalArgumentException("Missing configuration");
        // Validate every supplied field before writing any settings.
        for (String key : new String[] {"targets", "pif", "patch"}) {
            if (!config.containsKey(key)) continue;
            String value = config.getString(key, "").trim();
            if (value.length() > CONFIG_LIMIT) throw new IllegalArgumentException("Configuration is too large");
            try {
                if (key.equals("targets")) validateTargets(value);
                if (key.equals("pif") && !value.isEmpty()) {
                    if (value.startsWith("{")) new JSONObject(value);
                    else for (String line : value.split("\n")) {
                        if (!line.isBlank() && !line.trim().startsWith("#") && line.indexOf('=') <= 0)
                            throw new IllegalArgumentException("Use JSON or key=value properties");
                    }
                }
                if (key.equals("patch") && !value.isEmpty()) validatePatch(new JSONObject(value), true);
            } catch (org.json.JSONException e) {
                throw new IllegalArgumentException("Invalid " + key + " configuration", e);
            }
        }
        for (String key : new String[] {"targets", "pif", "patch"}) {
            if (!config.containsKey(key)) continue;
            String setting = key.equals("targets") ? TARGETS : key.equals("pif") ? PIF : PATCH;
            if (!Settings.Secure.putStringForUser(mContext.getContentResolver(), setting,
                    config.getString(key, "").trim(), UserHandle.USER_SYSTEM))
                throw new IllegalStateException("Cannot save " + key);
        }
        if (config.containsKey("master_enabled") && !Settings.Secure.putIntForUser(
                mContext.getContentResolver(), MASTER,
                config.getBoolean("master_enabled") ? 1 : 0, UserHandle.USER_SYSTEM))
            throw new IllegalStateException("Cannot save device integrity setting");
    }

    static void validateTargets(String value) {
        for (String raw : value.split("\n")) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#") || line.matches("android[!?-]?")) continue;
            if (!line.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+[!?-]?"))
                throw new IllegalArgumentException("Invalid app target: " + line);
        }
    }

    static void validatePatch(JSONObject object, boolean allowPackages) throws org.json.JSONException {
        for (var keys = object.keys(); keys.hasNext();) {
            String key = keys.next();
            if (key.equals("packages") && allowPackages) {
                JSONObject packages = object.getJSONObject(key);
                for (var names = packages.keys(); names.hasNext();) {
                    String name = names.next();
                    if (!name.equals("android")
                            && !name.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+"))
                        throw new IllegalArgumentException("Invalid patch package: " + name);
                    validatePatch(packages.getJSONObject(name), false);
                }
            } else if (java.util.Set.of("system", "vendor", "boot", "all").contains(key)) {
                Object value = object.get(key);
                if (!(value instanceof String) || !TrickyStoreService.isValidPatchValue((String) value))
                    throw new IllegalArgumentException("Invalid patch value for " + key);
            } else {
                throw new IllegalArgumentException("Unknown patch field: " + key);
            }
        }
    }

    public String targets() {
        String value = read(TARGETS);
        return value == null ? TrickyStoreService.DEFAULT_TARGET_LIST : value;
    }

    public String targetConfig() { return callerEnabled() ? targets() : null; }
    public String patchConfig() { return callerEnabled() ? read(PATCH) : null; }

    private boolean callerEnabled() {
        return UserHandle.getUserId(Binder.getCallingUid()) == UserHandle.USER_SYSTEM && enabled();
    }

    public String pifConfig() {
        if (!callerEnabled()) return null;
        int uid = Binder.getCallingUid();
        if (uid == Process.SYSTEM_UID) return read(PIF);
        String[] packages = mContext.getPackageManager().getPackagesForUid(uid);
        if (packages == null || java.util.Arrays.stream(packages)
                .noneMatch(p -> p.equals("com.google.android.gms") || p.equals("com.android.vending")))
            return null;
        return read(PIF);
    }

    public String keybox() {
        if (!enabled() || !mayReadKeybox()) return null;
        long token = Binder.clearCallingIdentity();
        try { return duck().getKeybox(); }
        finally { Binder.restoreCallingIdentity(token); }
    }

    private boolean mayReadKeybox() {
        int uid = Binder.getCallingUid();
        if (uid == Process.SYSTEM_UID || uid == Process.ROOT_UID) return true;
        String[] packages = mContext.getPackageManager().getPackagesForUid(uid);
        if (UserHandle.getUserId(uid) != UserHandle.USER_SYSTEM || packages == null) return false;
        boolean allowed = false;
        for (String pkg : packages) {
            if (TrickyStoreService.XPOSED_PACKAGES.contains(pkg)) return false;
            for (String raw : targets().split("\n")) {
                String target = raw.trim();
                if (target.equals(pkg + "-")) return false;
                if (target.equals(pkg) || target.equals(pkg + "!") || target.equals(pkg + "?"))
                    allowed = true;
            }
        }
        return allowed;
    }

}
