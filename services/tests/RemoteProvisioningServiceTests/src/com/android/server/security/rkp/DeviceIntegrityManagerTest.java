/* SPDX-License-Identifier: Apache-2.0 */
package com.android.server.security.rkp;

import static org.junit.Assert.assertThrows;

import org.json.JSONObject;
import org.junit.Test;

public class DeviceIntegrityManagerTest {
    @Test public void acceptsExplicitPackageModesAndComments() {
        DeviceIntegrityManager.validateTargets("# targets\nandroid\nandroid!\nandroid?\nandroid-\ncom.google.android.gms\n"
                + "com.example.generate!\ncom.example.leaf?\ncom.example.skip-\n");
    }

    @Test public void refusesWildcardsPathsAndUnrecognizedModes() {
        for (String target : new String[] {"*", "com.example.*", "/data/adb", "com.example.app;id",
                "com.example.app!!", "com.example.app other.app", "app"}) {
            assertThrows(IllegalArgumentException.class,
                    () -> DeviceIntegrityManager.validateTargets(target));
        }
    }

    @Test public void validatesGlobalAndPerPackagePatchFields() throws Exception {
        DeviceIntegrityManager.validatePatch(new JSONObject("{\"all\":\"prop\","
                + "\"packages\":{\"com.example.app\":{\"system\":\"2026-11-01\"}}}"), true);
    }

    @Test public void refusesUnknownOrMistypedPatchFields() {
        for (String json : new String[] {"{\"all\":42}", "{\"all\":\"bad-date\"}",
                "{\"unknown\":\"prop\"}", "{\"packages\":{\"com.example.app\":{\"packages\":{}}}}"}) {
            assertThrows(Exception.class,
                    () -> DeviceIntegrityManager.validatePatch(new JSONObject(json), true));
        }
    }

    @Test public void patchPackageNamesCannotContainTargetModesOrComments() {
        for (String name : new String[] {"com.example.app!", "com.example.app?",
                "com.example.app-", "# comment", "", "com.example.app\nother.package"}) {
            assertThrows(IllegalArgumentException.class, () -> {
                JSONObject packages = new JSONObject().put(name, new JSONObject());
                DeviceIntegrityManager.validatePatch(new JSONObject().put("packages", packages), true);
            });
        }
    }
}
