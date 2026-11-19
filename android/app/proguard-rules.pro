# SPDX-FileCopyrightText: 2026 FastKiwi (Sarmad)
# SPDX-License-Identifier: Apache-2.0
# Strip verbose/debug logging from release builds.
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}
# When the UniFFI/JNA bindings arrive, keep rules for com.sun.jna.** and the generated package go here.
