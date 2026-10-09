package com.nextvm.core.binder

import android.app.Application
import android.content.Context
import android.os.Build
import com.nextvm.core.services.pm.VirtualPackageManagerService
import timber.log.Timber

/**
 * Identifies calls made from one of NEXTVM's stub processes.
 *
 * Virtual apps are launched in processes such as com.nextvm.app:p0.  The
 * package-manager proxy is also installed in the host process, so checking
 * only whether virtual packages are registered would incorrectly hide the
 * host's real package list from the NEXTVM UI.
 */
class VirtualCallerResolver(
    private val context: Context,
    private val virtualPm: VirtualPackageManagerService
) {
    companion object {
        private const val TAG = "VirtualCaller"
        private val SLOT_PROCESS = Regex("(?:^|:)p(\\d+)(?::.*)?$")

        /**
         * Slot captured from the stub process name BEFORE the process is
         * renamed to the guest identity. Once the framework-visible
         * process name becomes the guest's, [processSlot] can no longer
         * parse the slot out of it and must use this cache — otherwise
         * PM isolation breaks (resolver would report "not a guest").
         */
        @Volatile
        private var cachedSlot: Int? = null

        private fun readProcessName(): String? {
            return try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    Application.getProcessName()
                } else {
                    val activityThread = Class.forName("android.app.ActivityThread")
                    val method = activityThread.getDeclaredMethod("currentProcessName")
                    method.isAccessible = true
                    method.invoke(null) as? String
                }
            } catch (e: Exception) {
                Timber.tag(TAG).w(e, "Unable to determine current process name")
                null
            }
        }

        /**
         * Capture the stub slot from the current process name and cache
         * it process-wide. MUST be called before the process name is
         * rewritten to the guest identity.
         */
        fun cacheProcessSlotFromCurrentName() {
            if (cachedSlot != null) return
            val name = readProcessName() ?: return
            val slot = SLOT_PROCESS.find(name)?.groupValues?.get(1)?.toIntOrNull() ?: return
            cachedSlot = slot
            Timber.tag(TAG).i("Cached guest process slot $slot from process name $name")
        }
    }

    fun isGuestProcess(): Boolean = processSlot() >= 0

    fun currentInstanceId(): String? {
        val slot = processSlot()
        if (slot < 0) return null
        return virtualPm.getAllPackageNames()
            .asSequence()
            .mapNotNull { virtualPm.getRecord(it) }
            .firstOrNull { it.virtualApp.processSlot == slot }
            ?.virtualApp
            ?.instanceId
    }

    fun currentProcessName(): String? = readProcessName()

    private fun processSlot(): Int {
        cachedSlot?.let { return it }
        val processName = currentProcessName() ?: return -1
        val match = SLOT_PROCESS.find(processName) ?: return -1
        return match.groupValues[1].toIntOrNull() ?: -1
    }
}
