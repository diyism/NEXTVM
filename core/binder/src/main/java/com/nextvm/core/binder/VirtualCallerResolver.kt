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

    fun currentProcessName(): String? {
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

    private fun processSlot(): Int {
        val processName = currentProcessName() ?: return -1
        val match = SLOT_PROCESS.find(processName) ?: return -1
        return match.groupValues[1].toIntOrNull() ?: -1
    }
}
