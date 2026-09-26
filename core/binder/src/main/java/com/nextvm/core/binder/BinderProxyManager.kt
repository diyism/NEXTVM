package com.nextvm.core.binder

import android.content.Context
import com.nextvm.core.binder.proxy.ActivityManagerProxy
import com.nextvm.core.binder.proxy.PackageManagerProxy
import com.nextvm.core.common.AndroidCompat
import com.nextvm.core.common.findField
import com.nextvm.core.model.GmsServiceRouter
import com.nextvm.core.model.VirtualApp
import com.nextvm.core.services.pm.VirtualPackageManagerService
import timber.log.Timber
import java.lang.reflect.Proxy

/**
 * BinderProxyManager — Installs and manages all Binder IPC proxies.
 *
 * Based on Android 16 frameworks/base analysis:
 * - ActivityManager.IActivityManagerSingleton (Singleton<IActivityManager>)
 * - ActivityThread.sPackageManager (static IPackageManager field)
 *
 * These proxies intercept system service calls from guest apps and
 * redirect them through our virtual engine instead of the real system.
 */
class BinderProxyManager(
    private val context: Context,
    private val virtualPm: VirtualPackageManagerService
) {

    companion object {
        private const val TAG = "BinderProxy"
    }

    private var amProxy: ActivityManagerProxy? = null
    private var pmProxy: PackageManagerProxy? = null

    // Virtual app registry (package name -> VirtualApp)
    private val virtualApps = mutableMapOf<String, VirtualApp>()

    /**
     * Install all Binder proxies.
     * MUST be called after hidden API bypass.
     */
    fun installAllProxies() {
        Timber.tag(TAG).i("Installing Binder proxies...")

        installActivityManagerProxy()
        installPackageManagerProxy()

        Timber.tag(TAG).i("All Binder proxies installed")
    }

    /**
     * Register a virtual app in the proxy system.
     * After registration, system service calls for this package
     * will be intercepted and handled virtually.
     */
    fun registerVirtualApp(app: VirtualApp) {
        virtualApps[app.packageName] = app
        pmProxy?.registerApp(app)
        amProxy?.registerApp(app)
        Timber.tag(TAG).d("Registered virtual app: ${app.packageName}")
    }

    /**
     * Unregister a virtual app from the proxy system.
     */
    fun unregisterVirtualApp(packageName: String) {
        virtualApps.remove(packageName)
        pmProxy?.unregisterApp(packageName)
        amProxy?.unregisterApp(packageName)
        Timber.tag(TAG).d("Unregistered virtual app: $packageName")
    }

    /**
     * Check if a package is a virtual app.
     */
    fun isVirtualPackage(packageName: String): Boolean =
        virtualApps.containsKey(packageName)

    /**
     * Connect the GMS service router to the ActivityManagerProxy.
     * This enables GMS bindService/startService calls from guest apps
     * to be routed through the Hybrid GMS bridge.
     */
    fun setGmsRouter(router: GmsServiceRouter) {
        amProxy?.setGmsRouter(router)
        pmProxy?.setGmsRouter(router)
    }

    /**
     * Get theme resource ID for a specific activity from parsed manifest.
     */
    fun getActivityTheme(packageName: String, activityName: String): Int =
        pmProxy?.getActivityTheme(packageName, activityName) ?: 0

    // === IActivityManager Proxy ===

    /**
     * Install the IActivityManager proxy.
     *
     * Android 16 source (ActivityManager.java line 5787):
     * private static final Singleton<IActivityManager> IActivityManagerSingleton = new Singleton<>() {
     *     protected IActivityManager create() {
     *         final IBinder b = ServiceManager.getService(Context.ACTIVITY_SERVICE);
     *         return IActivityManager.Stub.asInterface(b);
     *     }
     * };
     *
     * We replace the mInstance field of this Singleton with our proxy.
     */
    private fun installActivityManagerProxy() {
        try {
            val fieldName = AndroidCompat.getIActivityManagerSingletonFieldName()
            val amClass = Class.forName("android.app.ActivityManager")
            val singletonField = amClass.getDeclaredField(fieldName)
            singletonField.isAccessible = true
            val singleton = singletonField.get(null)
                ?: throw IllegalStateException("IActivityManagerSingleton is null")

            val singletonClass = Class.forName("android.util.Singleton")
            val instanceField = singletonClass.getDeclaredField("mInstance")
            instanceField.isAccessible = true

            // Force singleton initialization
            val getMethod = singletonClass.getDeclaredMethod("get")
            getMethod.isAccessible = true
            val originalAm = getMethod.invoke(singleton)
                ?: throw IllegalStateException("IActivityManager original instance is null")

            // Create our proxy handler
            amProxy = ActivityManagerProxy(originalAm, context)

            // Create dynamic proxy
            val iamClass = Class.forName("android.app.IActivityManager")
            val proxy = Proxy.newProxyInstance(
                iamClass.classLoader,
                arrayOf(iamClass),
                amProxy!!
            )

            // Replace the singleton's mInstance with our proxy
            instanceField.set(singleton, proxy)

            Timber.tag(TAG).i("IActivityManager proxy installed")

        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Failed to install IActivityManager proxy")
        }
    }

    // === IPackageManager Proxy ===

    /**
     * Install the IPackageManager proxy.
     *
     * Android 16 source (ActivityThread.java):
     * static volatile IPackageManager sPackageManager;
     * Also in ApplicationPackageManager.mPM instance field.
     */
    private fun installPackageManagerProxy() {
        try {
            // Method 1: Replace ActivityThread.sPackageManager
            val atClass = Class.forName("android.app.ActivityThread")
            val spmField = atClass.getDeclaredField("sPackageManager")
            spmField.isAccessible = true
            val originalPm = spmField.get(null)
                ?: run {
                    // Force initialization
                    val getMethod = atClass.getDeclaredMethod("getPackageManager")
                    getMethod.isAccessible = true
                    getMethod.invoke(null)
                    spmField.get(null)
                }
                ?: throw IllegalStateException("sPackageManager is null")

            // Create our proxy handler
            pmProxy = PackageManagerProxy(
                original = originalPm,
                context = context,
                virtualPm = virtualPm,
                callerResolver = VirtualCallerResolver(context, virtualPm)
            )

            // Create dynamic proxy
            val ipmClass = Class.forName("android.content.pm.IPackageManager")
            val proxy = Proxy.newProxyInstance(
                ipmClass.classLoader,
                arrayOf(ipmClass),
                pmProxy!!
            )

            // Replace static field
            spmField.set(null, proxy)

            // Method 2: Also try to replace ApplicationPackageManager.mPM
            try {
                val appPm = context.packageManager
                val mPmField = findField(appPm::class.java, "mPM")
                mPmField?.isAccessible = true
                mPmField?.set(appPm, proxy)
                Timber.tag(TAG).d("Also replaced ApplicationPackageManager.mPM")
            } catch (e: Exception) {
                Timber.tag(TAG).w("Could not replace ApplicationPackageManager.mPM: ${e.message}")
            }

            Timber.tag(TAG).i("IPackageManager proxy installed")

        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Failed to install IPackageManager proxy")
        }
    }
}
