// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.os.SystemClock
import android.provider.Settings
import android.util.Log
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.net.HttpURLConnection
import java.net.URL

private const val TUNNEL_NOTIFICATION_CHANNEL_ID = CsqttConstants.Notifications.TUNNEL_CHANNEL_ID
private const val TUNNEL_NOTIFICATION_ID = CsqttConstants.Notifications.TUNNEL_NOTIFICATION_ID
private const val NETWORK_LOSS_DEBOUNCE_MS = 4_000L
private const val VK_PROBE_CONNECT_TIMEOUT_MS = 3_000
private const val VK_PROBE_READ_TIMEOUT_MS = 3_000
private val VK_PROBE_URLS = listOf(
    "https://login.vk.ru/",
    "https://api.vk.com/",
    "https://vk.ru/",
)

private data class ResolvedVkHashes(
    val value: String,
    val allowWorkerRedistribution: Boolean,
    val mode: String = CsqttConstants.VkAutoHash.MODE_MANUAL,
    val accessToken: String = "",
)

class TunnelService : Service() {
    private val serviceJob = SupervisorJob()
    private val serviceScope = CoroutineScope(serviceJob + Dispatchers.Default)

    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null
    private var updateJob: Job? = null
    private var lastNotificationText: String? = null
    private var isStopping = false
    private var resourcesReleased = false
    private var foregroundStarted = false
    private lateinit var connectivityManager: ConnectivityManager
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var airplaneModeReceiver: BroadcastReceiver? = null
    private var deviceStateReceiver: BroadcastReceiver? = null
    private var networkLossJob: Job? = null
    private val physicalNetworks = PhysicalNetworkTracker<Network>()
    private val physicalCandidates = mutableSetOf<Network>()
    private val vkProbeJobs = mutableMapOf<Network, Job>()
    private val vkProbeLock = Any()
    private var vkRecoveryJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        TunnelManager.activeScope = serviceScope
        createNotificationChannel()

        acquireWakeLock()
        connectivityManager = getSystemService(ConnectivityManager::class.java)
        registerAirplaneModeReceiver()
        registerDeviceStateReceiver()
        registerPhysicalNetworkCallback()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            return if (restoreTunnel()) START_STICKY else START_NOT_STICKY
        }

        when (intent.action) {
            "START" -> {
                TunnelManager.starting.value = true
                val notification = createNotification("Запуск...")
                if (!tryStartPersistentForeground(notification, "запуск VPN")) {
                    TunnelManager.starting.value = false
                    stopSelf()
                    return START_NOT_STICKY
                }

                val intentGenId = intent.getLongExtra("generation_id", 0L)
                val intentSalt = intent.getStringExtra("session_salt") ?: ""

                serviceScope.launch {
                    try {
                        val store = SettingsStore(applicationContext)
                        val genId = store.reserveConnectionGeneration(intentGenId)
                        val salt = if (intentSalt.isNotBlank() && genId == intentGenId) {
                            intentSalt
                        } else {
                            java.util.UUID.randomUUID().toString().replace("-", "")
                        }

                        val requestedWorkers = intent.getIntExtra("workers_per_hash", 18)
                        val vkAuthMode = sanitizeVkAuthMode(intent.getStringExtra("vk_auth_mode"))
                        val isExtra = store.extraWorkers.first()
                        val maxWorkers = if (isExtra) CsqttConstants.Tunnel.MAX_WORKERS else 90
                        val workersPerHash = WorkerCountPolicy.normalize(requestedWorkers, maximum = maxWorkers)
                        val intentHashes = intent.getStringExtra("vk_hashes") ?: ""
                        val hashesFromLink = intent.getBooleanExtra("vk_hashes_from_link", false)
                        val accountAutoJs = vkAuthMode == CsqttConstants.VkAuth.MODE_AUTO_JS
                        if (accountAutoJs) {
                            store.saveVkAuthMode(CsqttConstants.VkAuth.MODE_AUTO_JS)
                            TunnelManager.updateLog(
                                "vk_js_account_mode",
                                "[VK JS] Один звонок · хеши Auto JS · максимум 162 потока",
                                40,
                                false,
                            )
                        }
                        if (!awaitVkNetwork()) return@launch
                        val resolvedHashes = if (hashesFromLink && !accountAutoJs) {
                            ResolvedVkHashes(intentHashes, false)
                        } else {
                            resolveAutoHashes(
                                store,
                                intentHashes,
                                workersPerHash,
                                if (accountAutoJs) CsqttConstants.VkAutoHash.MODE_AUTO_JS else null,
                            )
                        }
                        if (resolvedHashes == null) {
                            TunnelManager.updateLog(
                                "vk_auto_calls_error",
                                "Авто-режим: не удалось создать звонки VK (нет access token или ошибка VK)",
                                99,
                                true,
                            )
                            launch(Dispatchers.Main) { stopTunnel() }
                            return@launch
                        }

                        val params = TunnelParams(
                            peer = intent.getStringExtra("peer") ?: "",
                            vkHashes = resolvedHashes.value,
                            secondaryVkHash = intent.getStringExtra("secondary_vk_hash") ?: "",
                            workersPerHash = workersPerHash,
                            port = intent.getIntExtra("port", 0),
                            sni = intent.getStringExtra("sni") ?: "",
                            connectionPassword = intent.getStringExtra("connection_password") ?: "",
                            protocol = intent.getStringExtra("protocol") ?: "udp",
                            vkAuthMode = vkAuthMode,
                            captchaMode = sanitizeCaptchaMode(intent.getStringExtra("captcha_mode")),
                            captchaSolveMethod = intent.getStringExtra("captcha_solve_method") ?: "auto",
                            fingerprint = intent.getStringExtra("fingerprint") ?: "firefox",
                            clientIds = intent.getStringExtra("client_ids") ?: "8202606,6287487",
                            obfsMode = intent.getStringExtra("obfs_mode")
                                ?.takeIf { it.isNotBlank() }
                                ?.let { if (it == "mix" || it == "vkquic" || it == "callv2") "video" else it }
                                ?: CsqttConstants.Tunnel.DEFAULT_OBFS_MODE,
                            generationId = genId,
                            sessionSalt = salt,
                            allowHashRedistribution = resolvedHashes.allowWorkerRedistribution,
                            vkHashMode = resolvedHashes.mode,
                            vkAccessToken = resolvedHashes.accessToken,
                        )
                        launch(Dispatchers.Main) {
                            startTunnel(params)
                        }
                    } catch (e: Exception) {
                        Log.e("TunnelService", "Unable to prepare tunnel start", e)
                        TunnelManager.updateLog(
                            "service_start_error",
                            "Ошибка подготовки VPN-сервиса: ${e.message ?: e.javaClass.simpleName}",
                            99,
                            true,
                        )
                        launch(Dispatchers.Main) { stopTunnel() }
                    }
                }
            }
            "STOP", "DISCONNECT" -> stopTunnel()
            CsqttConstants.General.ACTION_RESTART_WHEN_VK_REACHABLE -> verifyVkAndRestart()
            "DEPLOY_START" -> {
                try {
                    isStopping = false
                    resourcesReleased = false
                    val notification = createNotification("Установка на сервер...", "DEPLOY_CANCEL", "Отменить")
                    startPersistentForeground(notification)
                    prepareForDeploy()
                    acquireWakeLock()
                } catch (e: Exception) {
                    DeployManager.writeError(
                        "Deploy foreground service error (${e.javaClass.simpleName}): ${e.message}\n" +
                            e.stackTraceToString().take(1200)
                    )
                    TunnelManager.addDeployErrorLog(
                        "Не удалось запустить сервис установки: ${e.message?.take(120) ?: e.javaClass.simpleName}"
                    )
                    DeployManager.stopDeploy("Не удалось запустить сервис установки: ${e.message?.take(120)}")
                    runCatching { releaseTunnelResources() }
                    runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
                    foregroundStarted = false
                    stopSelf()
                    return START_NOT_STICKY
                }
            }
            "DEPLOY_CANCEL" -> {
                com.csqtt.client.DeployManager.writeError("✗ Установка отменена пользователем")
                com.csqtt.client.DeployManager.stopDeploy("error: Отменена пользователем")
                if (TunnelManager.running.value) {
                    lastNotificationText = null
                    updateNotification(buildTunnelNotificationText())
                } else {
                    stopTunnel()
                }
            }
            "DEPLOY_STOP" -> {
                if (!TunnelManager.running.value) {
                    stopTunnel()
                } else {
                    updateNotification("Туннель активен")
                }
            }
            "RESTORE_NOTIFICATION" -> {
                if (foregroundStarted && !isStopping) {
                    lastNotificationText = null
                    updateNotification(currentNotificationText())
                }
            }
        }
        return START_STICKY
    }

    private fun restoreTunnel(): Boolean {
        TunnelManager.starting.value = true
        val notification = createNotification("Восстановление соединения...")
        if (!tryStartPersistentForeground(notification, "восстановление VPN")) {
            TunnelManager.starting.value = false
            stopSelf()
            return false
        }

        val appContext = applicationContext
        TunnelManager.scope.launch {
            try {
                val store = SettingsStore(appContext)

                // Проверяем: был ли CSQTT активен до перезапуска.
                // Если нет — не поднимаем VPN: устройство может работать с другим VPN (напр. WireGuard).
                // Android VPN API: при establish() всегда отзывает текущий VPN другого приложения.
                val wasRunning = store.tunnelWasRunning.first()
                if (!wasRunning) {
                    Log.d("TunnelService", "restoreTunnel: tunnelWasRunning=false, автостарт отменён — чужой VPN не нужно убивать")
                    launch(Dispatchers.Main) { stopTunnel() }
                    return@launch
                }

                val source = resolveConnectionSource(store)
                val genId = store.reserveConnectionGeneration()
                val salt = java.util.UUID.randomUUID().toString().replace("-", "")
                val vkAuthMode = sanitizeVkAuthMode(store.vkAuthMode.first())
                val workersPerHash = WorkerCountPolicy.normalize(store.workersPerHash.first())
                val accountAutoJs = vkAuthMode == CsqttConstants.VkAuth.MODE_AUTO_JS
                if (!awaitVkNetwork()) return@launch
                val restoredHashes = when {
                    source == null -> null
                    source.hashesFromLink && !accountAutoJs -> ResolvedVkHashes(source.hashes, false)
                    else -> resolveAutoHashes(
                        store,
                        source.hashes,
                        workersPerHash,
                        if (accountAutoJs) CsqttConstants.VkAutoHash.MODE_AUTO_JS else null,
                    )
                }
                val params = TunnelParams(
                    peer = source?.peer.orEmpty(),
                    vkHashes = restoredHashes?.value ?: "",
                    secondaryVkHash = store.secondaryVkHash.first(),
                    workersPerHash = workersPerHash,
                    port = store.listenPort.first(),
                    sni = store.sni.first(),
                    connectionPassword = source?.password.orEmpty(),
                    obfsMode = store.obfsMode.first(),
                    vkAuthMode = vkAuthMode,
                    captchaMode = sanitizeCaptchaMode(store.captchaMode.first()),
                    captchaSolveMethod = store.captchaSolveMethod.first(),
                    fingerprint = store.selectedFingerprint.first(),
                    clientIds = store.activeClientIds.first(),
                    generationId = genId,
                    sessionSalt = salt,
                    allowHashRedistribution = restoredHashes?.allowWorkerRedistribution == true,
                    vkHashMode = restoredHashes?.mode ?: CsqttConstants.VkAutoHash.MODE_MANUAL,
                    vkAccessToken = restoredHashes?.accessToken.orEmpty(),
                )
                if (
                    params.peer.isNotEmpty() &&
                    (
                        params.vkHashes.isNotEmpty() ||
                            params.vkHashMode == CsqttConstants.VkAutoHash.MODE_AUTO_JS
                    )
                ) {
                    launch(Dispatchers.Main) {
                        startTunnel(params)
                    }
                } else {
                    launch(Dispatchers.Main) {
                        stopTunnel()
                    }
                }
            } catch (e: Exception) {
                launch(Dispatchers.Main) {
                    stopTunnel()
                }
            }
        }
        return true
    }

    private suspend fun resolveAutoHashes(
        store: SettingsStore,
        fallbackHashes: String,
        workersPerHash: Int,
        forcedMode: String? = null,
    ): ResolvedVkHashes? {
        return when (val mode = forcedMode ?: store.vkHashMode.first()) {
            CsqttConstants.VkAutoHash.MODE_AUTO_API -> {
                val token = store.vkAccessToken.first()
                val result = VkAutoCallsManager.startAutoCalls(applicationContext, token, workersPerHash)
                    ?: return null
                ResolvedVkHashes(
                    result.hashes,
                    result.needsWorkerRedistribution,
                    mode,
                )
            }

            CsqttConstants.VkAutoHash.MODE_AUTO_JS -> {
                val token = store.vkAccessToken.first()
                if (token.isBlank()) return null
                ResolvedVkHashes(
                    "",
                    true,
                    mode,
                    token,
                )
            }

            else -> ResolvedVkHashes(fallbackHashes, false)
        }
    }

    private fun tryStartPersistentForeground(notification: Notification, operation: String): Boolean {
        return try {
            startPersistentForeground(notification)
            true
        } catch (e: Exception) {
            Log.e("TunnelService", "Foreground service rejected during $operation", e)
            TunnelManager.updateLog(
                "foreground_start_error",
                "Android заблокировал foreground-сервис ($operation): ${e.message ?: e.javaClass.simpleName}",
                99,
                true,
            )
            false
        }
    }

    private fun startTunnel(params: TunnelParams) {
        updateNotification("Подключение...")
        acquireWakeLock()
        acquireWifiLock()

        CaptchaWebViewManager.onTunnelStart(applicationContext)

        // Сохраняем: пользователь явно запустил CSQTT — авторестарт при холодном старте разрешён
        serviceScope.launch {
            runCatching { SettingsStore(applicationContext).saveTunnelWasRunning(true) }
        }

        TunnelManager.start(this, params)
        if (!physicalNetworks.hasUsableNetwork()) {
            schedulePhysicalNetworkLoss()
        }
        TunnelManager.scope.launch(Dispatchers.Main) {
            VkAutoCallsManager.replayPendingLogs()
        }
        startStatsUpdater()
    }

    private fun registerPhysicalNetworkCallback() {
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                rememberPhysicalCandidate(network)
                startVkNetworkProbe(network)
            }

            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                if (hasPhysicalInternetCapability(capabilities)) {
                    rememberPhysicalCandidate(network)
                    startVkNetworkProbe(network)
                } else {
                    forgetPhysicalNetwork(network)
                }
            }

            override fun onLost(network: Network) {
                forgetPhysicalNetwork(network)
            }
        }
        networkCallback = callback
        runCatching {
            connectivityManager.registerNetworkCallback(
                NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build(),
                callback,
            )
        }.onFailure {
            Log.w("TunnelService", "Unable to register physical network callback", it)
            networkCallback = null
        }
    }

    private fun rememberPhysicalCandidate(network: Network) {
        synchronized(vkProbeLock) {
            physicalCandidates.add(network)
        }
    }

    private fun isPhysicalCandidate(network: Network): Boolean = synchronized(vkProbeLock) {
        network in physicalCandidates
    }

    private fun startVkNetworkProbe(network: Network) {
        if (physicalNetworks.isUsable(network)) return
        synchronized(vkProbeLock) {
            if (network !in physicalCandidates || vkProbeJobs[network]?.isActive == true) return
            val job = serviceScope.launch(Dispatchers.IO, start = CoroutineStart.LAZY) {
                var failures = 0
                try {
                    while (isActive && !physicalNetworks.isUsable(network)) {
                        if (probeVkThrough(network)) {
                            if (!isActive || !isPhysicalCandidate(network)) return@launch
                            updatePhysicalNetwork(network, true)
                            return@launch
                        }
                        failures++
                        delay(vkProbeRetryDelayMs(failures))
                    }
                } finally {
                    synchronized(vkProbeLock) {
                        if (vkProbeJobs[network] === coroutineContext[Job]) {
                            vkProbeJobs.remove(network)
                        }
                    }
                }
            }
            vkProbeJobs[network] = job
            job.start()
        }
    }

    private fun forgetPhysicalNetwork(network: Network) {
        synchronized(vkProbeLock) {
            physicalCandidates.remove(network)
            vkProbeJobs.remove(network)?.cancel()
        }
        updatePhysicalNetwork(network, false)
    }

    private fun probeVkThrough(network: Network): Boolean = VK_PROBE_URLS.any { address ->
        val connection = runCatching {
            network.openConnection(URL(address)) as HttpURLConnection
        }.getOrNull() ?: return@any false
        try {
            connection.instanceFollowRedirects = false
            connection.connectTimeout = VK_PROBE_CONNECT_TIMEOUT_MS
            connection.readTimeout = VK_PROBE_READ_TIMEOUT_MS
            connection.useCaches = false
            connection.requestMethod = "GET"
            connection.setRequestProperty("Connection", "close")
            connection.setRequestProperty("Range", "bytes=0-0")
            connection.setRequestProperty("Accept-Encoding", "identity")
            connection.setRequestProperty("User-Agent", "Mozilla/5.0")
            isVkProbeHttpResponse(connection.responseCode)
        } catch (_: Exception) {
            false
        } finally {
            connection.disconnect()
        }
    }

    private suspend fun awaitVkNetwork(): Boolean {
        while (serviceScope.coroutineContext[Job]?.isActive != false) {
            if (physicalNetworks.hasUsableNetwork()) return true
            currentPhysicalCandidates().forEach { network ->
                rememberPhysicalCandidate(network)
                startVkNetworkProbe(network)
            }
            delay(250)
        }
        return false
    }

    private fun currentPhysicalCandidates(): List<Network> {
        val candidates = synchronized(vkProbeLock) { physicalCandidates.toList() }
        if (candidates.isNotEmpty()) return candidates
        val active = runCatching { connectivityManager.activeNetwork }.getOrNull() ?: return emptyList()
        val usable = runCatching {
            connectivityManager.getNetworkCapabilities(active)
                ?.let(::hasPhysicalInternetCapability) == true
        }.getOrDefault(false)
        return if (usable) listOf(active) else emptyList()
    }

    private fun verifyVkAndRestart() {
        if (vkRecoveryJob?.isActive == true) return
        vkRecoveryJob = serviceScope.launch(Dispatchers.IO) {
            try {
                while (isActive && TunnelManager.running.value && TunnelManager.activeWorkers.value == 0) {
                    val ready = currentPhysicalCandidates().firstOrNull(::probeVkThrough)
                    if (ready != null) {
                        rememberPhysicalCandidate(ready)
                        updatePhysicalNetwork(ready, true)
                        if (TunnelManager.activeWorkers.value == 0) {
                            TunnelManager.restartAfterVkRecovery(applicationContext)
                        }
                        return@launch
                    }
                    delay(vkProbeRetryDelayMs(1))
                }
            } finally {
                if (vkRecoveryJob === coroutineContext[Job]) vkRecoveryJob = null
            }
        }
    }

    private fun updatePhysicalNetwork(network: Network, usable: Boolean) {
        val transition = physicalNetworks.update(network, usable)
        when (transition) {
            PhysicalNetworkTransition.AVAILABLE -> {
                networkLossJob?.cancel()
                networkLossJob = null
                TunnelManager.onPhysicalNetworkAvailable(applicationContext)
            }
            PhysicalNetworkTransition.UNAVAILABLE -> schedulePhysicalNetworkLoss()
            PhysicalNetworkTransition.CHANGED -> Unit
            PhysicalNetworkTransition.NONE -> Unit
        }
    }

    private fun registerDeviceStateReceiver() {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                when (intent.action) {
                    Intent.ACTION_SCREEN_ON -> TunnelManager.requestPathValidation("screen_on")
                    Intent.ACTION_USER_PRESENT -> TunnelManager.requestPathValidation("user_present")
                    Intent.ACTION_SCREEN_OFF -> Unit
                    PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED -> {
                        val power = getSystemService(POWER_SERVICE) as PowerManager
                        if (!power.isDeviceIdleMode) {
                            TunnelManager.requestPathValidation("device_idle_exit")
                        }
                    }
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_USER_PRESENT)
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED)
        }
        val registered = runCatching {
            ContextCompat.registerReceiver(
                this,
                receiver,
                filter,
                ContextCompat.RECEIVER_NOT_EXPORTED,
            )
        }.isSuccess
        if (registered) deviceStateReceiver = receiver
    }

    private fun registerAirplaneModeReceiver() {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.action != Intent.ACTION_AIRPLANE_MODE_CHANGED) return
                if (isAirplaneModeOn() && !physicalNetworks.hasUsableNetwork()) {
                    schedulePhysicalNetworkLoss()
                }
            }
        }
        val registered = runCatching {
            ContextCompat.registerReceiver(
                this,
                receiver,
                IntentFilter(Intent.ACTION_AIRPLANE_MODE_CHANGED),
                ContextCompat.RECEIVER_EXPORTED,
            )
        }.isSuccess
        if (registered) airplaneModeReceiver = receiver
    }

    private fun schedulePhysicalNetworkLoss() {
        networkLossJob?.cancel()
        networkLossJob = serviceScope.launch {
            delay(NETWORK_LOSS_DEBOUNCE_MS)
            if (physicalNetworks.hasUsableNetwork()) return@launch
            TunnelManager.pauseForNoNetwork(physicalNetworkPauseReason(isAirplaneModeOn()))
        }
    }

    private fun hasPhysicalInternetCapability(capabilities: NetworkCapabilities): Boolean =
        capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)

    private fun isAirplaneModeOn(): Boolean =
        runCatching {
            Settings.Global.getInt(contentResolver, Settings.Global.AIRPLANE_MODE_ON, 0) != 0
        }.getOrDefault(false)

    private fun stopTunnel() {
        if (isStopping) return
        isStopping = true
        TunnelManager.starting.value = false
        updateJob?.cancel()
        // Сохраняем: пользователь явно остановил CSQTT — авторестарт при холодном старте запрещён
        serviceScope.launch {
            runCatching { SettingsStore(applicationContext).saveTunnelWasRunning(false) }
        }
        releaseTunnelResources()
        stopForeground(STOP_FOREGROUND_REMOVE)
        foregroundStarted = false
        stopSelf()
    }

    private fun prepareForDeploy() {
        updateJob?.cancel()
        updateJob = null
        CaptchaWebViewManager.onTunnelStop()
        VkAutoCallsManager.finishActiveCalls()
        TunnelManager.stop()
        releaseWifiLock()
    }

    private fun releaseTunnelResources() {
        if (resourcesReleased) return
        resourcesReleased = true
        CaptchaWebViewManager.onTunnelStop()
        VkAutoCallsManager.finishActiveCalls()
        TunnelManager.stop()
        releaseWakeLock()
        releaseWifiLock()
    }

    private fun sanitizeCaptchaMode(mode: String?): String {
        return when (mode?.lowercase()) {
            "auto" -> "auto"
            "rjs" -> "rjs"
            "wv" -> "wv"
            else -> "auto"
        }
    }

    private fun sanitizeVkAuthMode(mode: String?): String {
        return when (mode?.lowercase()) {
            CsqttConstants.VkAuth.MODE_CAPTCHA -> CsqttConstants.VkAuth.MODE_CAPTCHA
            CsqttConstants.VkAuth.MODE_AUTO_JS -> CsqttConstants.VkAuth.MODE_AUTO_JS
            else -> CsqttConstants.VkAuth.MODE_CALLS
        }
    }

    @SuppressLint("WakelockTimeout")
    private fun acquireWakeLock() {
        if (wakeLock?.isHeld == true) return
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "csqtt:tunnel_cpu"
        ).apply { 
            setReferenceCounted(false)
            acquire()
        }
    }

    @Suppress("DEPRECATION")
    private fun acquireWifiLock() {
        if (wifiLock?.isHeld == true) return
        val wm = applicationContext.getSystemService(WIFI_SERVICE) as WifiManager

        val mode = if (Build.VERSION.SDK_INT >= 29) {
            WifiManager.WIFI_MODE_FULL_LOW_LATENCY
        } else {
            WifiManager.WIFI_MODE_FULL_HIGH_PERF
        }

        wifiLock = wm.createWifiLock(mode, "csqtt:wifi_perf").apply { 
            setReferenceCounted(false)
            acquire() 
        }
    }

    private fun releaseWakeLock() {
        if (wakeLock?.isHeld == true) {
            wakeLock?.release()
        }
        wakeLock = null
    }

    private fun releaseWifiLock() {
        if (wifiLock?.isHeld == true) {
            wifiLock?.release()
        }
        wifiLock = null
    }

    private fun startStatsUpdater() {
        updateJob?.cancel()
        updateJob = serviceScope.launch(Dispatchers.Main) {
            var wasEverUp = TunnelManager.running.value || TunnelManager.processStartedAtMs > 0L
            val startedAt = SystemClock.elapsedRealtime()
            delay(1000)
            while (isActive) {
                val running = TunnelManager.running.value
                wasEverUp = wasEverUp || running || TunnelManager.processStartedAtMs > 0L
                if (
                    TunnelServicePolicy.shouldStop(
                        wasEverRunning = wasEverUp,
                        running = running,
                        elapsedMs = SystemClock.elapsedRealtime() - startedAt,
                    )
                ) {
                    stopTunnel()
                    break
                }
                updateNotification(currentNotificationText())
                delay(2000)
            }
        }
    }

    private fun currentNotificationText(): String {
        return buildTunnelNotificationText()
    }

    private fun buildTunnelNotificationText(): String {
        val statsText = TunnelManager.stats.value.trim()
        return when {
            statsText.isEmpty() -> "Туннель активен"
            statsText == "Ожидание данных..." -> "Туннель активен"
            else -> statsText
        }
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            TUNNEL_NOTIFICATION_CHANNEL_ID,
            "CSQTT Туннель",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Уведомление о работе туннеля"
            setShowBadge(false)

            lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            setSound(null, null)
            enableVibration(false)
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun createNotification(text: String, actionName: String = "STOP", actionTitle: String = "Отключить"): Notification {
        val openIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val stopIntent = PendingIntent.getService(
            this, if (actionName == "STOP") 1 else 2,
            Intent(this, TunnelService::class.java).apply { action = actionName },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val restoreIntent = PendingIntent.getService(
            this, 3,
            Intent(this, TunnelService::class.java).apply { action = "RESTORE_NOTIFICATION" },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, TUNNEL_NOTIFICATION_CHANNEL_ID)
            .setContentTitle("CSQTT")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_stat_c)
            .setOngoing(true)
            .setLocalOnly(true)
            .setContentIntent(openIntent)
            .addAction(R.drawable.ic_stop, actionTitle, stopIntent)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)

            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)

            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setOnlyAlertOnce(true) 
            .setSilent(true) 
            .setShowWhen(false)
            .setUsesChronometer(false)
            .setWhen(0L)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setDeleteIntent(restoreIntent)
            .build()
            .also {
                it.flags = it.flags or Notification.FLAG_ONGOING_EVENT or Notification.FLAG_NO_CLEAR or Notification.FLAG_FOREGROUND_SERVICE
            }
    }

    private fun startPersistentForeground(notification: Notification) {
        notification.flags = notification.flags or Notification.FLAG_ONGOING_EVENT or Notification.FLAG_NO_CLEAR or Notification.FLAG_FOREGROUND_SERVICE
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(TUNNEL_NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(TUNNEL_NOTIFICATION_ID, notification)
        }
        foregroundStarted = true
    }

    private fun updateNotification(text: String) {
        if (lastNotificationText == text && isNotificationVisible()) return
        lastNotificationText = text
        val notification = createNotification(text)
        startPersistentForeground(notification)
    }

    private fun isNotificationVisible(): Boolean {
        return runCatching {
            getSystemService(NotificationManager::class.java)
                .activeNotifications
                .any { it.id == TUNNEL_NOTIFICATION_ID }
        }.getOrDefault(false)
    }

    override fun onDestroy() {
        isStopping = true
        updateJob?.cancel()
        networkLossJob?.cancel()
        networkLossJob = null
        vkRecoveryJob?.cancel()
        vkRecoveryJob = null
        synchronized(vkProbeLock) {
            vkProbeJobs.values.forEach(Job::cancel)
            vkProbeJobs.clear()
            physicalCandidates.clear()
        }
        releaseTunnelResources()
        if (foregroundStarted) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            foregroundStarted = false
        }
        serviceJob.cancel()
        networkCallback?.let { callback ->
            runCatching { connectivityManager.unregisterNetworkCallback(callback) }
        }
        networkCallback = null
        airplaneModeReceiver?.let { receiver ->
            runCatching { unregisterReceiver(receiver) }
        }
        airplaneModeReceiver = null
        deviceStateReceiver?.let { receiver ->
            runCatching { unregisterReceiver(receiver) }
        }
        deviceStateReceiver = null
        physicalNetworks.clear()
        TunnelManager.activeScope = TunnelManager.scope
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null


}
