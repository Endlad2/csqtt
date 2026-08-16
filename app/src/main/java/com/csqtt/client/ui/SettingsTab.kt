// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import com.csqtt.client.showRaisedToast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.lerp
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Tag
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.csqtt.client.SettingsStore
import com.csqtt.client.TunnelManager
import com.csqtt.client.TunnelService
import com.csqtt.client.TunnelAuthSnapshot
import com.csqtt.client.CSQTTColors
import com.csqtt.client.CsqttConstants
import com.csqtt.client.WorkerCountPolicy
import com.csqtt.client.VkHashValidationCodec
import com.csqtt.client.VkHashValidator
import com.csqtt.client.ui.components.CsqttScreen
import com.csqtt.client.ui.components.CsqttSettingRow
import com.csqtt.client.ui.dialogs.HashesDialog
import com.csqtt.client.ui.dialogs.SecretsDialog
import com.csqtt.client.ui.dialogs.VkAuthDialog
import com.csqtt.client.ui.dialogs.VkTokenRevokeDialog
import com.csqtt.client.ui.utils.parseCsqttLink
import com.csqtt.client.ui.utils.peerAddress
import com.csqtt.client.ui.utils.stripVkUrlStatic
import com.csqtt.client.VkAuthWebViewManager
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.first
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import kotlin.math.roundToInt

private const val WORKERS_PER_GROUP = CsqttConstants.Tunnel.WORKERS_PER_GROUP

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun SettingsTab(settingsStore: SettingsStore, tunnelAuthSettings: TunnelAuthSnapshot) {
    val context = LocalContext.current.applicationContext
    val scope = rememberCoroutineScope()
    SettingsTabContent(context, scope, settingsStore, tunnelAuthSettings)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun SettingsTabContent(
    context: android.content.Context,
    scope: kotlinx.coroutines.CoroutineScope,
    settingsStore: SettingsStore,
    tunnelAuthSettings: TunnelAuthSnapshot,
) {
    val savedConnectionPassword = tunnelAuthSettings.connectionPassword
    val savedManualPortsEnabled by settingsStore.manualPortsEnabled.collectAsStateWithLifecycle(initialValue = false)
    val savedServerPeerPort by settingsStore.serverPeerPort.collectAsStateWithLifecycle(initialValue = CsqttConstants.Network.DEFAULT_SERVER_PEER_PORT)
    val savedListenPort by settingsStore.listenPort.collectAsStateWithLifecycle(initialValue = CsqttConstants.Network.DEFAULT_LOCAL_PORT)

    val activeProfile = tunnelAuthSettings.profile
    val csqttLinkMode by settingsStore.csqttLinkMode.collectAsStateWithLifecycle(initialValue = false)
    val csqttLink by settingsStore.csqttLink.collectAsStateWithLifecycle(initialValue = "")

    val activeFingerprint by settingsStore.selectedFingerprint.collectAsStateWithLifecycle(initialValue = CsqttConstants.Tunnel.DEFAULT_FINGERPRINT)
    val activeClientIds by settingsStore.activeClientIds.collectAsStateWithLifecycle(initialValue = CsqttConstants.Tunnel.DEFAULT_CLIENT_IDS)
    val vkHashCheckResultsJson by settingsStore.vkHashCheckResults.collectAsStateWithLifecycle(initialValue = "{}")
    val vkHashCheckResults = remember(vkHashCheckResultsJson) {
        VkHashValidationCodec.decode(vkHashCheckResultsJson)
    }
    val savedObfsMode by settingsStore.obfsMode.collectAsStateWithLifecycle(
        initialValue = CsqttConstants.Tunnel.DEFAULT_OBFS_MODE,
    )
    val obfsModeLoaded by settingsStore.obfsMode.collectAsStateWithLifecycle(initialValue = SettingsStore.cachedObfsMode)
    val linkModeLoaded by settingsStore.csqttLinkMode.collectAsStateWithLifecycle(initialValue = SettingsStore.cachedCsqttLinkMode)
    val savedHashMode by settingsStore.vkHashMode.collectAsStateWithLifecycle(initialValue = SettingsStore.cachedVkHashMode)
    val savedVkAccessToken by settingsStore.vkAccessToken.collectAsStateWithLifecycle(initialValue = SettingsStore.cachedVkAccessToken)

    val tunnelRunning by TunnelManager.running.collectAsStateWithLifecycle()
    val tunnelStarting by TunnelManager.starting.collectAsStateWithLifecycle()

    val cooldownActive by TunnelManager.cooldownActive.collectAsStateWithLifecycle()
    val uptimeSeconds by TunnelManager.uptimeSeconds.collectAsStateWithLifecycle()
    var wasRunning by remember { mutableStateOf(false) }
    var showObfsGeneralDialog by rememberSaveable { mutableStateOf(false) }
    var showObfsDetailDialog by rememberSaveable { mutableStateOf<String?>(null) }
    var showHashModeGeneralDialog by rememberSaveable { mutableStateOf(false) }
    var showHashModeDetailDialog by rememberSaveable { mutableStateOf<String?>(null) }
    var showWorkModeGeneralDialog by rememberSaveable { mutableStateOf(false) }
    var showWorkModeDetailDialog by rememberSaveable { mutableStateOf<String?>(null) }
    var showVkAuthDialog by rememberSaveable { mutableStateOf(false) }
    var showVkRevokeDialog by rememberSaveable { mutableStateOf(false) }
    var vkAuthMode by rememberSaveable { mutableStateOf(CsqttConstants.VkAuth.MODE_CALLS) }

    val hashSettingsLoaded = savedHashMode != null && savedVkAccessToken != null
    val accountAutoJsMode = vkAuthMode == CsqttConstants.VkAuth.MODE_AUTO_JS
    val autoHashMode = accountAutoJsMode || (
        savedHashMode != null && savedHashMode != CsqttConstants.VkAutoHash.MODE_MANUAL
    )
    val vkTokenActive = savedVkAccessToken?.isNotBlank() == true

    LaunchedEffect(hashSettingsLoaded, autoHashMode, vkTokenActive) {
        if (!hashSettingsLoaded) return@LaunchedEffect
        if (autoHashMode && !vkTokenActive) {
            VkAuthWebViewManager.prewarm(context)
        } else {
            VkAuthWebViewManager.discardPrewarmed()
        }
    }

    LaunchedEffect(tunnelRunning) {
        if (wasRunning && !tunnelRunning) {
            TunnelManager.startCooldown(CsqttConstants.Timeouts.VPN_PERMISSION_COOLDOWN_MS)
        }
        wasRunning = tunnelRunning
    }

    var peerInput by rememberSaveable { mutableStateOf("") }
    var vkHash1 by rememberSaveable { mutableStateOf("") }
    var vkHash2 by rememberSaveable { mutableStateOf("") }
    var vkHash3 by rememberSaveable { mutableStateOf("") }
    var vkHash4 by rememberSaveable { mutableStateOf("") }
    var vkHash5 by rememberSaveable { mutableStateOf("") }
    var vkHash6 by rememberSaveable { mutableStateOf("") }
    var workersInput by rememberSaveable { mutableFloatStateOf(18f) }
    var showHashesDialog by rememberSaveable { mutableStateOf(false) }
    var obfsMode by rememberSaveable { mutableStateOf(CsqttConstants.Tunnel.DEFAULT_OBFS_MODE) }
    var autoCaptchaEnabled by rememberSaveable { mutableStateOf(true) }
    var useWVCaptcha by rememberSaveable { mutableStateOf(false) }
    var isManualMode by rememberSaveable { mutableStateOf(true) }
    var wbvManualMode by rememberSaveable { mutableStateOf(true) }
    var manualPortsEnabled by rememberSaveable { mutableStateOf(false) }
    var serverPeerPortInput by rememberSaveable { mutableStateOf(CsqttConstants.Network.DEFAULT_SERVER_PEER_PORT.toString()) }
    var saveJob by remember { mutableStateOf<Job?>(null) }
    var linkSaveJob by remember { mutableStateOf<Job?>(null) }
    var linkText by remember { mutableStateOf(csqttLink) }
    var loadedLinkMode by remember(activeProfile) { mutableStateOf<Boolean?>(null) }
    var initialized by rememberSaveable(activeProfile) { mutableStateOf(false) }
    val participantMode = loadedLinkMode ?: csqttLinkMode

    val allHashes = remember(vkHash1, vkHash2, vkHash3, vkHash4, vkHash5, vkHash6) {
        listOf(vkHash1, vkHash2, vkHash3, vkHash4, vkHash5, vkHash6)
    }
    val uniqueHashes = remember(vkHash1, vkHash2, vkHash3, vkHash4, vkHash5, vkHash6) {
        allHashes.filter { it.isNotBlank() && it.length >= 16 }.distinct()
    }
    val parsedCsqttLink = remember(linkText) { parseCsqttLink(linkText) }
    val linkHashes = parsedCsqttLink?.hashes.orEmpty()
    val filledHashCount = remember(vkHash1, vkHash2, vkHash3, vkHash4, vkHash5, vkHash6) { uniqueHashes.size }
    val combinedHashes = remember(vkHash1, vkHash2, vkHash3, vkHash4, vkHash5, vkHash6) { uniqueHashes.joinToString(",") }
    val savedExtraWorkers by settingsStore.extraWorkers.collectAsStateWithLifecycle(initialValue = false)
    var extraWorkersEnabled by rememberSaveable { mutableStateOf(false) }
    var showWorkersInfoDialog by rememberSaveable { mutableStateOf(false) }
    var showExtraWorkersInfoDialog by rememberSaveable { mutableStateOf(false) }

    LaunchedEffect(savedExtraWorkers) {
        extraWorkersEnabled = savedExtraWorkers
    }

    val dynamicMaxWorkers = remember(
        filledHashCount,
        hashSettingsLoaded,
        autoHashMode,
        participantMode,
        linkHashes,
        accountAutoJsMode,
        extraWorkersEnabled,
    ) {
        val sourceMaximum = if (!hashSettingsLoaded) {
            CsqttConstants.Tunnel.MAX_WORKERS.toFloat()
        } else {
            WorkerCountPolicy.maximumForSources(
                linkMode = participantMode,
                linkHashCount = linkHashes.size,
                autoHashMode = autoHashMode,
                manualHashCount = filledHashCount,
            ).toFloat()
        }
        if (!extraWorkersEnabled) {
            sourceMaximum.coerceAtMost(90f)
        } else {
            sourceMaximum
        }
    }
    var portInput by rememberSaveable { mutableStateOf(CsqttConstants.Network.DEFAULT_LOCAL_PORT.toString()) }
    var sniInput by rememberSaveable { mutableStateOf("") }

    val currentWorkers = workersInput.coerceIn(WORKERS_PER_GROUP.toFloat(), dynamicMaxWorkers)

    val hashErrors = remember(vkHash1, vkHash2, vkHash3, vkHash4, vkHash5, vkHash6) {
        buildList {
            allHashes.forEachIndexed { i, h ->
                if (h.isNotBlank() && h.length < 16) add("Хеш ${i + 1} — короткий")
            }
            val filled = allHashes.filter { it.isNotBlank() && it.length >= 16 }
            if (filled.size != filled.distinct().size) add("Есть дубликаты хешей")
        }
    }
    val hasInputHashErrors = remember(vkHash1, vkHash2, vkHash3, vkHash4, vkHash5, vkHash6) { hashErrors.isNotEmpty() }

    var showSecretsDialog by rememberSaveable { mutableStateOf(false) }

    fun parseHashes(raw: String) {
        val parts = raw.split(Regex("[,\\s\\n]+")).map { stripVkUrlStatic(it) }.filter { it.isNotEmpty() }
        vkHash1 = parts.getOrElse(0) { "" }
        vkHash2 = parts.getOrElse(1) { "" }
        vkHash3 = parts.getOrElse(2) { "" }
        vkHash4 = parts.getOrElse(3) { "" }
        vkHash5 = parts.getOrElse(4) { "" }
        vkHash6 = parts.getOrElse(5) { "" }
    }

    fun normalizeHashes(vararg hashes: String): String {
        return hashes
            .map { stripVkUrlStatic(it) }
            .filter { it.isNotBlank() && it.length >= 16 }
            .distinct()
            .joinToString(",")
    }

    LaunchedEffect(csqttLink) {
        linkText = csqttLink
    }

    LaunchedEffect(csqttLinkMode) {
        if (initialized) loadedLinkMode = csqttLinkMode
    }

    LaunchedEffect(activeProfile) {
        saveJob?.cancel()
        linkSaveJob?.cancel()
        val peer = settingsStore.peer.first()
        val hashes = settingsStore.vkHashes.first()
        val workers = settingsStore.workersPerHash.first()
        val port = settingsStore.listenPort.first()
        val manualPorts = settingsStore.manualPortsEnabled.first()
        val serverPeerPort = settingsStore.serverPeerPort.first()
        val loadedVkAuthMode = settingsStore.vkAuthMode.first()
        val captchaMode = settingsStore.captchaMode.first()
        val captchaMethod = settingsStore.captchaSolveMethod.first()
        val wbvCaptchaMethod = settingsStore.captchaWbvSolveMethod.first()
        val profileLink = settingsStore.csqttLink.first()
        val profileLinkMode = settingsStore.csqttLinkMode.first()
        
        peerInput = peer
        parseHashes(hashes)
        linkText = profileLink
        loadedLinkMode = profileLinkMode
        val loadedHashMode = settingsStore.vkHashMode.first()
        val profileLinkHashCount = parseCsqttLink(profileLink)?.hashes?.size ?: 0
        vkAuthMode = loadedVkAuthMode
        val loadMaxWorkers = WorkerCountPolicy.maximumForSources(
            linkMode = profileLinkMode,
            linkHashCount = profileLinkHashCount,
            autoHashMode = loadedVkAuthMode == CsqttConstants.VkAuth.MODE_AUTO_JS ||
                loadedHashMode != CsqttConstants.VkAutoHash.MODE_MANUAL,
            manualHashCount = listOf(vkHash1, vkHash2, vkHash3, vkHash4, vkHash5, vkHash6)
                .count { it.isNotBlank() },
        ).toFloat()
        workersInput = roundToGroup(workers.toFloat(), loadMaxWorkers)
        portInput = port.toString()
        manualPortsEnabled = manualPorts
        serverPeerPortInput = serverPeerPort.toString()
        sniInput = settingsStore.sni.first()
        obfsMode = savedObfsMode
        autoCaptchaEnabled = captchaMode == "auto"
        useWVCaptcha = captchaMode != "rjs"
        wbvManualMode = wbvCaptchaMethod != "auto"
        isManualMode = if (captchaMode == "wv") wbvManualMode else captchaMethod != "auto"
        
        initialized = true
    }

    LaunchedEffect(savedManualPortsEnabled) {
        manualPortsEnabled = savedManualPortsEnabled
    }

    LaunchedEffect(savedServerPeerPort) {
        serverPeerPortInput = savedServerPeerPort.toString()
    }

    LaunchedEffect(savedListenPort) {
        portInput = savedListenPort.toString()
    }

    val tunnelUiReady = initialized && hashSettingsLoaded && obfsModeLoaded != null && linkModeLoaded != null
    if (!tunnelUiReady) {
        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
        }
        return
    }

    DisposableEffect(Unit) {
        onDispose {
            saveJob?.cancel()
            linkSaveJob?.cancel()
        }
    }

    fun saveTunnelSettingsNow(hashes: String = combinedHashes, onSaved: (() -> Unit)? = null) {
        saveJob?.cancel()
        scope.launch {
            if (participantMode) {
                settingsStore.saveWorkersPerHash(workersInput.toInt())
            } else {
                settingsStore.save(
                    peerInput, hashes, "",
                    workersInput.toInt(), "udp", 0, sniInput, false
                )
            }
            onSaved?.invoke()
        }
    }

    fun scheduleSave() {
        saveJob?.cancel()
        saveJob = scope.launch {
            delay(300)
            if (participantMode) {
                settingsStore.saveWorkersPerHash(workersInput.toInt())
            } else {
                settingsStore.save(
                    peerInput, combinedHashes, "",
                    workersInput.toInt(), "udp", 0, sniInput, false
                )
            }
        }
    }

    LaunchedEffect(dynamicMaxWorkers) {
        if (initialized && workersInput > dynamicMaxWorkers) {
            workersInput = dynamicMaxWorkers
            scheduleSave()
        }
    }

    val scrollState = rememberScrollState()

    val isPeerValid = peerInput.isNotBlank() && !peerInput.contains(":")
    val isHashesValid = combinedHashes.isNotBlank()
    val isLinkValid = remember(parsedCsqttLink) { parsedCsqttLink != null }
    val hashesReady = hashSettingsLoaded && when {
        participantMode && linkHashes.isNotEmpty() -> true
        autoHashMode -> vkTokenActive
        else -> isHashesValid && !hasInputHashErrors
    }
    val isManualValid = isPeerValid && hashesReady && savedConnectionPassword.isNotBlank()
    val isValid = if (participantMode) isLinkValid && hashesReady else isManualValid
    val effectiveServerPeerPort = if (manualPortsEnabled) serverPeerPortInput.toIntOrNull()?.coerceIn(1, 65535) ?: 46000 else 46000
    var pendingStartAfterVpnPermission by remember { mutableStateOf(false) }

    fun startTunnelService() {
        val effectiveVkAuthMode = vkAuthMode
        val effectiveCaptchaMode = if (autoCaptchaEnabled) "auto" else if (useWVCaptcha) "wv" else "rjs"
        val effectiveCaptchaSolveMethod = if (!autoCaptchaEnabled && effectiveCaptchaMode == "wv" && isManualMode) "manual" else "auto"
        saveJob?.cancel()
        scope.launch {
            settingsStore.save(
                peerInput, combinedHashes, "",
                workersInput.toInt(), "udp", 0, sniInput, false
            )
            settingsStore.saveVkAuthMode(effectiveVkAuthMode)
            settingsStore.saveCaptchaMode(effectiveCaptchaMode)
            settingsStore.saveCaptchaSolveMethod(effectiveCaptchaSolveMethod)
        }

        var finalPeer = "$peerInput:$effectiveServerPeerPort"
        var finalHashes = combinedHashes
        var finalPassword = savedConnectionPassword

        if (participantMode) {
            parsedCsqttLink?.let { link ->
                finalPeer = link.peerAddress()
                finalPassword = link.password
                finalHashes = link.hashes.takeIf { it.isNotEmpty() }?.joinToString(",") ?: combinedHashes
            }
        }

        scope.launch {
            val nextGen = System.currentTimeMillis() / 1000L
            val salt = java.util.UUID.randomUUID().toString().replace("-", "").take(16)
            val intent = Intent(context, TunnelService::class.java).apply {
                action = "START"
                putExtra("peer", finalPeer)
                putExtra("vk_hashes", finalHashes)
                putExtra("vk_hashes_from_link", participantMode && linkHashes.isNotEmpty())
                putExtra("secondary_vk_hash", "")
                putExtra("workers_per_hash", workersInput.toInt())
                putExtra("port", 0)
                putExtra("sni", sniInput)
                putExtra("connection_password", finalPassword)
                putExtra("vk_auth_mode", effectiveVkAuthMode)
                putExtra("captcha_mode", effectiveCaptchaMode)
                putExtra("captcha_solve_method", effectiveCaptchaSolveMethod)
                putExtra("fingerprint", activeFingerprint)
                putExtra("client_ids", activeClientIds)
                putExtra("obfs_mode", obfsMode)
                putExtra("generation_id", nextGen)
                putExtra("session_salt", salt)
            }
            runCatching { context.startForegroundService(intent) }
                .onFailure { error ->
                    TunnelManager.updateLog(
                        "foreground_request_error",
                        "Android заблокировал запуск VPN: ${error.message ?: error.javaClass.simpleName}",
                        99,
                        true,
                    )
                    Toast.makeText(
                        context,
                        "Android заблокировал запуск VPN. Проверьте ограничения батареи приложения.",
                        Toast.LENGTH_LONG,
                    ).show()
                }
        }
    }

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        if (pendingStartAfterVpnPermission) {
            pendingStartAfterVpnPermission = false
            if (VpnService.prepare(context) == null) {
                startTunnelService()
            } else {
                context.showRaisedToast("VPN-разрешение не выдано", Toast.LENGTH_SHORT)
            }
        }
    }

    fun requestVpnAndStart() {
        val vpnIntent = VpnService.prepare(context)
        if (vpnIntent != null) {
            pendingStartAfterVpnPermission = true
            vpnPermissionLauncher.launch(vpnIntent)
        } else {
            startTunnelService()
        }
    }

    if (showSecretsDialog) {
        SecretsDialog(
            settingsStore = settingsStore,
            initialPassword = savedConnectionPassword,
            onSaved = { },
            onDismiss = { showSecretsDialog = false }
        )
    }

    if (showHashesDialog) {
        HashesDialog(
            hash1 = vkHash1,
            hash2 = vkHash2,
            hash3 = vkHash3,
            hash4 = vkHash4,
            hash5 = vkHash5,
            hash6 = vkHash6,
            validationResults = vkHashCheckResults,
            onValidationResultsChange = { results ->
                scope.launch {
                    settingsStore.saveVkHashCheckResults(VkHashValidationCodec.encode(results))
                }
            },
            onCheck = { hashes ->
                VkHashValidator.check(context, hashes, activeFingerprint, activeClientIds)
            },
            onSave = { h1, h2, h3, h4, h5, h6 ->
                val cleaned1 = stripVkUrlStatic(h1)
                val cleaned2 = stripVkUrlStatic(h2)
                val cleaned3 = stripVkUrlStatic(h3)
                val cleaned4 = stripVkUrlStatic(h4)
                val cleaned5 = stripVkUrlStatic(h5)
                val cleaned6 = stripVkUrlStatic(h6)
                vkHash1 = cleaned1
                vkHash2 = cleaned2
                vkHash3 = cleaned3
                vkHash4 = cleaned4
                vkHash5 = cleaned5
                vkHash6 = cleaned6
                saveTunnelSettingsNow(normalizeHashes(cleaned1, cleaned2, cleaned3, cleaned4, cleaned5, cleaned6)) {
                    showHashesDialog = false
                }
            },
            onDismiss = { showHashesDialog = false }
        )
    }

    if (showVkAuthDialog) {
        VkAuthDialog(
            onToken = { payload ->
                showVkAuthDialog = false
                scope.launch {
                    settingsStore.saveVkAccessToken(payload.token, payload.userId)
                    context.showRaisedToast("Вечный VK access token сохранен", Toast.LENGTH_SHORT)
                }
            },
            onDismiss = { showVkAuthDialog = false },
        )
    }

    if (showVkRevokeDialog) {
        VkTokenRevokeDialog(
            onCancel = { showVkRevokeDialog = false },
            onRevokeToken = {
                showVkRevokeDialog = false
                scope.launch { settingsStore.clearVkAccessToken() }
            }
        )
    }

    val tunnelSecretsMissing = savedConnectionPassword.isBlank()
    val btnEnabled = (isValid && !cooldownActive) || tunnelRunning

    CsqttScreen {
        Box(modifier = Modifier.fillMaxSize()) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(scrollState)
                    .padding(bottom = 110.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
            if (participantMode) {
                AppSectionCard(
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(0.dp)
                ) {
                    OutlinedTextField(
                        value = linkText,
                        onValueChange = { value ->
                            linkText = value.filterNot(Char::isWhitespace)
                            linkSaveJob?.cancel()
                            linkSaveJob = scope.launch {
                                delay(350)
                                settingsStore.saveCsqttLink(linkText)
                            }
                        },
                        label = { Text("Ссылка csqtt://", maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis) },
                        placeholder = { Text("csqtt://connect?v=2&host=ip&peer=порт&password=пароль", maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis) },
                        singleLine = true,
                        isError = linkText.isNotBlank() && parsedCsqttLink == null,
                        modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                        shape = RoundedCornerShape(20.dp),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = MaterialTheme.colorScheme.primary,
                            unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f),
                        )
                    )

                    if (linkText.isNotBlank() && parsedCsqttLink == null) {
                        Text(
                            text = "Неверная ссылка CSQTT v2",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.padding(bottom = 12.dp),
                        )
                    }

                    if (linkHashes.isNotEmpty()) {
                        Text(
                            text = "VK хеши из ссылки: ${linkHashes.size}",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.primary,
                            fontWeight = FontWeight.SemiBold,
                        )
                    } else {
                        VkHashModeControls(
                            hashSettingsLoaded = hashSettingsLoaded,
                            autoHashMode = autoHashMode,
                            savedHashMode = savedHashMode,
                            hashModeLocked = accountAutoJsMode,
                            vkTokenActive = vkTokenActive,
                            tunnelRunning = tunnelRunning,
                            filledHashCount = filledHashCount,
                            hasInputHashErrors = hasInputHashErrors,
                            hashErrorTexts = hashErrors.filter { !it.contains("короткий") },
                            onOpenHashes = { showHashesDialog = true },
                            onTitleInfo = { showHashModeGeneralDialog = true },
                            onInfo = { mode -> showHashModeDetailDialog = mode },
                            onSelected = { mode -> scope.launch { settingsStore.saveVkHashMode(mode) } },
                            onLogin = { showVkAuthDialog = true },
                            onRevokeToken = { showVkRevokeDialog = true },
                        )
                    }
                }
            } else {
                AppSectionCard(
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(0.dp)
                ) {
                    Text(
                        "Сервер и Хеши",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        softWrap = false,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.padding(bottom = 12.dp),
                    )
                    OutlinedTextField(
                        value = peerInput,
                        onValueChange = {
                            peerInput = it.filter { c -> !c.isWhitespace() }
                            scheduleSave()
                        },
                        label = {
                            Text(
                                if (manualPortsEnabled) "IP сервера или домен" else "IP сервера или домен (без порта)",
                                maxLines = 1,
                                softWrap = false,
                                overflow = TextOverflow.Ellipsis,
                            )
                        },
                        placeholder = {
                            Text(
                                if (manualPortsEnabled) "1.2.3.4" else "1.2.3.4 (или test.com)",
                                maxLines = 1,
                                softWrap = false,
                                overflow = TextOverflow.Ellipsis,
                            )
                        },
                        singleLine = true,
                        
                        isError = !isPeerValid && peerInput.isNotEmpty(),
                        modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                        shape = RoundedCornerShape(20.dp),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = MaterialTheme.colorScheme.primary,
                            unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f),
                        )
                    )

                    if (manualPortsEnabled) {
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            OutlinedTextField(
                                value = serverPeerPortInput,
                                onValueChange = { 
                                    serverPeerPortInput = it.filter(Char::isDigit).take(5)
                                    val peerPortValue = serverPeerPortInput.toIntOrNull()?.coerceIn(1, 65535) ?: 46000
                                    scope.launch { settingsStore.savePorts(peerPortValue, settingsStore.serverWebPort.first(), settingsStore.deploySshPort.first()) }
                                },
                                label = { Text("PEER Порт", maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis) },
                                placeholder = { Text("46000", maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis) },
                                singleLine = true,
                                modifier = Modifier.weight(1f),
                                shape = RoundedCornerShape(20.dp)
                            )
                        }
                    }

                    VkHashModeControls(
                        hashSettingsLoaded = hashSettingsLoaded,
                        autoHashMode = autoHashMode,
                        savedHashMode = savedHashMode,
                        hashModeLocked = accountAutoJsMode,
                        vkTokenActive = vkTokenActive,
                        tunnelRunning = tunnelRunning,
                        filledHashCount = filledHashCount,
                        hasInputHashErrors = hasInputHashErrors,
                        hashErrorTexts = hashErrors.filter { !it.contains("короткий") },
                        onOpenHashes = { showHashesDialog = true },
                        onTitleInfo = { showHashModeGeneralDialog = true },
                        onInfo = { mode -> showHashModeDetailDialog = mode },
                        onSelected = { mode -> scope.launch { settingsStore.saveVkHashMode(mode) } },
                        onLogin = { showVkAuthDialog = true },
                        onRevokeToken = { showVkRevokeDialog = true },
                    )
                }
            }

            AppSectionCard(
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(0.dp)
            ) {
                CompactDropdownSetting(
                    title = "Режим работы",
                    selectedKey = vkAuthMode,
                    options = listOf(
                        CsqttConstants.VkAuth.MODE_CAPTCHA to "Капча",
                        CsqttConstants.VkAuth.MODE_CALLS to "Авто",
                        CsqttConstants.VkAuth.MODE_AUTO_JS to "Авто ВК",
                    ),
                    enabled = true,
                    indicatorProvider = { mode ->
                        when (mode) {
                            CsqttConstants.VkAuth.MODE_CAPTCHA -> ModeIndicator(progress = 0.20f, color = Color(0xFFE53935))
                            CsqttConstants.VkAuth.MODE_CALLS -> ModeIndicator(progress = 0.65f, color = Color(0xFFFFB300))
                            CsqttConstants.VkAuth.MODE_AUTO_JS -> ModeIndicator(progress = 1.0f, color = Color(0xFF43A047))
                            else -> null
                        }
                    },
                    onTitleInfo = { showWorkModeGeneralDialog = true },
                    onInfo = { mode -> showWorkModeDetailDialog = mode },
                    onSelected = { mode ->
                        vkAuthMode = mode
                        scope.launch {
                            settingsStore.saveVkAuthMode(mode)
                            if (mode == CsqttConstants.VkAuth.MODE_AUTO_JS) {
                                TunnelManager.updateLog(
                                    "vk_js_mode_selected",
                                    "[VK JS] Выбран один звонок · хеши Авто ВК · максимум 162 потока",
                                    40,
                                    false,
                                )
                            }
                        }
                    },
                )

                CompactDropdownSetting(
                    title = "Маскировка",
                    selectedKey = obfsMode,
                    options = listOf(
                        "audio" to "Простая",
                        "video" to "Средняя",
                    ),
                    enabled = true,
                    indicatorProvider = { mode ->
                        when (mode) {
                            "audio" -> ModeIndicator(progress = 0.40f, color = Color(0xFFFFB300))
                            "video" -> ModeIndicator(progress = 0.75f, color = Color(0xFF43A047))
                            else -> null
                        }
                    },
                    onTitleInfo = { showObfsGeneralDialog = true },
                    onInfo = { mode -> showObfsDetailDialog = mode },
                    onSelected = { mode ->
                        obfsMode = mode
                        scope.launch { settingsStore.saveObfsMode(mode) }
                    },
                )

                Row(
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp, bottom = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(
                            "Потоки",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                            maxLines = 1,
                            softWrap = false,
                            overflow = TextOverflow.Ellipsis,
                        )
                        IconButton(
                            onClick = { showWorkersInfoDialog = true },
                            modifier = Modifier.size(24.dp)
                        ) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Filled.HelpOutline,
                                contentDescription = "Информация о потоках",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(16.dp),
                            )
                        }
                    }
                    Text(
                        text = "${currentWorkers.toInt()}",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }

                val maxWorkers = dynamicMaxWorkers
                val minWorkers = WORKERS_PER_GROUP.toFloat()
                val currentWorkersVal = roundToGroup(currentWorkers.coerceIn(minWorkers, maxWorkers), maxWorkers)

                CompactSteppedSlider(
                    value = currentWorkersVal,
                    onValueChange = { raw ->
                        workersInput = roundToGroup(raw, maxWorkers)
                        scheduleSave()
                    },
                    valueRange = minWorkers..maxWorkers,
                    stepSize = WORKERS_PER_GROUP.toFloat(),
                    enabled = true,
                    modifier = Modifier.fillMaxWidth()
                )

                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(
                            "Экстра потоки",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                            maxLines = 1,
                            softWrap = false,
                            overflow = TextOverflow.Ellipsis,
                        )
                        IconButton(
                            onClick = { showExtraWorkersInfoDialog = true },
                            modifier = Modifier.size(24.dp)
                        ) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Filled.HelpOutline,
                                contentDescription = "Информация об экстра потоках",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(16.dp),
                            )
                        }
                    }
                    Switch(
                        checked = extraWorkersEnabled,
                        enabled = !tunnelRunning,
                        onCheckedChange = { enabled ->
                            extraWorkersEnabled = enabled
                            scope.launch {
                                settingsStore.saveExtraWorkers(enabled)
                            }
                        }
                    )
                }

                AnimatedVisibility(
                    visible = vkAuthMode == CsqttConstants.VkAuth.MODE_CAPTCHA,
                    enter = fadeIn() + expandVertically(),
                    exit = fadeOut() + shrinkVertically()
                ) {
                    Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
                        HorizontalDivider(
                            modifier = Modifier.padding(vertical = 4.dp),
                            color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                        )

                        Row(
                            modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(
                                if (autoCaptchaEnabled) "Авто капча" else "Ручная капча",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Medium,
                                modifier = Modifier.weight(1f)
                            )
                            Switch(
                                checked = autoCaptchaEnabled,
                                enabled = !tunnelRunning,
                                onCheckedChange = { enabled ->
                                    autoCaptchaEnabled = enabled
                                    scope.launch {
                                        if (enabled) {
                                            settingsStore.saveCaptchaMode("auto")
                                            settingsStore.saveCaptchaSolveMethod("auto")
                                        } else {
                                            val mode = if (useWVCaptcha) "wv" else "rjs"
                                            settingsStore.saveCaptchaMode(mode)
                                            settingsStore.saveCaptchaSolveMethod(if (mode == "wv" && isManualMode) "manual" else "auto")
                                        }
                                    }
                                }
                            )
                        }

                        AnimatedVisibility(
                            visible = !autoCaptchaEnabled,
                            enter = fadeIn() + expandVertically(),
                            exit = fadeOut() + shrinkVertically()
                        ) {
                            Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
                                HorizontalDivider(
                                    modifier = Modifier.padding(vertical = 4.dp),
                                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                                )

                                Row(
                                    modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text(
                                        "Метод обхода капчи",
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = FontWeight.Medium,
                                        modifier = Modifier.weight(1f)
                                    )
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        ProtocolChip("WBV", useWVCaptcha, enabled = !tunnelRunning) {
                                            useWVCaptcha = true
                                            isManualMode = wbvManualMode
                                            scope.launch {
                                                settingsStore.saveCaptchaMode("wv")
                                                settingsStore.saveCaptchaSolveMethod(if (wbvManualMode) "manual" else "auto")
                                            }
                                        }
                                        ProtocolChip("RJS", !useWVCaptcha, enabled = !tunnelRunning, isError = false) {
                                            useWVCaptcha = false
                                            isManualMode = false
                                            scope.launch {
                                                settingsStore.saveCaptchaMode("rjs")
                                                settingsStore.saveCaptchaSolveMethod("auto")
                                            }
                                        }
                                    }
                                }

                                HorizontalDivider(
                                    modifier = Modifier.padding(vertical = 4.dp),
                                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                                )

                                Row(
                                    modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text(
                                        "Режим обхода",
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = FontWeight.Medium,
                                        modifier = Modifier.weight(1f)
                                    )
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        if (useWVCaptcha) {
                                            ProtocolChip(
                                                "РУЧ",
                                                isManualMode,
                                                enabled = !tunnelRunning,
                                                isError = false
                                            ) {
                                                isManualMode = true
                                                wbvManualMode = true
                                                scope.launch { settingsStore.saveWbvCaptchaSolveMethod("manual") }
                                            }
                                            ProtocolChip(
                                                "АВТ",
                                                !isManualMode,
                                                enabled = !tunnelRunning,
                                                isError = false
                                            ) {
                                                isManualMode = false
                                                wbvManualMode = false
                                                scope.launch { settingsStore.saveWbvCaptchaSolveMethod("auto") }
                                            }
                                        } else {
                                            ProtocolChip(
                                                "АВТ",
                                                selected = true,
                                                enabled = false,
                                                isError = false
                                            ) {}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

            }

            TunnelActionBar(
                linkMode = participantMode,
                secretsMissing = tunnelSecretsMissing,
                tunnelRunning = tunnelRunning,
                tunnelStarting = tunnelStarting,
                cooldownActive = cooldownActive,
                connectEnabled = btnEnabled,
                uptimeSeconds = uptimeSeconds,
                onAuthorization = { showSecretsDialog = true },
                onToggleTunnel = {
                    if (tunnelRunning) {
                        context.startService(Intent(context, TunnelService::class.java).apply { action = "STOP" })
                    } else {
                        requestVpnAndStart()
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            )

            if (showWorkersInfoDialog) {
                com.csqtt.client.ui.tunnel.WorkersInfoDialog(onDismiss = { showWorkersInfoDialog = false })
            }

            if (showExtraWorkersInfoDialog) {
                com.csqtt.client.ui.tunnel.ExtraWorkersInfoDialog(onDismiss = { showExtraWorkersInfoDialog = false })
            }

            if (showObfsGeneralDialog) {
                ObfsInfoDialog(mode = null, onDismiss = { showObfsGeneralDialog = false })
            }
            showObfsDetailDialog?.let { mode ->
                ObfsInfoDialog(mode = mode, onDismiss = { showObfsDetailDialog = null })
            }

            if (showHashModeGeneralDialog) {
                HashModeInfoDialog(mode = null, onDismiss = { showHashModeGeneralDialog = false })
            }
            showHashModeDetailDialog?.let { mode ->
                HashModeInfoDialog(mode = mode, onDismiss = { showHashModeDetailDialog = null })
            }

            if (showWorkModeGeneralDialog) {
                WorkModeInfoDialog(mode = null, onDismiss = { showWorkModeGeneralDialog = false })
            }
            showWorkModeDetailDialog?.let { mode ->
                WorkModeInfoDialog(mode = mode, onDismiss = { showWorkModeDetailDialog = null })
            }
        }
    }
}
}

@Composable
private fun VkHashAuthControls(
    tunnelRunning: Boolean,
    tokenActive: Boolean,
    onLogin: () -> Unit,
    onRevokeToken: () -> Unit,
) {
    if (tokenActive) {
        OutlinedButton(
            onClick = onRevokeToken,
            enabled = !tunnelRunning,
            modifier = Modifier.height(44.dp),
            shape = RoundedCornerShape(14.dp),
            colors = ButtonDefaults.outlinedButtonColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.35f),
                contentColor = MaterialTheme.colorScheme.primary,
                disabledContainerColor = Color.Transparent,
                disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f),
            ),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.5f)),
            contentPadding = PaddingValues(horizontal = 10.dp),
        ) {
            Text("Активно", fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.labelMedium, maxLines = 1)
        }
    } else {
        Button(
            onClick = onLogin,
            enabled = true,
            modifier = Modifier.height(44.dp),
            shape = RoundedCornerShape(14.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = MaterialTheme.colorScheme.onPrimary,
            ),
            contentPadding = PaddingValues(horizontal = 14.dp),
            elevation = ButtonDefaults.buttonElevation(defaultElevation = 0.dp, pressedElevation = 0.dp),
        ) {
            Text("Вход", fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelMedium, maxLines = 1)
        }
    }
}

@Composable
private fun VkHashModeControls(
    hashSettingsLoaded: Boolean,
    autoHashMode: Boolean,
    savedHashMode: String?,
    hashModeLocked: Boolean,
    vkTokenActive: Boolean,
    tunnelRunning: Boolean,
    filledHashCount: Int,
    hasInputHashErrors: Boolean,
    hashErrorTexts: List<String>,
    onOpenHashes: () -> Unit,
    onTitleInfo: () -> Unit,
    onInfo: (String) -> Unit,
    onSelected: (String) -> Unit,
    onLogin: () -> Unit,
    onRevokeToken: () -> Unit,
) {
    if (!hashSettingsLoaded) return

    AnimatedVisibility(
        visible = !autoHashMode,
        enter = fadeIn() + expandVertically(expandFrom = Alignment.Top),
        exit = fadeOut() + shrinkVertically(shrinkTowards = Alignment.Top)
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedButton(
                onClick = onOpenHashes,
                modifier = Modifier.fillMaxWidth().height(52.dp),
                shape = RoundedCornerShape(20.dp),
                colors = ButtonDefaults.outlinedButtonColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                    contentColor = MaterialTheme.colorScheme.onSurface
                ),
                border = BorderStroke(
                    1.dp,
                    if (hasInputHashErrors) MaterialTheme.colorScheme.error
                    else MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)
                )
            ) {
                Icon(Icons.Default.Tag, null, Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(
                    "VK Хеши $filledHashCount/${CsqttConstants.Tunnel.MAX_VK_HASHES}",
                    fontWeight = FontWeight.SemiBold,
                )
            }

            if (hashErrorTexts.isNotEmpty()) {
                Text(
                    text = hashErrorTexts.joinToString(", "),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }
        }
    }

    CompactDropdownSetting(
        title = if (autoHashMode && vkTokenActive) "Хеши" else "Режим хешей",
        selectedKey = savedHashMode ?: CsqttConstants.VkAutoHash.MODE_MANUAL,
        options = listOf(
            CsqttConstants.VkAutoHash.MODE_MANUAL to "Ручной",
            CsqttConstants.VkAutoHash.MODE_AUTO_API to "Авто API",
            CsqttConstants.VkAutoHash.MODE_AUTO_JS to "Авто ВК",
        ),
        enabled = !hashModeLocked,
        indicatorProvider = { mode ->
            when (mode) {
                CsqttConstants.VkAutoHash.MODE_MANUAL -> ModeIndicator(progress = 0.50f, color = Color(0xFFFFB300))
                CsqttConstants.VkAutoHash.MODE_AUTO_API -> ModeIndicator(progress = 0.85f, color = Color(0xFF43A047))
                CsqttConstants.VkAutoHash.MODE_AUTO_JS -> ModeIndicator(progress = 1.0f, color = Color(0xFF43A047))
                else -> null
            }
        },
        onTitleInfo = onTitleInfo,
        onInfo = onInfo,
        onSelected = onSelected,
        leadingContent = if (autoHashMode && hashSettingsLoaded) {
            {
                VkHashAuthControls(
                    tunnelRunning = tunnelRunning,
                    tokenActive = vkTokenActive,
                    onLogin = onLogin,
                    onRevokeToken = onRevokeToken,
                )
            }
        } else {
            null
        },
    )
}


