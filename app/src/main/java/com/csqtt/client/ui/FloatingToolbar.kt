// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import kotlinx.coroutines.launch
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.csqtt.client.SettingsStore
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.csqtt.client.R
import android.os.Build
import androidx.compose.ui.graphics.Color
import kotlin.math.roundToInt

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Check
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.foundation.verticalScroll
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import com.csqtt.client.ui.components.CsqttSegmentedControl
import com.csqtt.client.ui.design.CsqttShapes
import com.csqtt.client.ui.design.CsqttSizes

private enum class UsageRole { Owner, Participant }

@Composable
fun FloatingToolbar(
    settingsStore: SettingsStore,
    activeProfile: Int,
    onActiveProfileChange: (Int) -> Unit,
    currentTheme: String,
    onThemeChange: (String) -> Unit,
    isDynamicColor: Boolean,
    onDynamicColorChange: (Boolean) -> Unit,
    currentPalette: String,
    onPaletteChange: (String) -> Unit,
    activeFingerprint: String,
    onFingerprintChange: (String) -> Unit,
    activeClientIds: String,
    onClientIdsChange: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val locale = LocalConfiguration.current.locales[0]
    val density = LocalDensity.current
    val scope = rememberCoroutineScope()
    val csqttLinkMode by settingsStore.csqttLinkMode.collectAsStateWithLifecycle(initialValue = false)
    val savedOffsetFraction by settingsStore.floatingToolbarYFraction.collectAsStateWithLifecycle(initialValue = Float.NaN)
    val selectedRole = if (csqttLinkMode) UsageRole.Participant else UsageRole.Owner
    val windowSize = LocalWindowInfo.current.containerSize
    val screenHeightPx = windowSize.height.toFloat()
    val screenWidthPx = windowSize.width.toFloat()

    var parentWidthPx by remember { mutableFloatStateOf(0f) }
    var parentHeightPx by remember { mutableFloatStateOf(0f) }

    var offsetY by rememberSaveable { mutableFloatStateOf(-1f) }
    var isRightSide by rememberSaveable { mutableStateOf(true) }
    var isExpanded by rememberSaveable { mutableStateOf(false) }
    var tabHeightPx by remember { mutableFloatStateOf(0f) }

    val tabWidthDp = 42.dp
    val tabHeightDp = 52.dp
    val tabWidthPx = remember(density) { with(density) { tabWidthDp.toPx() } }
    val fallbackTabHeightPx = remember(density) { with(density) { tabHeightDp.toPx() } }
    val edgePaddingPx = remember(density) { with(density) { 8.dp.toPx() } }
    val safeTopPx = WindowInsets.safeDrawing.getTop(density).toFloat()
    val safeBottomPx = WindowInsets.safeDrawing.getBottom(density).toFloat()
    val effectiveTabHeightPx = maxOf(tabHeightPx, fallbackTabHeightPx)
    val floatingHeightPx = effectiveTabHeightPx
    
    val currentParentHeight = if (parentHeightPx > 0f) parentHeightPx else screenHeightPx
    val currentParentWidth = if (parentWidthPx > 0f) parentWidthPx else screenWidthPx

    val minOffsetY = safeTopPx + edgePaddingPx
    val maxOffsetY = (currentParentHeight - safeBottomPx - floatingHeightPx - edgePaddingPx)
        .coerceAtLeast(minOffsetY)
    val defaultOffsetY = (currentParentHeight * 0.24f).coerceIn(minOffsetY, maxOffsetY)

    val targetXPx = if (isRightSide) currentParentWidth - tabWidthPx else 0f

    val animatedTabXPx by animateFloatAsState(
        targetValue = targetXPx,
        animationSpec = spring(stiffness = Spring.StiffnessLow),
        label = "tab_shift"
    )

    fun persistOffset() {
        val available = maxOffsetY - minOffsetY
        val fraction = if (available > 0f) {
            ((offsetY - minOffsetY) / available).coerceIn(0f, 1f)
        } else {
            0.24f
        }
        scope.launch { settingsStore.saveFloatingToolbarYFraction(fraction) }
    }

    LaunchedEffect(savedOffsetFraction, minOffsetY, maxOffsetY) {
        if (savedOffsetFraction.isFinite()) {
            offsetY = minOffsetY + (maxOffsetY - minOffsetY) * savedOffsetFraction
        } else if (offsetY < 0f) {
            offsetY = defaultOffsetY
        }
    }

    Box(
        modifier = modifier
            .fillMaxSize()
            .onGloballyPositioned { coordinates ->
                parentWidthPx = coordinates.size.width.toFloat()
                parentHeightPx = coordinates.size.height.toFloat()
            }
    ) {
        Surface(
            onClick = { isExpanded = !isExpanded },
            modifier = Modifier
                .offset { IntOffset(animatedTabXPx.roundToInt(), offsetY.roundToInt()) }
                .onGloballyPositioned { coordinates ->
                    tabHeightPx = coordinates.size.height.toFloat()
                }
                .pointerInput(minOffsetY, maxOffsetY) {
                    detectDragGestures(
                        onDragEnd = { persistOffset() },
                        onDragCancel = { persistOffset() },
                        onDrag = { change, dragAmount ->
                            change.consume()
                            offsetY = (offsetY + dragAmount.y).coerceIn(minOffsetY, maxOffsetY)
                        }
                    )
                },
            shape = if (isRightSide)
                RoundedCornerShape(topStart = 14.dp, bottomStart = 14.dp)
            else
                RoundedCornerShape(topEnd = 14.dp, bottomEnd = 14.dp),
            color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.9f),
            shadowElevation = 0.dp,
            tonalElevation = 0.dp,
        ) {
            Box(
                modifier = Modifier.size(tabWidthDp, tabHeightDp),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Filled.Settings,
                    contentDescription = stringResource(R.string.quick_settings),
                    modifier = Modifier.size(22.dp),
                    tint = MaterialTheme.colorScheme.onPrimaryContainer
                )
            }
        }

        if (isExpanded) {
            Dialog(
                onDismissRequest = { isExpanded = false },
                properties = DialogProperties(usePlatformDefaultWidth = false)
            ) {
                Surface(
                    shape = RoundedCornerShape(32.dp),
                    color = MaterialTheme.colorScheme.surface,
                    shadowElevation = 0.dp,
                    tonalElevation = 0.dp,
                    modifier = Modifier.fillMaxWidth(0.9f)
                ) {
                    Column(
                        modifier = Modifier
                            .padding(16.dp)
                            .verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            "Настройки",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        IconButton(
                            onClick = { isExpanded = false },
                            modifier = Modifier.size(48.dp)
                        ) {
                            Icon(
                                Icons.Filled.Close,
                                contentDescription = stringResource(R.string.action_close),
                                tint = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }

                    Text(
                        "Ваша роль использования",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.padding(start = 4.dp, bottom = 4.dp)
                    )

                    CsqttSegmentedControl(
                        options = listOf(
                            UsageRole.Owner to "Владелец",
                            UsageRole.Participant to "Участник",
                        ),
                        selected = selectedRole,
                        onSelected = { role ->
                            val participant = role == UsageRole.Participant
                            if (participant != csqttLinkMode) {
                                scope.launch { settingsStore.saveCsqttLinkMode(participant) }
                            }
                        },
                        modifier = Modifier
                            .padding(horizontal = 4.dp)
                            .height(CsqttSizes.CompactControlHeight),
                    )

                    HorizontalDivider(
                        modifier = Modifier.padding(vertical = 4.dp),
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                    )

                    Text(
                        "Профили конфигураций",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.padding(start = 4.dp, bottom = 4.dp)
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        listOf(0, 1, 2).forEach { profile ->
                            val selected = profile == activeProfile
                            Surface(
                                onClick = {
                                    onActiveProfileChange(profile)
                                    isExpanded = false
                                },
                                shape = CsqttShapes.Control,
                                color = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                                modifier = Modifier
                                    .weight(1f)
                                    .height(CsqttSizes.CompactControlHeight)
                            ) {
                                Box(
                                    modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text(
                                        text = "Пр. $profile",
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
                                        color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                                        fontSize = 12.sp
                                    )
                                }
                            }
                        }
                    }



                    HorizontalDivider(
                        modifier = Modifier.padding(vertical = 4.dp),
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                    )

                    Text(
                        "Отпечаток",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.padding(start = 4.dp, bottom = 4.dp)
                    )

                    val fingerprints = listOf("chrome", "safari", "firefox")
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        fingerprints.forEach { fp ->
                            val selected = fp == activeFingerprint
                            Surface(
                                onClick = { onFingerprintChange(fp) },
                                shape = CsqttShapes.Control,
                                color = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                                modifier = Modifier
                                    .weight(1f)
                                    .height(CsqttSizes.CompactControlHeight)
                            ) {
                                Box(
                                    modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                                    contentAlignment = Alignment.Center
                                ) {
                                    val fpName = when(fp) {
                                        "chrome" -> "Chrome"
                                        "safari" -> "Safari"
                                        "firefox" -> "Firefox"
                                        else -> fp.replaceFirstChar { if (it.isLowerCase()) it.titlecase(locale) else it.toString() }
                                    }
                                    Text(
                                        text = fpName,
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
                                        color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                                        fontSize = 12.sp
                                    )
                                }
                            }
                        }
                    }

                    HorizontalDivider(
                        modifier = Modifier.padding(vertical = 4.dp),
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                    )

                    Text(
                        "Client IDs",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.padding(start = 4.dp, bottom = 4.dp)
                    )

                    val clientIdsList = activeClientIds.split(",").map { it.trim() }.filter { it.isNotEmpty() }
                    
                    val checkResultsJson by settingsStore.clientIdCheckResults.collectAsStateWithLifecycle(initialValue = "{}")
                    
                    var checkResults by remember(checkResultsJson) { 
                        mutableStateOf(try {
                            val json = org.json.JSONObject(checkResultsJson)
                            val map = mutableMapOf<String, Boolean>()
                            val keys = json.keys()
                            while (keys.hasNext()) {
                                val key = keys.next() as String
                                map[key] = json.getBoolean(key)
                            }
                            map
                        } catch (e: Exception) { emptyMap() })
                    }

                    var isChecking by remember { mutableStateOf(false) }

                    val knownIds = listOf("8202606", "6287487")
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        knownIds.forEach { id ->
                            Row(
                                modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Checkbox(
                                        checked = clientIdsList.contains(id),
                                        onCheckedChange = { checked ->
                                            val newList = if (checked) {
                                                if (!clientIdsList.contains(id)) clientIdsList + id else clientIdsList
                                            } else {
                                                clientIdsList - id
                                            }
                                            if (newList.isNotEmpty()) {
                                                onClientIdsChange(newList.joinToString(","))
                                            }
                                        },
                                        modifier = Modifier.scale(0.8f)
                                    )
                                    Text(
                                        text = id,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurface
                                    )
                                }
                                if (checkResults.containsKey(id)) {
                                     val isValid = checkResults[id] == true
                                     Icon(
                                         imageVector = if (isValid) Icons.Default.Check else Icons.Default.Close,
                                         contentDescription = null,
                                         tint = MaterialTheme.colorScheme.primary,
                                         modifier = Modifier.size(16.dp)
                                     )
                                }
                            }
                        }
                        
                        Button(
                            onClick = {
                                isChecking = true
                                scope.launch {
                                    val results = withContext(Dispatchers.IO) {
                                        checkResults.toMutableMap().also { updated ->
                                            knownIds.forEach { id -> updated[id] = checkVkClientId(id) }
                                        }
                                    }
                                    val newJson = org.json.JSONObject()
                                    results.forEach { (k, v) -> newJson.put(k, v) }
                                    settingsStore.saveClientIdCheckResults(newJson.toString())
                                    isChecking = false
                                }
                            },
                            modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 4.dp),
                            enabled = !isChecking,
                            contentPadding = PaddingValues(0.dp)
                        ) {
                            Text(if (isChecking) "Checking..." else "Проверить", fontSize = 12.sp)
                        }
                    }
                }
            }
        }
    }
}
}

private fun checkVkClientId(appId: String): Boolean {
    for (i in 0..1) {
        try {
            val url = java.net.URL("https://oauth.vk.ru/authorize?client_id=$appId&display=mobile&response_type=token")
            val conn = url.openConnection() as java.net.HttpURLConnection
            conn.requestMethod = "GET"
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            
            val code = conn.responseCode
            val stream = if (code >= 400) conn.errorStream else conn.inputStream
            val response = stream?.bufferedReader()?.readText() ?: ""
            
            if (response.contains("\"error\"") && (response.contains("invalid_client") || response.contains("invalid_request"))) {
                return false
            }
            
            return true
        } catch (e: Exception) {
        }
    }
    return false
}

@Composable
private fun ThemeOption(
    icon: Int,
    label: String,
    selected: Boolean,
    onClick: () -> Unit
) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(24.dp),
        color = if (selected) MaterialTheme.colorScheme.primaryContainer
        else MaterialTheme.colorScheme.surface,
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Icon(
                painter = painterResource(id = icon),
                contentDescription = null,
                modifier = Modifier.size(18.dp),
                tint = if (selected) MaterialTheme.colorScheme.primary
                else MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = label,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
                color = if (selected) MaterialTheme.colorScheme.primary
                else MaterialTheme.colorScheme.onSurface,
                fontSize = 13.sp
            )
        }
    }
}

@Composable
fun PaletteCircle(
    paletteId: String,
    colorHex: Long,
    selectedId: String,
    onClick: (String) -> Unit
) {
    val isSelected = paletteId == selectedId
    val accent = Color(colorHex)
    Box(
        modifier = Modifier
            .size(30.dp)
            .clip(CircleShape)
            .background(accent)
            .clickable { onClick(paletteId) }
            .then(
                if (isSelected) Modifier.border(3.dp, MaterialTheme.colorScheme.primary, CircleShape)
                else Modifier
            )
    )
}
