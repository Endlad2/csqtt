// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.BoxWithConstraintsScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.GenericShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.csqtt.client.ui.design.CsqttMotion
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin

private fun android16OrbShape(points: Int, innerRatio: Float): Shape = GenericShape { size, _ ->
    val centerX = size.width / 2f
    val centerY = size.height / 2f
    val outerRadius = min(size.width, size.height) / 2f
    val innerRadius = outerRadius * innerRatio

    for (i in 0 until points * 2) {
        val angle = (-PI / 2.0) + (i * PI / points)
        val radius = if (i % 2 == 0) outerRadius else innerRadius
        val x = centerX + (radius * cos(angle)).toFloat()
        val y = centerY + (radius * sin(angle)).toFloat()
        if (i == 0) moveTo(x, y) else lineTo(x, y)
    }
    close()
}

private val Android16OrbLarge: Shape = android16OrbShape(points = 18, innerRatio = 0.90f)
private val Android16OrbMedium: Shape = android16OrbShape(points = 20, innerRatio = 0.92f)
private val Android16OrbSmall: Shape = android16OrbShape(points = 16, innerRatio = 0.88f)

@Immutable
private data class OrbPlacement(val xFraction: Float, val yFraction: Float)

@Immutable
private data class OrbScene(
    val large: OrbPlacement,
    val medium: OrbPlacement,
    val small: OrbPlacement,
)

private fun orbSceneForTab(tab: Int): OrbScene = when (tab) {
    1 -> OrbScene(
        large = OrbPlacement(0.78f, 0.12f),
        medium = OrbPlacement(0.14f, 0.42f),
        small = OrbPlacement(0.80f, 0.68f),
    )
    2 -> OrbScene(
        large = OrbPlacement(0.14f, 0.78f),
        medium = OrbPlacement(0.80f, 0.30f),
        small = OrbPlacement(0.54f, 0.66f),
    )
    3 -> OrbScene(
        large = OrbPlacement(0.82f, 0.78f),
        medium = OrbPlacement(0.72f, 0.20f),
        small = OrbPlacement(0.12f, 0.46f),
    )
    4 -> OrbScene(
        large = OrbPlacement(0.14f, 0.16f),
        medium = OrbPlacement(0.20f, 0.76f),
        small = OrbPlacement(0.86f, 0.52f),
    )
    else -> OrbScene(
        large = OrbPlacement(0.05f, 0.04f),
        medium = OrbPlacement(0.92f, 0.70f),
        small = OrbPlacement(0.08f, 0.52f),
    )
}

@Composable
internal fun AppBackdrop(
    selectedTab: Int,
    modifier: Modifier = Modifier,
) {
    val colors = MaterialTheme.colorScheme
    val isDark = colors.background.luminance() < 0.22f
    val baseBrush = remember(colors.background, colors.surface, colors.surfaceVariant) {
        Brush.verticalGradient(
            colors = if (isDark) {
                listOf(
                    lerp(colors.background, colors.surface, 0.18f),
                    colors.background,
                    lerp(colors.surfaceVariant, colors.background, 0.72f)
                )
            } else {
                listOf(
                    lerp(colors.background, colors.surface, 0.78f),
                    colors.background,
                    lerp(colors.surfaceVariant, colors.background, 0.30f)
                )
            }
        )
    }
    val topGlow = colors.primary.copy(alpha = if (isDark) 0.055f else 0.09f)
    val leftGlow = if (isDark) {
        colors.tertiary.copy(alpha = 0.045f)
    } else {
        lerp(colors.tertiary, colors.secondaryContainer, 0.74f).copy(alpha = 0.24f)
    }
    val bottomGlow = if (isDark) {
        colors.primary.copy(alpha = 0.04f)
    } else {
        lerp(colors.secondary, colors.primaryContainer, 0.70f).copy(alpha = 0.22f)
    }
    val lightOrbOutline = colors.outlineVariant.copy(alpha = 0.26f)
    val topOrbGlow = if (isDark) {
        topGlow
    } else {
        lerp(colors.primary, colors.primaryContainer, 0.72f).copy(alpha = 0.32f)
    }

    BoxWithConstraints(
        modifier = modifier
            .fillMaxSize()
            .background(baseBrush)
    ) {
        val scene = remember(selectedTab) { orbSceneForTab(selectedTab) }
        AnimatedBackdropOrb(
            placement = scene.large,
            size = 258.dp,
            shape = Android16OrbLarge,
            color = topOrbGlow,
            outline = if (isDark) null else lightOrbOutline,
            label = "large_orb",
        )
        AnimatedBackdropOrb(
            placement = scene.medium,
            size = 198.dp,
            shape = Android16OrbMedium,
            color = bottomGlow,
            outline = if (isDark) null else lightOrbOutline.copy(alpha = 0.20f),
            label = "medium_orb",
        )
        AnimatedBackdropOrb(
            placement = scene.small,
            size = 146.dp,
            shape = Android16OrbSmall,
            color = leftGlow,
            outline = if (isDark) null else lightOrbOutline.copy(alpha = 0.22f),
            label = "small_orb",
        )
    }
}

@Composable
private fun BoxWithConstraintsScope.AnimatedBackdropOrb(
    placement: OrbPlacement,
    size: Dp,
    shape: Shape,
    color: Color,
    outline: Color?,
    label: String,
) {
    val targetX = maxWidth * placement.xFraction - size / 2
    val targetY = maxHeight * placement.yFraction - size / 2
    val density = LocalDensity.current
    val targetXPx = with(density) { targetX.toPx() }
    val targetYPx = with(density) { targetY.toPx() }
    val animatedX by animateFloatAsState(
        targetValue = targetXPx,
        animationSpec = CsqttMotion.backdropTween(),
        label = "${label}_x",
    )
    val animatedY by animateFloatAsState(
        targetValue = targetYPx,
        animationSpec = CsqttMotion.backdropTween(),
        label = "${label}_y",
    )
    val animatedColor by animateColorAsState(
        targetValue = color,
        animationSpec = CsqttMotion.backdropTween(),
        label = "${label}_color",
    )

    Box(
        modifier = Modifier
            .size(size)
            .graphicsLayer {
                translationX = animatedX
                translationY = animatedY
                this.shape = shape
                clip = true
            }
            .background(animatedColor)
            .then(if (outline == null) Modifier else Modifier.border(1.dp, outline, shape)),
    )
}
