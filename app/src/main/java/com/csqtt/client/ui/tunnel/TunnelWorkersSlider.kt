// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.height
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp
import com.csqtt.client.CsqttConstants
import kotlin.math.roundToInt

import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberUpdatedState

@Composable
internal fun CompactSteppedSlider(
    value: Float,
    onValueChange: (Float) -> Unit,
    valueRange: ClosedFloatingPointRange<Float>,
    stepSize: Float,
    enabled: Boolean,
    modifier: Modifier = Modifier,
) {
    val activeColor = MaterialTheme.colorScheme.primary.copy(alpha = if (enabled) 1f else 0.38f)
    val inactiveColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = if (enabled) 1f else 0.55f)
    val thumbStrokeColor = MaterialTheme.colorScheme.surface
    val density = LocalDensity.current
    val thumbRadiusPx = with(density) { 9.dp.toPx() }
    val trackWidthPx = with(density) { 5.dp.toPx() }

    val currentOnValueChange by rememberUpdatedState(onValueChange)
    val currentValueRange by rememberUpdatedState(valueRange)
    val currentStepSize by rememberUpdatedState(stepSize)

    fun snap(raw: Float): Float {
        val min = currentValueRange.start
        val max = currentValueRange.endInclusive
        val snapped = (((raw - min) / currentStepSize).roundToInt() * currentStepSize) + min
        return snapped.coerceIn(min, max)
    }

    fun positionToValue(x: Float, width: Float): Float {
        val left = thumbRadiusPx
        val right = (width - thumbRadiusPx).coerceAtLeast(left + 1f)
        val fraction = ((x.coerceIn(left, right) - left) / (right - left)).coerceIn(0f, 1f)
        return snap(currentValueRange.start + fraction * (currentValueRange.endInclusive - currentValueRange.start))
    }

    Canvas(
        modifier = modifier
            .height(34.dp)
            .pointerInput(enabled) {
                if (!enabled) return@pointerInput
                detectDragGestures(
                    onDragStart = { offset ->
                        currentOnValueChange(positionToValue(offset.x, size.width.toFloat()))
                    },
                    onDrag = { change, _ ->
                        change.consume()
                        currentOnValueChange(positionToValue(change.position.x, size.width.toFloat()))
                    }
                )
            }
            .pointerInput(enabled) {
                if (!enabled) return@pointerInput
                detectTapGestures { offset ->
                    currentOnValueChange(positionToValue(offset.x, size.width.toFloat()))
                }
            },
    ) {
        val centerY = size.height / 2f
        val left = thumbRadiusPx
        val right = size.width - thumbRadiusPx
        val range = (valueRange.endInclusive - valueRange.start).coerceAtLeast(1f)
        val fraction = ((value - valueRange.start) / range).coerceIn(0f, 1f)
        val thumbX = left + (right - left) * fraction

        drawLine(inactiveColor, Offset(left, centerY), Offset(right, centerY), trackWidthPx, StrokeCap.Round)
        drawLine(activeColor, Offset(left, centerY), Offset(thumbX, centerY), trackWidthPx, StrokeCap.Round)

        val tickCount = (((valueRange.endInclusive - valueRange.start) / stepSize).roundToInt()).coerceAtLeast(1)
        repeat(tickCount + 1) { index ->
            val tickFraction = index / tickCount.toFloat()
            val tickX = left + (right - left) * tickFraction
            drawCircle(
                color = if (tickX <= thumbX) activeColor else inactiveColor,
                radius = 2.dp.toPx(),
                center = Offset(tickX, centerY),
            )
        }

        drawCircle(color = activeColor, radius = thumbRadiusPx, center = Offset(thumbX, centerY))
        drawCircle(
            color = thumbStrokeColor,
            radius = thumbRadiusPx,
            center = Offset(thumbX, centerY),
            style = androidx.compose.ui.graphics.drawscope.Stroke(width = 2.dp.toPx()),
        )
    }
}

internal fun roundToGroup(value: Float, maxW: Float = 96f): Float {
    val groupSize = CsqttConstants.Tunnel.WORKERS_PER_GROUP
    val rounded = (Math.round(value / groupSize) * groupSize).toFloat()
    return rounded.coerceIn(groupSize.toFloat(), maxW)
}
