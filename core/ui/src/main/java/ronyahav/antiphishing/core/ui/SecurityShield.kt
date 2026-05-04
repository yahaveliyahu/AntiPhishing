package ronyahav.antiphishing.core.ui

import androidx.compose.animation.core.*
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp

@Composable
fun SecurityShield(
    modifier: Modifier = Modifier
) {
    // Infinite transition for the "breathing" effect
    val infiniteTransition = rememberInfiniteTransition(label = "ShieldPulse")

    val scale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 1.15f,
        animationSpec = infiniteRepeatable(
            animation = tween(1500, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "ShieldScale"
    )

//    Icon(
//        imageVector = Icons.Default.Shield,
    Image(
        painter = painterResource(id = R.drawable.shield),
        contentDescription = null,
        modifier = modifier
            .size(120.dp)
            .scale(scale)
            .graphicsLayer {
                // Subtle alpha animation to enhance the effect
                alpha = 0.8f + (scale - 1f)
            }
//        tint = MaterialTheme.colorScheme.primary
    )
}