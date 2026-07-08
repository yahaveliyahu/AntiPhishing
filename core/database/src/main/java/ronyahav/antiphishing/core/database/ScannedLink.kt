package ronyahav.antiphishing.core.database

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "scanned_links")
data class ScannedLink(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val url: String,
    val timestamp: Long = System.currentTimeMillis(),
    val isSuspicious: Boolean, // True for Red, False for Green
    val riskScore: Int, // Calculated risk from ML/Heuristics (0-100)
    val threatType: String? = null, // Optional: phishing, malware, etc.
    val explanation: String? = null // Why this link was flagged
)