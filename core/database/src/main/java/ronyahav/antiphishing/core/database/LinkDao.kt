package ronyahav.antiphishing.core.database

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import kotlinx.coroutines.flow.Flow

@Dao
interface LinkDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertLink(link: ScannedLink)

    // Deletes safe links (isSuspicious = 0) that are no longer in the top 5 most recent scans
    @Query("DELETE FROM scanned_links WHERE isSuspicious = 0 AND id NOT IN (SELECT id FROM scanned_links ORDER BY timestamp DESC LIMIT 5)")
    suspend fun enforceFifoOnSafeLinks()

    // Transaction to insert a new link and immediately clean up old safe links to maintain privacy
    @Transaction
    suspend fun insertAndTrim(link: ScannedLink) {
        insertLink(link)
        enforceFifoOnSafeLinks()
    }

    // Retrieve the latest 5 scanned links for the dashboard view
    @Query("SELECT * FROM scanned_links ORDER BY timestamp DESC LIMIT 5")
    fun getRecentLinks(): Flow<List<ScannedLink>>

    // Get the total count of scanned links since a specific timestamp
    @Query("SELECT COUNT(*) FROM scanned_links WHERE timestamp >= :startOfDay")
    fun getTodayScannedCount(startOfDay: Long): Flow<Int>

    // Get the total count of links marked as suspicious
    @Query("SELECT COUNT(*) FROM scanned_links WHERE isSuspicious = 1")
    fun getBlockedThreatsCount(): Flow<Int>

    // Clears all history, both safe and suspicious, providing full user control
    @Query("DELETE FROM scanned_links")
    suspend fun clearHistory()
}