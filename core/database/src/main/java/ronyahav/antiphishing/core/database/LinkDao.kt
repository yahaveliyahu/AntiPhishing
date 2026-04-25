package ronyahav.antiphishing.core.database

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface LinkDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertLink(link: ScannedLink)

    // Get the last 3 scanned links for the home screen dashboard
    @Query("SELECT * FROM scanned_links ORDER BY timestamp DESC LIMIT 3")
    fun getRecentLinks(): Flow<List<ScannedLink>>

    // Count total links scanned today (using simplified timestamp logic)
    @Query("SELECT COUNT(*) FROM scanned_links WHERE timestamp >= :startOfDay")
    fun getTodayScannedCount(startOfDay: Long): Flow<Int>

    // Count suspicious links (Red links)
    @Query("SELECT COUNT(*) FROM scanned_links WHERE isSuspicious = 1")
    fun getBlockedThreatsCount(): Flow<Int>

    @Query("DELETE FROM scanned_links")
    suspend fun clearHistory()
}