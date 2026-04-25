package ronyahav.antiphishing.core.database

import androidx.room.Database
import androidx.room.RoomDatabase

@Database(entities = [ScannedLink::class], version = 1, exportSchema = false)
abstract class AppDatabase : RoomDatabase() {
    abstract fun linkDao(): LinkDao
}