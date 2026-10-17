package com.example.shieldav

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/**
 * Local store of known-bad file hashes (MD5 = 32 hex chars, SHA-256 = 64 hex chars).
 */
class DefinitionDb private constructor(ctx: Context) :
    SQLiteOpenHelper(ctx.applicationContext, "defs.db", null, 1) {

    init {
        setWriteAheadLoggingEnabled(true)
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("CREATE TABLE sigs (hash TEXT PRIMARY KEY, name TEXT NOT NULL) WITHOUT ROWID")
        seed(db)
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {}

    private fun seed(db: SQLiteDatabase) {
        for ((hash, name) in BUILTIN) {
            db.execSQL("INSERT OR REPLACE INTO sigs(hash, name) VALUES(?, ?)", arrayOf(hash, name))
        }
    }

    fun lookup(hash: String): String? =
        readableDatabase.rawQuery("SELECT name FROM sigs WHERE hash = ?", arrayOf(hash)).use { c ->
            if (c.moveToFirst()) c.getString(0) else null
        }

    fun count(): Long =
        readableDatabase.rawQuery("SELECT COUNT(*) FROM sigs", null).use { c ->
            if (c.moveToFirst()) c.getLong(0) else 0L
        }

    /**
     * Replaces the whole database in one transaction. If [entries] throws part-way
     * (e.g. the download drops), the transaction rolls back and old definitions stay.
     */
    fun replaceAll(entries: Sequence<Pair<String, String>>, onProgress: (Int) -> Unit): Int {
        val db = writableDatabase
        var n = 0
        db.beginTransaction()
        try {
            db.execSQL("DELETE FROM sigs")
            seed(db)
            val st = db.compileStatement("INSERT OR REPLACE INTO sigs(hash, name) VALUES(?, ?)")
            try {
                for ((hash, name) in entries) {
                    st.clearBindings()
                    st.bindString(1, hash)
                    st.bindString(2, name)
                    st.executeInsert()
                    n++
                    if (n % 20000 == 0) onProgress(n)
                }
            } finally {
                st.close()
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
        return n
    }

    companion object {
        @Volatile
        private var instance: DefinitionDb? = null

        fun get(ctx: Context): DefinitionDb =
            instance ?: synchronized(this) {
                instance ?: DefinitionDb(ctx).also { instance = it }
            }

        /** Harmless industry-standard EICAR test file, so you can verify the scanner works. */
        val BUILTIN = listOf(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" to "Eicar-Test-File",
            "44d88612fea8a8f36de82e1278abb02f" to "Eicar-Test-File"
        )
    }
}
