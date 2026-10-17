package com.example.shieldav

import android.content.Context
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.util.zip.GZIPInputStream

/**
 * Downloads the compact definitions file (gzip text) built by the
 * "Build definitions" GitHub workflow and loads it into [DefinitionDb].
 *
 * File format, one entry per line:
 *   # comment / header lines start with '#'
 *   <md5-or-sha256-hex>:<signature name>
 */
object DefinitionUpdater {

    sealed class Result {
        object UpToDate : Result()
        data class Updated(val count: Int) : Result()
        data class Failed(val message: String) : Result()
    }

    const val PREFS = "av"
    const val KEY_URL = "defs_url"
    const val KEY_ETAG = "defs_etag"
    const val KEY_UPDATED = "defs_updated_at"

    fun currentUrl(ctx: Context): String =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_URL, null) ?: BuildConfig.DEFS_URL

    fun update(ctx: Context, db: DefinitionDb, onProgress: (Int) -> Unit): Result {
        val prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val url = currentUrl(ctx)
        var conn: HttpURLConnection? = null
        try {
            conn = (URL(url).openConnection() as HttpURLConnection).apply {
                connectTimeout = 20_000
                readTimeout = 60_000
                instanceFollowRedirects = true
                setRequestProperty("User-Agent", "ShieldAV/${BuildConfig.VERSION_NAME}")
                prefs.getString(KEY_ETAG, null)?.let { setRequestProperty("If-None-Match", it) }
            }
            when (val code = conn.responseCode) {
                HttpURLConnection.HTTP_NOT_MODIFIED -> return Result.UpToDate
                HttpURLConnection.HTTP_OK -> Unit
                404 -> return Result.Failed(
                    "Definitions not found (HTTP 404). Run the 'Build definitions' workflow in GitHub first, " +
                        "and make sure the repository is public."
                )
                else -> return Result.Failed("Server returned HTTP $code")
            }
            val etag = conn.getHeaderField("ETag")

            val count = conn.inputStream.use { raw ->
                BufferedReader(InputStreamReader(GZIPInputStream(raw), Charsets.UTF_8), 1 shl 16).use { reader ->
                    val entries = reader.lineSequence().mapNotNull { parseLine(it) }
                    db.replaceAll(entries, onProgress)
                }
            }

            prefs.edit()
                .putString(KEY_ETAG, etag)
                .putLong(KEY_UPDATED, System.currentTimeMillis())
                .apply()
            return Result.Updated(count)
        } catch (e: Exception) {
            return Result.Failed(e.message ?: e.javaClass.simpleName)
        } finally {
            conn?.disconnect()
        }
    }

    private fun parseLine(line: String): Pair<String, String>? {
        if (line.isEmpty() || line[0] == '#') return null
        val idx = line.indexOf(':')
        if (idx != 32 && idx != 64) return null
        val hash = line.substring(0, idx).lowercase()
        if (!hash.all { it in '0'..'9' || it in 'a'..'f' }) return null
        val name = line.substring(idx + 1).ifBlank { "Malware" }
        return hash to name
    }
}
