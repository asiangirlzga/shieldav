package com.example.shieldav

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.documentfile.provider.DocumentFile
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import java.io.File
import java.io.InputStream
import java.security.MessageDigest

enum class Severity { MALWARE, SUSPICIOUS }

data class Finding(
    val severity: Severity,
    val title: String,
    val detail: String,
    val packageName: String? = null,
    val fileUri: Uri? = null
) {
    override fun toString(): String = "[${severity.name}] $title\n$detail"
}

object Hashing {
    data class Digests(val md5: String, val sha256: String)

    fun digest(input: InputStream): Digests {
        val md5 = MessageDigest.getInstance("MD5")
        val sha = MessageDigest.getInstance("SHA-256")
        val buf = ByteArray(64 * 1024)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            md5.update(buf, 0, n)
            sha.update(buf, 0, n)
        }
        return Digests(hex(md5.digest()), hex(sha.digest()))
    }

    private fun hex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) {
            val v = x.toInt() and 0xff
            sb.append("0123456789abcdef"[v ushr 4]).append("0123456789abcdef"[v and 15])
        }
        return sb.toString()
    }
}

/** Heuristic review of an app's requested permissions. This is NOT a malware verdict. */
object RiskAnalyzer {
    private val weights = mapOf(
        "android.permission.SEND_SMS" to 2,
        "android.permission.READ_SMS" to 2,
        "android.permission.RECEIVE_SMS" to 1,
        "android.permission.READ_CALL_LOG" to 1,
        "android.permission.SYSTEM_ALERT_WINDOW" to 2,
        "android.permission.REQUEST_INSTALL_PACKAGES" to 2,
        "android.permission.RECORD_AUDIO" to 1,
        "android.permission.READ_CONTACTS" to 1,
        "android.permission.MANAGE_EXTERNAL_STORAGE" to 1,
        "android.permission.ACCESS_BACKGROUND_LOCATION" to 1,
        "android.permission.QUERY_ALL_PACKAGES" to 1
    )

    data class Assessment(val score: Int, val flagged: List<String>)

    fun assess(requested: Array<String>?): Assessment {
        val hits = requested.orEmpty().filter { it in weights }
        return Assessment(hits.sumOf { weights.getValue(it) }, hits.map { it.substringAfterLast('.') })
    }

    fun isSuspicious(a: Assessment, sideloaded: Boolean): Boolean =
        a.score >= 8 || (sideloaded && a.score >= 5)
}

class Scanner(private val ctx: Context, private val db: DefinitionDb) {

    private fun match(d: Hashing.Digests): String? = db.lookup(d.sha256) ?: db.lookup(d.md5)

    suspend fun scanInstalledApps(onProgress: (String) -> Unit): List<Finding> {
        val pm = ctx.packageManager
        val findings = mutableListOf<Finding>()
        val packages = installedPackages(pm).filter { p ->
            val ai = p.applicationInfo
            ai != null && p.packageName != ctx.packageName &&
                (ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) == 0
        }

        packages.forEachIndexed { i, p ->
            currentCoroutineContext().ensureActive()
            val ai = p.applicationInfo ?: return@forEachIndexed
            val label = runCatching { pm.getApplicationLabel(ai).toString() }.getOrDefault(p.packageName)
            onProgress("Scanning ${i + 1}/${packages.size}: $label")

            val paths = buildList {
                ai.sourceDir?.let { add(it) }
                ai.splitSourceDirs?.let { addAll(it) }
            }

            var malwareName: String? = null
            for (path in paths) {
                val d = runCatching { File(path).inputStream().use { Hashing.digest(it) } }.getOrNull() ?: continue
                malwareName = match(d)
                if (malwareName != null) break
            }

            if (malwareName != null) {
                findings += Finding(
                    Severity.MALWARE, "$label ($malwareName)",
                    "Known malware signature matched.\nPackage: ${p.packageName}",
                    packageName = p.packageName
                )
            } else {
                val a = RiskAnalyzer.assess(p.requestedPermissions)
                val sideloaded = installer(pm, p.packageName) !in TRUSTED_INSTALLERS
                if (RiskAnalyzer.isSuspicious(a, sideloaded)) {
                    findings += Finding(
                        Severity.SUSPICIOUS, "$label (review)",
                        "Risky permissions: ${a.flagged.joinToString(", ")}" +
                            (if (sideloaded) "\nNot installed from Google Play." else "") +
                            "\nPackage: ${p.packageName}\nThis is a heuristic, not a virus detection.",
                        packageName = p.packageName
                    )
                }
            }
        }
        return findings
    }

    suspend fun scanTree(root: Uri, allTypes: Boolean, onProgress: (String) -> Unit): List<Finding> {
        val findings = mutableListOf<Finding>()
        val start = DocumentFile.fromTreeUri(ctx, root) ?: return findings
        val stack = ArrayDeque<DocumentFile>()
        stack.addLast(start)
        var scanned = 0

        while (stack.isNotEmpty()) {
            currentCoroutineContext().ensureActive()
            val node = stack.removeLast()
            if (node.isDirectory) {
                node.listFiles().forEach { stack.addLast(it) }
                continue
            }
            val name = node.name ?: continue
            if (!allTypes && name.substringAfterLast('.', "").lowercase() !in RISKY_EXTENSIONS) continue
            if (node.length() > MAX_FILE_BYTES) continue

            scanned++
            if (scanned % 5 == 0) onProgress("Scanned $scanned files… $name")

            val d = runCatching {
                ctx.contentResolver.openInputStream(node.uri)?.use { Hashing.digest(it) }
            }.getOrNull() ?: continue

            val hit = match(d)
            if (hit != null) {
                findings += Finding(
                    Severity.MALWARE, "$name ($hit)",
                    "Known malware signature matched.\nSHA-256: ${d.sha256}",
                    fileUri = node.uri
                )
            }
        }
        onProgress("Scanned $scanned files")
        return findings
    }

    @Suppress("DEPRECATION")
    private fun installedPackages(pm: PackageManager): List<PackageInfo> =
        if (Build.VERSION.SDK_INT >= 33)
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        else
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)

    @Suppress("DEPRECATION")
    private fun installer(pm: PackageManager, pkg: String): String? =
        try {
            if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(pkg).installingPackageName
            else pm.getInstallerPackageName(pkg)
        } catch (e: Exception) {
            null
        }

    companion object {
        private const val MAX_FILE_BYTES = 200L * 1024 * 1024
        private val TRUSTED_INSTALLERS = setOf("com.android.vending")
        private val RISKY_EXTENSIONS = setOf(
            "apk", "apks", "xapk", "dex", "jar", "zip", "rar", "7z", "exe", "dll", "scr", "bat",
            "cmd", "com", "msi", "vbs", "js", "ps1", "sh", "so", "docm", "xlsm", "pptm", "lnk", "iso"
        )
    }
}
