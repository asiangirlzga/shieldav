package com.example.shieldav

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.DocumentsContract
import android.provider.Settings
import android.text.format.DateFormat
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.ListView
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.Date

class MainActivity : AppCompatActivity() {

    private lateinit var db: DefinitionDb
    private lateinit var tvDefs: TextView
    private lateinit var tvBanner: TextView
    private lateinit var tvStatus: TextView
    private lateinit var progress: ProgressBar
    private lateinit var btnUpdate: Button
    private lateinit var btnFullScan: Button
    private lateinit var btnScanApps: Button
    private lateinit var btnScanFolder: Button
    private lateinit var btnCancel: Button
    private lateinit var cbAll: CheckBox
    private lateinit var lv: ListView
    private lateinit var adapter: FindingAdapter

    private val findings = mutableListOf<Finding>()
    private var job: Job? = null
    private var pendingFullScan = false

    private val pickFolder =
        registerForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
            if (uri != null) scanFolder(uri)
        }

    private val requestStorage =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) startFullScan()
            else banner(C_SUSPICIOUS, "Storage permission denied. Full scan needs storage access.")
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        db = DefinitionDb.get(this)

        tvDefs = findViewById(R.id.tvDefs)
        tvBanner = findViewById(R.id.tvBanner)
        tvStatus = findViewById(R.id.tvStatus)
        progress = findViewById(R.id.progress)
        btnUpdate = findViewById(R.id.btnUpdate)
        btnFullScan = findViewById(R.id.btnFullScan)
        btnScanApps = findViewById(R.id.btnScanApps)
        btnScanFolder = findViewById(R.id.btnScanFolder)
        btnCancel = findViewById(R.id.btnCancel)
        cbAll = findViewById(R.id.cbAll)
        lv = findViewById(R.id.lvResults)

        adapter = FindingAdapter()
        lv.adapter = adapter
        lv.setOnItemClickListener { _, _, pos, _ -> findings.getOrNull(pos)?.let { showFinding(it) } }

        btnUpdate.setOnClickListener { updateDefinitions() }
        btnFullScan.setOnClickListener { onFullScanClicked() }
        btnScanApps.setOnClickListener { scanApps() }
        btnScanFolder.setOnClickListener { pickFolder.launch(null) }
        btnCancel.setOnClickListener { job?.cancel() }

        banner(C_INFO, "Ready to scan")
        refreshDefsInfo()
    }

    override fun onResume() {
        super.onResume()
        // Returning from the "All files access" settings screen.
        if (pendingFullScan && hasStorageAccess()) {
            pendingFullScan = false
            startFullScan()
        }
    }

    // ---------- colour coding ----------

    private fun banner(color: Int, text: String) {
        tvBanner.text = text
        tvBanner.background = GradientDrawable().apply {
            setColor(color)
            cornerRadius = 16f
        }
    }

    private fun colorFor(s: Severity) = if (s == Severity.MALWARE) C_MALWARE else C_SUSPICIOUS

    private inner class FindingAdapter :
        ArrayAdapter<Finding>(this@MainActivity, 0, findings) {
        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val v = convertView
                ?: LayoutInflater.from(context).inflate(R.layout.item_finding, parent, false)
            val f = getItem(position)!!
            val c = colorFor(f.severity)
            v.findViewById<View>(R.id.strip).setBackgroundColor(c)
            v.setBackgroundColor(Color.argb(0x26, Color.red(c), Color.green(c), Color.blue(c)))
            v.findViewById<TextView>(R.id.tvBadge).apply {
                text = if (f.severity == Severity.MALWARE) "MALWARE" else "REVIEW"
                background = GradientDrawable().apply { setColor(c); cornerRadius = 20f }
            }
            v.findViewById<TextView>(R.id.tvTitle).text = f.title
            v.findViewById<TextView>(R.id.tvDetail).text = f.detail
            return v
        }
    }

    // ---------- UI state ----------

    private fun refreshDefsInfo() {
        lifecycleScope.launch {
            val count = withContext(Dispatchers.IO) { db.count() }
            val ts = getSharedPreferences(DefinitionUpdater.PREFS, MODE_PRIVATE)
                .getLong(DefinitionUpdater.KEY_UPDATED, 0L)
            val whenText = if (ts == 0L) "never updated"
            else "updated " + DateFormat.format("d MMM yyyy HH:mm", Date(ts))
            tvDefs.text = "Definitions: $count signatures, $whenText"
        }
    }

    private fun setBusy(busy: Boolean) {
        progress.visibility = if (busy) View.VISIBLE else View.INVISIBLE
        listOf(btnUpdate, btnFullScan, btnScanApps, btnScanFolder).forEach { it.isEnabled = !busy }
        btnCancel.isEnabled = busy
    }

    private fun runJob(start: String, block: suspend () -> Unit) {
        job?.cancel()
        setBusy(true)
        banner(C_INFO, start)
        tvStatus.text = ""
        job = lifecycleScope.launch {
            try {
                block()
            } catch (e: CancellationException) {
                banner(C_INFO, "Cancelled")
                throw e
            } catch (e: Exception) {
                banner(C_SUSPICIOUS, "Error: ${e.message}")
            } finally {
                setBusy(false)
            }
        }
    }

    private fun postStatus(text: String) {
        tvStatus.post { tvStatus.text = text }
    }

    // ---------- actions ----------

    private fun updateDefinitions() = runJob("Downloading definitions…") {
        val result = withContext(Dispatchers.IO) {
            DefinitionUpdater.update(applicationContext, db) { n -> postStatus("Importing… $n signatures") }
        }
        when (result) {
            is DefinitionUpdater.Result.UpToDate -> banner(C_SAFE, "Definitions are already up to date")
            is DefinitionUpdater.Result.Updated -> banner(C_SAFE, "Updated: ${result.count} signatures")
            is DefinitionUpdater.Result.Failed -> banner(C_SUSPICIOUS, "Update failed: ${result.message}")
        }
        tvStatus.text = ""
        refreshDefsInfo()
    }

    private fun scanApps() = runJob("Scanning installed apps…") {
        val scanner = Scanner(applicationContext, db)
        val result = withContext(Dispatchers.IO) { scanner.scanInstalledApps { postStatus(it) } }
        showResults(result, "Apps")
    }

    private fun scanFolder(uri: Uri) = runJob("Scanning folder…") {
        val scanner = Scanner(applicationContext, db)
        val all = cbAll.isChecked
        val result = withContext(Dispatchers.IO) { scanner.scanTree(uri, all) { postStatus(it) } }
        showResults(result, "Folder")
    }

    private fun hasStorageAccess(): Boolean =
        if (Build.VERSION.SDK_INT >= 30) Environment.isExternalStorageManager()
        else ContextCompat.checkSelfPermission(
            this, Manifest.permission.READ_EXTERNAL_STORAGE
        ) == PackageManager.PERMISSION_GRANTED

    private fun onFullScanClicked() {
        if (hasStorageAccess()) {
            startFullScan()
            return
        }
        if (Build.VERSION.SDK_INT >= 30) {
            AlertDialog.Builder(this)
                .setTitle("Allow access to all files")
                .setMessage(
                    "A full device scan has to read every file on your storage. On the next screen " +
                        "turn on \"Allow access to manage all files\" for ShieldAV, then come back. " +
                        "Files are only hashed on your phone and never uploaded."
                )
                .setPositiveButton("Open settings") { _, _ ->
                    pendingFullScan = true
                    val pkg = Uri.parse("package:$packageName")
                    try {
                        startActivity(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, pkg))
                    } catch (e: Exception) {
                        startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
                    }
                }
                .setNegativeButton("Cancel", null)
                .show()
        } else {
            requestStorage.launch(Manifest.permission.READ_EXTERNAL_STORAGE)
        }
    }

    private fun startFullScan() = runJob("Full device scan: apps…") {
        val scanner = Scanner(applicationContext, db)
        val all = cbAll.isChecked
        val result = withContext(Dispatchers.IO) {
            val apps = scanner.scanInstalledApps { postStatus("Apps: $it") }
            val files = scanner.scanStorage(all) { postStatus(it) }
            apps + files
        }
        showResults(result, "Full device")
    }

    private fun showResults(result: List<Finding>, what: String) {
        findings.clear()
        findings.addAll(result.sortedBy { it.severity })
        adapter.notifyDataSetChanged()
        val malware = findings.count { it.severity == Severity.MALWARE }
        val review = findings.size - malware
        tvStatus.text = "Tap an item for actions."
        when {
            malware > 0 -> banner(C_MALWARE, "$what scan: $malware malware found, $review to review")
            review > 0 -> banner(C_SUSPICIOUS, "$what scan: no malware, $review app(s) to review")
            else -> {
                banner(C_SAFE, "$what scan finished: no threats found")
                tvStatus.text = ""
            }
        }
    }

    private fun showFinding(f: Finding) {
        val b = AlertDialog.Builder(this).setTitle(f.title).setMessage(f.detail)
            .setNegativeButton("Close", null)
        if (f.packageName != null) {
            b.setPositiveButton("Uninstall") { _, _ ->
                startActivity(Intent(Intent.ACTION_DELETE, Uri.parse("package:${f.packageName}")))
            }
        } else if (f.fileUri != null || f.filePath != null) {
            b.setPositiveButton("Delete file") { _, _ ->
                val ok = runCatching {
                    if (f.filePath != null) File(f.filePath).delete()
                    else DocumentsContract.deleteDocument(contentResolver, f.fileUri!!)
                }.getOrDefault(false)
                if (ok) {
                    findings.remove(f)
                    adapter.notifyDataSetChanged()
                    Toast.makeText(this, "File deleted", Toast.LENGTH_SHORT).show()
                    val malware = findings.count { it.severity == Severity.MALWARE }
                    if (findings.isEmpty()) banner(C_SAFE, "All threats removed")
                    else if (malware == 0) banner(C_SUSPICIOUS, "${findings.size} app(s) to review")
                } else {
                    Toast.makeText(this, "Could not delete file", Toast.LENGTH_LONG).show()
                }
            }
        }
        b.show()
    }

    companion object {
        private val C_MALWARE = Color.parseColor("#D32F2F")     // red
        private val C_SUSPICIOUS = Color.parseColor("#F57C00")  // orange
        private val C_SAFE = Color.parseColor("#2E7D32")        // green
        private val C_INFO = Color.parseColor("#1565C0")        // blue
    }
}
