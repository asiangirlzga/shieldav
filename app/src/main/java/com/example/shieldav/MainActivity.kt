package com.example.shieldav

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.DocumentsContract
import android.text.format.DateFormat
import android.view.View
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
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Date

class MainActivity : AppCompatActivity() {

    private lateinit var db: DefinitionDb
    private lateinit var tvDefs: TextView
    private lateinit var tvStatus: TextView
    private lateinit var progress: ProgressBar
    private lateinit var btnUpdate: Button
    private lateinit var btnScanApps: Button
    private lateinit var btnScanFolder: Button
    private lateinit var btnCancel: Button
    private lateinit var cbAll: CheckBox
    private lateinit var lv: ListView
    private lateinit var adapter: ArrayAdapter<String>

    private val findings = mutableListOf<Finding>()
    private var job: Job? = null

    private val pickFolder =
        registerForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
            if (uri != null) scanFolder(uri)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        db = DefinitionDb.get(this)

        tvDefs = findViewById(R.id.tvDefs)
        tvStatus = findViewById(R.id.tvStatus)
        progress = findViewById(R.id.progress)
        btnUpdate = findViewById(R.id.btnUpdate)
        btnScanApps = findViewById(R.id.btnScanApps)
        btnScanFolder = findViewById(R.id.btnScanFolder)
        btnCancel = findViewById(R.id.btnCancel)
        cbAll = findViewById(R.id.cbAll)
        lv = findViewById(R.id.lvResults)

        adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, mutableListOf<String>())
        lv.adapter = adapter
        lv.setOnItemClickListener { _, _, pos, _ -> findings.getOrNull(pos)?.let { showFinding(it) } }

        btnUpdate.setOnClickListener { updateDefinitions() }
        btnScanApps.setOnClickListener { scanApps() }
        btnScanFolder.setOnClickListener { pickFolder.launch(null) }
        btnCancel.setOnClickListener { job?.cancel() }

        refreshDefsInfo()
    }

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
        btnUpdate.isEnabled = !busy
        btnScanApps.isEnabled = !busy
        btnScanFolder.isEnabled = !busy
        btnCancel.isEnabled = busy
    }

    private fun runJob(start: String, block: suspend () -> Unit) {
        job?.cancel()
        setBusy(true)
        tvStatus.text = start
        job = lifecycleScope.launch {
            try {
                block()
            } catch (e: CancellationException) {
                tvStatus.text = "Cancelled"
                throw e
            } catch (e: Exception) {
                tvStatus.text = "Error: ${e.message}"
            } finally {
                setBusy(false)
            }
        }
    }

    private fun postStatus(text: String) {
        tvStatus.post { tvStatus.text = text }
    }

    private fun updateDefinitions() = runJob("Downloading definitions…") {
        val result = withContext(Dispatchers.IO) {
            DefinitionUpdater.update(applicationContext, db) { n -> postStatus("Importing… $n signatures") }
        }
        tvStatus.text = when (result) {
            is DefinitionUpdater.Result.UpToDate -> "Definitions are already up to date"
            is DefinitionUpdater.Result.Updated -> "Updated: ${result.count} signatures"
            is DefinitionUpdater.Result.Failed -> "Update failed: ${result.message}"
        }
        refreshDefsInfo()
    }

    private fun scanApps() = runJob("Scanning installed apps…") {
        val scanner = Scanner(applicationContext, db)
        val result = withContext(Dispatchers.IO) { scanner.scanInstalledApps { postStatus(it) } }
        showResults(result, "apps")
    }

    private fun scanFolder(uri: Uri) = runJob("Scanning folder…") {
        val scanner = Scanner(applicationContext, db)
        val all = cbAll.isChecked
        val result = withContext(Dispatchers.IO) { scanner.scanTree(uri, all) { postStatus(it) } }
        showResults(result, "folder")
    }

    private fun showResults(result: List<Finding>, what: String) {
        findings.clear()
        findings.addAll(result.sortedBy { it.severity })
        adapter.clear()
        adapter.addAll(findings.map { it.toString() })
        val malware = findings.count { it.severity == Severity.MALWARE }
        val suspicious = findings.size - malware
        tvStatus.text = if (findings.isEmpty()) "Scan of $what finished: no threats found"
        else "Scan of $what finished: $malware malware, $suspicious to review. Tap an item for actions."
    }

    private fun showFinding(f: Finding) {
        val b = AlertDialog.Builder(this).setTitle(f.title).setMessage(f.detail)
            .setNegativeButton("Close", null)
        if (f.packageName != null) {
            b.setPositiveButton("Uninstall") { _, _ ->
                startActivity(Intent(Intent.ACTION_DELETE, Uri.parse("package:${f.packageName}")))
            }
        } else if (f.fileUri != null) {
            b.setPositiveButton("Delete file") { _, _ ->
                val ok = runCatching { DocumentsContract.deleteDocument(contentResolver, f.fileUri) }
                    .getOrDefault(false)
                if (ok) {
                    val i = findings.indexOf(f)
                    if (i >= 0) {
                        findings.removeAt(i)
                        adapter.remove(adapter.getItem(i))
                    }
                    Toast.makeText(this, "File deleted", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this, "Could not delete file", Toast.LENGTH_LONG).show()
                }
            }
        }
        b.show()
    }
}
