package com.example.shieldav

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Background job that keeps virus definitions fresh (scheduled in [AvApp]). */
class UpdateWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {
    override suspend fun doWork(): androidx.work.ListenableWorker.Result = withContext(Dispatchers.IO) {
        val r = DefinitionUpdater.update(applicationContext, DefinitionDb.get(applicationContext)) {}
        if (r is DefinitionUpdater.Result.Failed) androidx.work.ListenableWorker.Result.retry()
        else androidx.work.ListenableWorker.Result.success()
    }
}
