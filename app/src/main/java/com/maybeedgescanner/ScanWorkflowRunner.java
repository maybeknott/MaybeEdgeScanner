package com.maybeedgescanner;

import java.util.concurrent.ExecutorService;

/** Runs a staged scan on the service-owned orchestrator thread + worker pool. */
interface ScanWorkflowRunner {
    void run(long generation, ExecutorService executor, ScanLaunchSpec spec);
}
