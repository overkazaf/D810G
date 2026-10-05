package d810g;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import generic.jar.ResourceFile;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import d810g.core.DeobfuscationOrchestrator;
import d810g.core.PcodeUtils;
import d810g.engine.EngineManager;

/**
 * Ghidra Analyzer that automatically detects and deobfuscates functions
 * during the analysis phase. Runs after initial disassembly and function
 * detection, checking each function for obfuscation indicators.
 *
 * <p>Disabled by default -- users opt in via Analysis &gt; Auto-Analyze
 * options. When enabled, it scans every newly-discovered function for
 * control-flow-flattening signatures (dispatcher blocks, high back-edge
 * ratios) and sends suspicious functions to the Python engine for
 * deflattening, MBA simplification, and opaque predicate elimination.
 */
public class D810GAnalyzer extends AbstractAnalyzer {

    private static final String NAME = "D810G Deobfuscation";
    private static final String DESCRIPTION =
        "Automatically detects and removes control flow flattening, " +
        "MBA obfuscation, and bogus control flow from functions.";

    private EngineManager engineManager;

    public D810GAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
        setDefaultEnablement(false);  // user opts in
        setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after());
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean getDefaultEnablement(Program program) {
        return false;
    }

    @Override
    public boolean canAnalyze(Program program) {
        String processor = program.getLanguage().getProcessor().toString().toLowerCase();
        return processor.contains("x86")
            || processor.contains("aarch64")
            || processor.contains("arm");
    }

    @Override
    public boolean added(Program program, AddressSetView set,
            TaskMonitor monitor, MessageLog log) throws CancelledException {

        FunctionManager fm = program.getFunctionManager();
        FunctionIterator functions = fm.getFunctions(set, true);

        List<Function> suspiciousFunctions = new ArrayList<>();

        // Phase 1: Identify suspicious functions
        monitor.setMessage("D810G: Scanning for obfuscated functions...");
        while (functions.hasNext()) {
            monitor.checkCancelled();
            Function func = functions.next();
            if (isSuspicious(program, func)) {
                suspiciousFunctions.add(func);
            }
        }

        if (suspiciousFunctions.isEmpty()) {
            log.appendMsg(NAME, "No obfuscated functions detected.");
            return true;
        }

        log.appendMsg(NAME, String.format(
            "Found %d suspicious functions", suspiciousFunctions.size()));

        // Phase 2: Start engine and deobfuscate
        try {
            ensureEngineStarted();
        } catch (IOException e) {
            log.appendMsg(NAME, "Failed to start engine: " + e.getMessage());
            Msg.error(this, "D810G: Failed to start engine", e);
            return false;
        }

        DeobfuscationOrchestrator orchestrator = new DeobfuscationOrchestrator(
            engineManager.getProtocol()
        );

        int processed = 0;
        int patched = 0;
        monitor.initialize(suspiciousFunctions.size());
        monitor.setMessage("D810G: Deobfuscating functions...");

        for (Function func : suspiciousFunctions) {
            monitor.checkCancelled();
            monitor.setMessage("D810G: " + func.getName());
            try {
                DeobfuscationOrchestrator.DeobResult result =
                    orchestrator.deobfuscateFunction(program, func);
                processed++;
                if (result.patchCount > 0) {
                    patched++;
                    log.appendMsg(NAME, String.format(
                        "%s: %d patches applied (%s)",
                        func.getName(), result.patchCount, result.status
                    ));
                }
            } catch (Exception e) {
                log.appendMsg(NAME, String.format(
                    "%s: failed - %s", func.getName(), e.getMessage()
                ));
                Msg.warn(this, "D810G: Error processing " + func.getName(), e);
            }
            monitor.incrementProgress(1);
        }

        log.appendMsg(NAME, String.format(
            "Done: %d/%d functions processed, %d patched",
            processed, suspiciousFunctions.size(), patched
        ));

        return true;
    }

    @Override
    public void analysisEnded(Program program) {
        if (engineManager != null) {
            engineManager.close();
            engineManager = null;
        }
    }

    /**
     * Heuristic: a function is "suspicious" if it has a basic block with
     * many successors (dispatcher pattern) or a high back-edge ratio
     * relative to its size (characteristic of control-flow flattening).
     */
    private boolean isSuspicious(Program program, Function func) {
        List<Map<String, Object>> blocks;
        try {
            blocks = PcodeUtils.extractBlocks(program, func);
        } catch (Exception e) {
            // If we cannot decompile, skip silently
            return false;
        }

        if (blocks.size() < 5) {
            return false;
        }

        // Check for dispatcher-like blocks (3+ successors)
        for (Map<String, Object> block : blocks) {
            @SuppressWarnings("unchecked")
            List<Long> succs = (List<Long>) block.get("succs");
            if (succs != null && succs.size() >= 3) {
                return true;
            }
        }

        // Check for high back-edge ratio (characteristic of CFF)
        int backEdges = 0;
        int totalEdges = 0;
        for (Map<String, Object> block : blocks) {
            @SuppressWarnings("unchecked")
            List<Long> succs = (List<Long>) block.get("succs");
            if (succs != null) {
                long blockAddr = (Long) block.get("addr");
                for (Long succ : succs) {
                    totalEdges++;
                    if (succ <= blockAddr) {
                        backEdges++;
                    }
                }
            }
        }

        // High back-edge ratio (>40%) with many blocks suggests flattening
        if (totalEdges > 0 && blocks.size() > 8) {
            double ratio = (double) backEdges / totalEdges;
            if (ratio > 0.4) {
                return true;
            }
        }

        return false;
    }

    private void ensureEngineStarted() throws IOException {
        if (engineManager == null || !engineManager.isRunning()) {
            Path extDir = resolveExtensionDir();
            engineManager = new EngineManager(extDir);
            engineManager.start();
        }
    }

    /**
     * Resolve the extension's root directory.  Uses the same strategy as
     * {@link D810GPlugin}: Application module data first, then JAR location
     * fallback.
     */
    private Path resolveExtensionDir() {
        try {
            ResourceFile moduleDir = Application.getModuleDataSubDirectory("");
            java.io.File extRoot = moduleDir.getParentFile().getFile(false);
            if (extRoot != null && extRoot.isDirectory()) {
                return extRoot.toPath();
            }
        } catch (Exception e) {
            // fall through to JAR-based resolution
        }

        try {
            Path jarPath = Paths.get(
                getClass().getProtectionDomain().getCodeSource().getLocation().toURI());
            return jarPath.getParent().getParent();
        } catch (Exception e) {
            return Paths.get(".");
        }
    }
}
