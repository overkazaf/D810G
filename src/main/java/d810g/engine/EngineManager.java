package d810g.engine;

import java.io.*;
import java.nio.file.*;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import ghidra.util.Msg;

/**
 * Manages the Python d810g_engine subprocess lifecycle.
 *
 * <p>Starts the engine as {@code python -m d810g_engine}, communicating
 * over stdin/stdout with Content-Length-framed JSON-RPC. The process's
 * stderr is forwarded to Ghidra's log console.
 */
public class EngineManager implements AutoCloseable {

    private Process process;
    private EngineProtocol protocol;
    private final Path extensionDir;

    public EngineManager(Path extensionDir) {
        this.extensionDir = extensionDir;
    }

    /**
     * Start the Python engine subprocess.
     *
     * <p>Looks for a virtualenv at {@code .venv/bin/python} under the
     * extension directory first; falls back to {@code python3} on PATH.
     */
    public void start() throws IOException {
        if (process != null && process.isAlive()) {
            Msg.warn(this, "D810G engine already running (PID " + process.pid() + ")");
            return;
        }

        Path pythonDir = extensionDir.resolve("python");
        String python = findPython();

        ProcessBuilder pb = new ProcessBuilder(python, "-m", "d810g_engine");
        pb.directory(extensionDir.toFile());
        pb.environment().put("PYTHONPATH", pythonDir.toString());
        pb.redirectErrorStream(false);

        process = pb.start();
        protocol = new EngineProtocol(process.getInputStream(), process.getOutputStream());

        // Forward stderr to Ghidra console on a daemon thread
        startStderrReader(process.getErrorStream());

        Msg.info(this, "D810G engine started (PID " + process.pid() + ")");
    }

    public EngineProtocol getProtocol() {
        return protocol;
    }

    public boolean isRunning() {
        return process != null && process.isAlive();
    }

    @Override
    public void close() {
        if (process != null && process.isAlive()) {
            try {
                protocol.send("shutdown", Map.of());
            } catch (IOException ignored) {
                // Best-effort shutdown signal
            }
            process.destroy();
            try {
                if (!process.waitFor(3, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                }
            } catch (InterruptedException e) {
                process.destroyForcibly();
                Thread.currentThread().interrupt();
            }
            Msg.info(this, "D810G engine stopped");
        }
        process = null;
        protocol = null;
    }

    private String findPython() {
        // 1. Check for venv under extension directory
        Path venvPython = extensionDir.resolve(".venv/bin/python");
        if (Files.isExecutable(venvPython)) {
            Msg.info(this, "Using venv Python: " + venvPython);
            return venvPython.toString();
        }

        // 2. Try python3 on PATH
        String[] candidates = {"python3", "python"};
        for (String candidate : candidates) {
            try {
                Process p = new ProcessBuilder(candidate, "--version")
                    .redirectErrorStream(true)
                    .start();
                if (p.waitFor(5, TimeUnit.SECONDS) && p.exitValue() == 0) {
                    return candidate;
                }
            } catch (Exception e) {
                // try next candidate
            }
        }
        return "python3";
    }

    private void startStderrReader(InputStream stderr) {
        Thread thread = new Thread(() -> {
            try (BufferedReader br = new BufferedReader(new InputStreamReader(stderr))) {
                String line;
                while ((line = br.readLine()) != null) {
                    Msg.info(this, "[d810g-engine] " + line);
                }
            } catch (IOException e) {
                if (process != null && process.isAlive()) {
                    Msg.warn(this, "D810G stderr reader stopped: " + e.getMessage());
                }
            }
        }, "D810G-StderrReader");
        thread.setDaemon(true);
        thread.start();
    }
}
