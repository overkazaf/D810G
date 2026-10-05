package d810g;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;

import generic.jar.ResourceFile;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.Application;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import d810g.actions.DeobfuscateFunctionAction;
import d810g.engine.EngineManager;
import d810g.ui.D810GProvider;

//@formatter:off
@PluginInfo(
    status = PluginStatus.UNSTABLE,
    packageName = "D810G",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Deobfuscation Framework",
    description = "Control flow deflattening, MBA simplification, and opaque " +
        "predicate elimination for Ghidra.  Powered by a Python analysis engine " +
        "communicating over JSON-RPC."
)
//@formatter:on
public class D810GPlugin extends Plugin {

    private EngineManager engineManager;
    private D810GProvider provider;

    public D810GPlugin(PluginTool tool) {
        super(tool);

        Path extDir = getExtensionDir();
        engineManager = new EngineManager(extDir);
        provider = new D810GProvider(this);

        // Register context-menu actions
        new DeobfuscateFunctionAction(this);
    }

    /**
     * Resolve the extension's root directory so we can find the bundled
     * Python engine (in {@code python/d810g_engine/}).
     */
    private Path getExtensionDir() {
        try {
            // When installed as a Ghidra extension, Application knows our
            // module data directory.  Go up from data/ to the extension root.
            ResourceFile moduleDir = Application.getModuleDataSubDirectory("");
            File extRoot = moduleDir.getParentFile().getFile(false);
            if (extRoot != null && extRoot.isDirectory()) {
                return extRoot.toPath();
            }
        } catch (Exception e) {
            Msg.warn(this, "Could not resolve extension dir via Application: " + e.getMessage());
        }

        // Fallback: derive from the JAR location
        try {
            Path jarPath = Path.of(
                getClass().getProtectionDomain().getCodeSource().getLocation().toURI());
            // jar is at lib/<name>.jar, so parent.parent is the extension root
            return jarPath.getParent().getParent();
        } catch (Exception e) {
            Msg.error(this, "Failed to resolve extension directory", e);
            return Path.of(".");
        }
    }

    public EngineManager getEngineManager() {
        return engineManager;
    }

    public D810GProvider getProvider() {
        return provider;
    }

    /**
     * Start the Python engine subprocess.  Called lazily on first use.
     */
    public void startEngine() {
        try {
            engineManager.start();
            provider.appendLog("D810G engine started successfully");
        } catch (IOException e) {
            Msg.showError(this, null, "D810G", "Failed to start engine: " + e.getMessage(), e);
        }
    }

    @Override
    protected void dispose() {
        engineManager.close();
        super.dispose();
    }
}
