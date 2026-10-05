package d810g.actions;

import d810g.D810GPlugin;
import d810g.core.DeobfuscationOrchestrator;
import d810g.core.DeobfuscationOrchestrator.DeobResult;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Right-click context menu action: D810G > Deobfuscate Function.
 *
 * <p>Sends the function under the cursor to the Python engine for
 * deobfuscation and applies the returned patches.
 */
public class DeobfuscateFunctionAction extends ListingContextAction {

    private final D810GPlugin plugin;

    public DeobfuscateFunctionAction(D810GPlugin plugin) {
        super("Deobfuscate Function", plugin.getName());
        this.plugin = plugin;

        setPopupMenuData(new MenuData(
            new String[]{"D810G", "Deobfuscate Function"}, null, "D810G"));

        // Register with the tool so it appears in menus
        plugin.getTool().addAction(this);
    }

    @Override
    protected void actionPerformed(ListingActionContext context) {
        Program program = context.getProgram();
        FunctionManager fm = program.getFunctionManager();
        Function function = fm.getFunctionContaining(context.getAddress());

        if (function == null) {
            Msg.showError(this, null, "D810G", "No function at current address");
            return;
        }

        // Start engine if not running
        if (!plugin.getEngineManager().isRunning()) {
            plugin.startEngine();
            if (!plugin.getEngineManager().isRunning()) {
                Msg.showError(this, null, "D810G", "Could not start D810G engine");
                return;
            }
        }

        try {
            DeobfuscationOrchestrator orchestrator = new DeobfuscationOrchestrator(
                plugin.getEngineManager().getProtocol()
            );
            DeobResult result = orchestrator.deobfuscateFunction(program, function);
            plugin.getProvider().appendLog(String.format(
                "Deobfuscated %s: %s (%d patches applied)",
                function.getName(), result.status, result.patchCount
            ));
        } catch (Exception e) {
            plugin.getProvider().appendLog("FAILED: " + function.getName() + " -- " + e.getMessage());
            Msg.showError(this, null, "D810G", "Deobfuscation failed: " + e.getMessage(), e);
        }
    }
}
