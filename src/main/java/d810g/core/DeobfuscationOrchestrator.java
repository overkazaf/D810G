package d810g.core;

import com.google.gson.*;
import d810g.engine.EngineProtocol;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.*;

/**
 * Coordinates all deobfuscation passes against a single function.
 *
 * <p>Extracts P-Code blocks and raw bytes from Ghidra, sends them to the
 * Python engine for analysis (deflattening, MBA simplification, opaque
 * predicate elimination), and applies the returned patches.
 */
public class DeobfuscationOrchestrator {

    private final EngineProtocol protocol;

    public DeobfuscationOrchestrator(EngineProtocol protocol) {
        this.protocol = protocol;
    }

    /**
     * Run the full deobfuscation pipeline (deflat, MBA, opaque, BCF, DCE,
     * strings) on the given function via the Python engine.
     *
     * @return a result summary with status and patch count
     */
    public DeobResult deobfuscateFunction(Program program, Function function) throws Exception {
        // Extract the function's block graph (with full properties) and raw bytes
        List<Map<String, Object>> blocks = PcodeUtils.extractBlocks(program, function);
        byte[] funcBytes = PcodeUtils.getFunctionBytes(program, function);
        String arch = program.getLanguage().getProcessor().toString();
        long baseAddr = function.getEntryPoint().getOffset();

        Msg.info(this, "D810G: Analyzing " + function.getName() +
            " (" + blocks.size() + " blocks, " + funcBytes.length + " bytes, arch=" + arch + ")");

        // Build params for the full pipeline (all 6 passes)
        Map<String, Object> params = new HashMap<>();
        params.put("blocks", blocks);
        params.put("binary_hex", bytesToHex(funcBytes));
        params.put("arch", arch);
        params.put("entry_addr", baseAddr);

        // Use the full pipeline instead of just deflat.run
        JsonObject pipelineResult = protocol.send("pipeline.run", params);

        DeobResult result = new DeobResult();

        if (pipelineResult.has("error")) {
            JsonObject err = pipelineResult.getAsJsonObject("error");
            result.status = "error: " + err.get("message").getAsString();
            Msg.error(this, "D810G engine error: " + result.status);
            return result;
        }

        if (pipelineResult.has("result")) {
            JsonObject r = pipelineResult.getAsJsonObject("result");
            result.status = r.has("status") ? r.get("status").getAsString() : "ok";
            result.patchCount = r.has("total_patches") ? r.get("total_patches").getAsInt() : 0;

            // Log per-pass results
            JsonArray passes = r.getAsJsonArray("passes");
            if (passes != null) {
                for (JsonElement passEl : passes) {
                    JsonObject pass = passEl.getAsJsonObject();
                    String passName = pass.has("name") ? pass.get("name").getAsString() : "unknown";
                    int passPatches = pass.has("patches") ? pass.get("patches").getAsInt() : 0;
                    if (passPatches > 0) {
                        Msg.info(this, String.format("D810G [%s]: %d patches", passName, passPatches));
                    }
                }
            }

            // Apply accumulated byte-level patches from the pipeline
            JsonArray patches = r.getAsJsonArray("patches");
            if (patches != null && patches.size() > 0) {
                List<Map<String, Object>> patchList = new ArrayList<>();
                for (JsonElement p : patches) {
                    JsonObject po = p.getAsJsonObject();
                    Map<String, Object> patch = new HashMap<>();
                    patch.put("address", po.get("address").getAsLong());
                    patch.put("bytes", po.get("bytes").getAsString());
                    patchList.add(patch);
                }
                result.patchCount = PatchManager.applyPatches(program, patchList);
            }
        }
        return result;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    /**
     * Result summary from a deobfuscation run.
     */
    public static class DeobResult {
        public String status = "ok";
        public int patchCount = 0;
    }
}
