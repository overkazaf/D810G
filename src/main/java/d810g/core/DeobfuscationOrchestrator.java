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
     * Run all deobfuscation passes on the given function.
     *
     * @return a result summary with status and patch count
     */
    public DeobResult deobfuscateFunction(Program program, Function function) throws Exception {
        // Extract the function's block graph and raw bytes
        List<Map<String, Object>> blocks = PcodeUtils.extractBlocks(program, function);
        byte[] funcBytes = PcodeUtils.getFunctionBytes(program, function);
        String arch = program.getLanguage().getProcessor().toString();

        Msg.info(this, "D810G: Analyzing " + function.getName() +
            " (" + blocks.size() + " blocks, " + funcBytes.length + " bytes, arch=" + arch + ")");

        // Send to the Python engine
        Map<String, Object> deflatParams = new HashMap<>();
        deflatParams.put("blocks", blocks);
        deflatParams.put("binary_hex", bytesToHex(funcBytes));
        deflatParams.put("arch", arch);
        deflatParams.put("base_addr", function.getEntryPoint().getOffset());

        JsonObject deflatResult = protocol.send("deflat.run", deflatParams);

        DeobResult result = new DeobResult();

        if (deflatResult.has("error")) {
            JsonObject err = deflatResult.getAsJsonObject("error");
            result.status = "error: " + err.get("message").getAsString();
            Msg.error(this, "D810G engine error: " + result.status);
            return result;
        }

        if (deflatResult.has("result")) {
            JsonObject r = deflatResult.getAsJsonObject("result");
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
            result.status = r.has("status") ? r.get("status").getAsString() : "ok";
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
