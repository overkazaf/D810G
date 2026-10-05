package d810g.core;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Extracts P-Code basic-block structure and raw bytes from Ghidra functions.
 */
public class PcodeUtils {

    /**
     * Decompile a function and extract its basic-block graph.
     *
     * @return list of blocks, each a map with "addr" (long) and "succs" (List&lt;Long&gt;)
     */
    public static List<Map<String, Object>> extractBlocks(Program program, Function function) {
        DecompInterface decompiler = new DecompInterface();
        List<Map<String, Object>> blocks = new ArrayList<>();

        try {
            decompiler.openProgram(program);
            DecompileResults results = decompiler.decompileFunction(
                function, 30, TaskMonitor.DUMMY);

            if (results.decompileCompleted()) {
                HighFunction hf = results.getHighFunction();
                if (hf != null) {
                    ArrayList<PcodeBlockBasic> basicBlocks = hf.getBasicBlocks();
                    for (PcodeBlockBasic bb : basicBlocks) {
                        Map<String, Object> block = new HashMap<>();
                        block.put("addr", bb.getStart().getOffset());
                        List<Long> succs = new ArrayList<>();
                        for (int i = 0; i < bb.getOutSize(); i++) {
                            succs.add(bb.getOut(i).getStart().getOffset());
                        }
                        block.put("succs", succs);
                        blocks.add(block);
                    }
                }
            }
        } finally {
            decompiler.dispose();
        }
        return blocks;
    }

    /**
     * Read the raw bytes of a function's body from program memory.
     */
    public static byte[] getFunctionBytes(Program program, Function function) throws Exception {
        long start = function.getEntryPoint().getOffset();
        long end = function.getBody().getMaxAddress().getOffset();
        int size = (int) (end - start + 1);
        byte[] bytes = new byte[size];
        program.getMemory().getBytes(function.getEntryPoint(), bytes);
        return bytes;
    }
}
