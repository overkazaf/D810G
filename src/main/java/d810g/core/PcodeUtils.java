package d810g.core;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Extracts P-Code basic-block structure and raw bytes from Ghidra functions.
 */
public class PcodeUtils {

    /**
     * Decompile a function and extract its basic-block graph with full
     * properties needed by every Python engine pass:
     *
     * <ul>
     *   <li><b>addr</b> (long) — block start offset</li>
     *   <li><b>succs</b> (List&lt;Long&gt;) — successor block addresses</li>
     *   <li><b>size</b> (int) — block size in bytes</li>
     *   <li><b>insn_count</b> (int) — P-Code instruction count</li>
     *   <li><b>has_memory_access</b> (boolean) — contains LOAD/STORE</li>
     *   <li><b>has_arithmetic</b> (boolean) — contains INT_ADD/SUB/MULT/DIV</li>
     *   <li><b>has_indirect_jump</b> (boolean) — contains BRANCHIND</li>
     *   <li><b>condition</b> (String, optional) — conditional branch expression</li>
     *   <li><b>state_update</b> (Long, optional) — constant written via COPY/STORE</li>
     * </ul>
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
                    for (PcodeBlockBasic bb : hf.getBasicBlocks()) {
                        Map<String, Object> block = new HashMap<>();
                        block.put("addr", bb.getStart().getOffset());

                        // Successors
                        List<Long> succs = new ArrayList<>();
                        for (int i = 0; i < bb.getOutSize(); i++) {
                            succs.add(bb.getOut(i).getStart().getOffset());
                        }
                        block.put("succs", succs);

                        // Block size in bytes
                        long startOff = bb.getStart().getOffset();
                        long stopOff = bb.getStop().getOffset();
                        block.put("size", (int) (stopOff - startOff + 1));

                        // Walk P-Code ops to gather per-block properties
                        int insnCount = 0;
                        boolean hasMemoryAccess = false;
                        boolean hasArithmetic = false;
                        boolean hasIndirectJump = false;
                        String condition = null;
                        Long stateUpdate = null;

                        Iterator<PcodeOpAST> allOps = hf.getPcodeOps();
                        while (allOps.hasNext()) {
                            PcodeOpAST op = allOps.next();
                            if (op.getParent() != bb) continue;
                            insnCount++;
                            int opcode = op.getOpcode();

                            // Memory access (LOAD / STORE)
                            if (opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE) {
                                hasMemoryAccess = true;
                            }

                            // Arithmetic ops
                            if (opcode == PcodeOp.INT_ADD || opcode == PcodeOp.INT_SUB ||
                                opcode == PcodeOp.INT_MULT || opcode == PcodeOp.INT_DIV) {
                                hasArithmetic = true;
                            }

                            // Conditional branch — extract the comparison expression
                            if (opcode == PcodeOp.CBRANCH) {
                                Varnode condVar = op.getInput(1);
                                if (condVar != null && condVar.getDef() != null) {
                                    condition = extractConditionString(condVar.getDef());
                                }
                            }

                            // Indirect branch (e.g. Tigress VM dispatch)
                            if (opcode == PcodeOp.BRANCHIND) {
                                hasIndirectJump = true;
                            }

                            // State-variable write: COPY/STORE with a constant operand
                            if ((opcode == PcodeOp.COPY || opcode == PcodeOp.STORE) &&
                                op.getNumInputs() > 0) {
                                Varnode input = op.getInput(op.getNumInputs() - 1);
                                if (input.isConstant()) {
                                    stateUpdate = input.getOffset();
                                }
                            }
                        }

                        block.put("insn_count", insnCount);
                        block.put("has_memory_access", hasMemoryAccess);
                        block.put("has_arithmetic", hasArithmetic);
                        block.put("has_indirect_jump", hasIndirectJump);

                        if (condition != null) {
                            block.put("condition", condition);
                        }
                        if (stateUpdate != null) {
                            block.put("state_update", stateUpdate);
                        }

                        blocks.add(block);
                    }
                }
            }
        } finally {
            decompiler.dispose();
        }
        return blocks;
    }

    // ------------------------------------------------------------------
    //  Helpers for extracting human-readable condition strings from P-Code
    // ------------------------------------------------------------------

    /**
     * Convert a P-Code comparison op (the def of a CBRANCH condition varnode)
     * into a readable string like {@code "var_4 == 0x3"}.
     */
    private static String extractConditionString(PcodeOp compOp) {
        if (compOp == null) return null;

        int opcode = compOp.getOpcode();
        String opStr;
        switch (opcode) {
            case PcodeOp.INT_EQUAL:      opStr = "=="; break;
            case PcodeOp.INT_NOTEQUAL:   opStr = "!="; break;
            case PcodeOp.INT_LESS:       opStr = "<";  break;
            case PcodeOp.INT_LESSEQUAL:  opStr = "<="; break;
            case PcodeOp.INT_SLESS:      opStr = "<";  break;
            case PcodeOp.INT_SLESSEQUAL: opStr = "<="; break;
            default: return null;
        }

        if (compOp.getNumInputs() < 2) return null;

        String left  = varnodeToString(compOp.getInput(0));
        String right = varnodeToString(compOp.getInput(1));

        return left + " " + opStr + " " + right;
    }

    /**
     * Best-effort conversion of a Varnode to a human-readable token.
     * Constants become hex literals; registers use the HighVariable name
     * when available; one level of INT_AND / OR / XOR / MULT is expanded.
     */
    private static String varnodeToString(Varnode vn) {
        if (vn == null) return "?";
        if (vn.isConstant()) return "0x" + Long.toHexString(vn.getOffset());
        if (vn.isRegister()) {
            return vn.getHigh() != null ? vn.getHigh().getName() : "reg";
        }
        if (vn.getDef() != null) {
            PcodeOp def = vn.getDef();
            int op = def.getOpcode();
            if (op == PcodeOp.INT_AND && def.getNumInputs() >= 2) {
                return "(" + varnodeToString(def.getInput(0)) + " & " +
                       varnodeToString(def.getInput(1)) + ")";
            }
            if (op == PcodeOp.INT_OR && def.getNumInputs() >= 2) {
                return "(" + varnodeToString(def.getInput(0)) + " | " +
                       varnodeToString(def.getInput(1)) + ")";
            }
            if (op == PcodeOp.INT_XOR && def.getNumInputs() >= 2) {
                return "(" + varnodeToString(def.getInput(0)) + " ^ " +
                       varnodeToString(def.getInput(1)) + ")";
            }
            if (op == PcodeOp.INT_MULT && def.getNumInputs() >= 2) {
                return "(" + varnodeToString(def.getInput(0)) + " * " +
                       varnodeToString(def.getInput(1)) + ")";
            }
        }
        return "var_" + Long.toHexString(vn.getOffset());
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
