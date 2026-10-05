package d810g.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.Msg;

import java.util.List;
import java.util.Map;

/**
 * Applies binary patches to the Ghidra program's memory.
 *
 * <p>Each patch is a map with:
 * <ul>
 *   <li>{@code "address"} -- absolute virtual address (long)</li>
 *   <li>{@code "bytes"}   -- hex-encoded replacement bytes</li>
 * </ul>
 */
public class PatchManager {

    /**
     * Apply a list of patches inside a single Ghidra transaction.
     *
     * @return the number of patches applied
     */
    public static int applyPatches(Program program, List<Map<String, Object>> patches)
            throws Exception {
        Memory memory = program.getMemory();
        int applied = 0;
        int txId = program.startTransaction("D810G: Apply deobfuscation patches");
        try {
            for (Map<String, Object> patch : patches) {
                long addr = ((Number) patch.get("address")).longValue();
                String hexBytes = (String) patch.get("bytes");
                byte[] bytes = hexStringToBytes(hexBytes);
                Address address = program.getAddressFactory()
                    .getDefaultAddressSpace()
                    .getAddress(addr);
                memory.setBytes(address, bytes);
                applied++;
            }
            program.endTransaction(txId, true);
        } catch (Exception e) {
            program.endTransaction(txId, false);
            throw e;
        }
        Msg.info(PatchManager.class, "D810G: Applied " + applied + " patches");
        return applied;
    }

    static byte[] hexStringToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                  + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
