package d810g.engine;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.gson.*;

/**
 * JSON-RPC client using Content-Length framing over stdin/stdout.
 *
 * <p>Wire format (matching the Python server):
 * <pre>
 * Content-Length: &lt;n&gt;\r\n
 * \r\n
 * &lt;n bytes of JSON&gt;
 * </pre>
 */
public class EngineProtocol {

    private final InputStream input;
    private final OutputStream output;
    private final AtomicInteger nextId = new AtomicInteger(1);
    private final Gson gson = new Gson();

    public EngineProtocol(InputStream input, OutputStream output) {
        this.input = input;
        this.output = output;
    }

    /**
     * Send a JSON-RPC request and block until the response arrives.
     *
     * @param method RPC method name (e.g. "deflat.run", "shutdown")
     * @param params method parameters
     * @return the parsed JSON response object
     */
    public synchronized JsonObject send(String method, Map<String, Object> params)
            throws IOException {
        int id = nextId.getAndIncrement();
        JsonObject req = new JsonObject();
        req.addProperty("id", id);
        req.addProperty("method", method);
        req.add("params", gson.toJsonTree(params));

        byte[] body = gson.toJson(req).getBytes(StandardCharsets.UTF_8);
        String header = "Content-Length: " + body.length + "\r\n\r\n";
        output.write(header.getBytes(StandardCharsets.US_ASCII));
        output.write(body);
        output.flush();
        return readResponse();
    }

    private JsonObject readResponse() throws IOException {
        // Read header lines until we hit the blank line (\r\n\r\n)
        StringBuilder headerBuilder = new StringBuilder();
        int c;
        while ((c = input.read()) != -1) {
            headerBuilder.append((char) c);
            String built = headerBuilder.toString();
            if (built.endsWith("\r\n\r\n") || built.endsWith("\n\n")) {
                break;
            }
        }
        if (c == -1) {
            throw new IOException("Engine connection closed while reading header");
        }

        String header = headerBuilder.toString();
        // Extract content length -- header is "Content-Length: <n>\r\n\r\n"
        int colonIdx = header.indexOf(':');
        if (colonIdx < 0) {
            throw new IOException("Malformed header from engine: " + header);
        }
        String lengthStr = header.substring(colonIdx + 1).trim().split("\\r?\\n")[0];
        int length = Integer.parseInt(lengthStr);

        byte[] body = input.readNBytes(length);
        if (body.length < length) {
            throw new IOException(
                "Engine sent incomplete body: expected " + length + " bytes, got " + body.length);
        }
        return JsonParser.parseString(new String(body, StandardCharsets.UTF_8)).getAsJsonObject();
    }
}
