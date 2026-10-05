package d810g.ui;

import d810g.D810GPlugin;
import docking.ComponentProvider;

import javax.swing.*;
import java.awt.*;

/**
 * Dockable results/log panel for D810G.
 *
 * <p>Shows a scrollable text area with deobfuscation results and
 * engine messages.
 */
public class D810GProvider extends ComponentProvider {

    private JTextArea logArea;
    private JPanel panel;

    public D810GProvider(D810GPlugin plugin) {
        super(plugin.getTool(), "D810G Results", plugin.getName());
        buildPanel();
        setVisible(true);
    }

    private void buildPanel() {
        panel = new JPanel(new BorderLayout());

        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        panel.add(new JScrollPane(logArea), BorderLayout.CENTER);

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> logArea.setText(""));
        toolbar.add(clearBtn);
        panel.add(toolbar, BorderLayout.NORTH);
    }

    /**
     * Append a message to the log panel (thread-safe).
     */
    public void appendLog(String message) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }
}
