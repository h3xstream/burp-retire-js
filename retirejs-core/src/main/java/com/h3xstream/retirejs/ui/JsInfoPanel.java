package com.h3xstream.retirejs.ui;

import javax.swing.*;
import java.awt.*;

public class JsInfoPanel {
    private JPanel panel;
    private JTextArea textArea;

    public JsInfoPanel() {
        buildReportStructure();
    }

    public void buildReportStructure() {
        panel = new JPanel();
        panel.setLayout(new BorderLayout());
        textArea = new JTextArea();
        panel.add(textArea, BorderLayout.CENTER);
    }

    public JPanel getComponent() {
        return panel;
    }

    public void appendText(String value) {
        textArea.append(value+"\n");
    }

    public void clearDisplay() {
        textArea.setText("");
    }
}
