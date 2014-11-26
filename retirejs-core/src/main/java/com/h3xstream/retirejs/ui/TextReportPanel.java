package com.h3xstream.retirejs.ui;

import javax.swing.*;
import java.awt.*;

public class TextReportPanel {
    private JPanel panel;
    private JTextArea textArea;

    public TextReportPanel() {
        buildReportStructure();
    }

    public void buildReportStructure() {
        panel = new JPanel();
        panel.setLayout(new BorderLayout());
        textArea = new JTextArea();
        panel.add(textArea, BorderLayout.CENTER);
    }

    public Component getComponent() {
        return panel;
    }

    public void appendText(String value) {
        textArea.append(value+"\n");
    }

    public void clearDisplay() {
        textArea.setText("");
    }
}

