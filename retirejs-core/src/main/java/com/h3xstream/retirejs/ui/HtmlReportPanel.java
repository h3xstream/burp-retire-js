package com.h3xstream.retirejs.ui;

import javax.swing.JEditorPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import java.awt.*;

public class HtmlReportPanel {

    private JPanel container;
    private JEditorPane editorPane = new JEditorPane();

    public HtmlReportPanel() {
        buildPanel();
    }

    public void buildPanel() {

        editorPane.setEditable(false);
        editorPane.setContentType("text/html");

        JPanel container = new JPanel();
        container.setLayout(new BorderLayout());
        container.add(new JScrollPane(editorPane));
        this.container=container;
    }


    public Component getComponent() {
        return container;
    }

    public void clearDisplay() {
        editorPane.setText("<html></html>");
    }

    public void updateHtmlContent(String html) {
        editorPane.setText(html);
    }

}

