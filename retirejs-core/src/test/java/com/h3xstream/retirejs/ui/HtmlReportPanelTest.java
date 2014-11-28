package com.h3xstream.retirejs.ui;

import javax.swing.*;
import java.awt.*;

public class HtmlReportPanelTest {

    public static void main(String[] args) {
        //panelEmpty();
        panelWithContent();
    }

    private static void panelEmpty() {
        HtmlReportPanel panel = new HtmlReportPanel();
        display(panel.getComponent());
    }

    private static void panelWithContent() {
        HtmlReportPanel panel = new HtmlReportPanel();
        panel.updateHtmlContent("<b>Hello World!</b>");
        display(panel.getComponent());
    }

    private static void display(Component comp) {

        JFrame window = new JFrame();

        window.add(comp);

        window.setTitle("Mock Window (Test)");
        window.pack();
        window.setSize(600, 400);
        window.setVisible(true);
    }
}
