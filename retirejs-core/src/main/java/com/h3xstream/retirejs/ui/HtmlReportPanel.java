package com.h3xstream.retirejs.ui;

import com.esotericsoftware.minlog.Log;

import javax.swing.JEditorPane;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.Element;
import javax.swing.text.html.HTML;
import javax.swing.text.html.HTMLDocument;
import javax.swing.text.html.HTMLEditorKit;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

public class HtmlReportPanel {

    JTextPane textPanel;
    HTMLEditorKit kit;
    HTMLDocument doc;

    public HtmlReportPanel() {
        buildPanel();
    }

    public void buildPanel() {
        JTextPane textPanel = new JTextPane();

        kit = new HTMLEditorKit();
        doc = new HTMLDocument();
        textPanel.setEditorKit(kit);
        textPanel.setDocument(doc);

        JPanel container = new JPanel();
        container.add(textPanel);
    }


    public Component getComponent() {
        return textPanel;
    }

    public void clearHtml() {
        //TODO: Find a better way
        kit = new HTMLEditorKit();
        doc = new HTMLDocument();
        textPanel.setEditorKit(kit);
        textPanel.setDocument(doc);
    }

    public void updateHtmlContent(String html) {
        try {
            kit.insertHTML(doc, doc.getLength(), html, 0, 0, HTML.Tag.HTML);

        } catch (IOException e) {
            Log.error(e.getMessage(),e);
        } catch (BadLocationException e) {
            Log.error(e.getMessage(), e);
        }
    }



    public static void main(String[] args) {

    }
}

