package burp;

import com.esotericsoftware.minlog.Log;
import com.h3xstream.retirejs.repo.JsLibraryResult;
import com.h3xstream.retirejs.repo.ScannerFacade;
import com.h3xstream.retirejs.ui.HtmlReportPanel;
import com.h3xstream.retirejs.ui.TextReportPanel;

import java.awt.*;
import java.io.IOException;
import java.util.List;

public class VulnerabilitiesDetailTab implements  IMessageEditorTab {

    private byte[] message;
    private HtmlReportPanel infoPanel;

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private IMessageEditorController controller;

    public VulnerabilitiesDetailTab(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, IMessageEditorController controller) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.controller = controller;

        infoPanel = new HtmlReportPanel();

        callbacks.customizeUiComponent(infoPanel.getComponent());
    }


    @Override
    public String getTabCaption() {
        return "Vulnerabilities";
    }

    @Override
    public Component getUiComponent() {
        return infoPanel.getComponent();
    }

    @Override
    public boolean isEnabled(byte[] respBytes, boolean isRequest) {
        if(isRequest) return false; //Appears on response only

        IRequestInfo requestInfo = helpers.analyzeRequest(controller.getRequest());
        String path = HttpUtil.getPathRequested(requestInfo);
        return path.endsWith(".js");
    }

    @Override
    public void setMessage(byte[] respBytes, boolean isRequest) {
        if(isRequest) return; //Only look at the response

        this.message = respBytes;


        infoPanel.clearDisplay();

        try {
            //Extract the info required
            IRequestInfo requestInfo = helpers.analyzeRequest(controller.getRequest());
            String scriptName = HttpUtil.getPathRequested(requestInfo); //Actually the full path

            //Scan !
            List<JsLibraryResult> res = ScannerFacade.getInstance().scanScript(scriptName, respBytes, requestInfo.getBodyOffset());

            StringBuilder html = new StringBuilder();
            //Display the results
            for(JsLibraryResult lib : res) {
                html.append("<hr/>");
                html.append("Lib:<b>"+lib.getLibrary().getName()+"</b><br/>");
                html.append("Vulnerability:<b>"+lib.getVuln().getInfo().get(0)+"</b><br/>");
            }

            infoPanel.updateHtmlContent(html.toString());

        }
        catch (IOException io) {
            Log.error("Error occurs while scanning the request/response.", io);
        }


    }

    @Override
    public byte[] getMessage() {
        return message;
    }

    @Override
    public boolean isModified() {
        return false;
    }

    @Override
    public byte[] getSelectedData() {
        return new byte[0];
    }

}

