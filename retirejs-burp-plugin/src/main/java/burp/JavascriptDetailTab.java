package burp;

import com.esotericsoftware.minlog.Log;
import com.h3xstream.retirejs.repo.JsLibraryResult;
import com.h3xstream.retirejs.repo.ScannerFacade;
import com.h3xstream.retirejs.ui.JsInfoPanel;
import com.h3xstream.retirejs.util.BytesUtil;

import java.awt.*;
import java.io.IOException;
import java.util.List;

public class JavascriptDetailTab implements IMessageEditorTab {

    private byte[] message;
    private JsInfoPanel infoPanel;

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;

    JavascriptDetailTab(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.helpers = helpers;
        this.callbacks = callbacks;

        infoPanel = new JsInfoPanel();

        callbacks.customizeUiComponent(infoPanel.getComponent());
    }


    @Override
    public String getTabCaption() {
        return "Library";
    }

    @Override
    public Component getUiComponent() {
        return infoPanel.getComponent();
    }

    @Override
    public boolean isEnabled(byte[] respBytes, boolean isRequest) {
        return true;
        /*
        if (isRequest) {
            return false;
        } else { //The tab will appears if the response is a JPG or PNG image
            IResponseInfo responseInfo = helpers.analyzeResponse(respBytes);

            String contentType = HttpUtil.getContentType(responseInfo);
            //TODO: Add some heuristic to identify javascript based on the response.
            return contentType.indexOf("javascript") != -1 || responseInfo.getInferredMimeType().indexOf("javascript") != -1 || BytesUtil.indexOf(respBytes,"function".getBytes()) != -1;
        }*/
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        this.message = content;

        List<JsLibraryResult> res;

        infoPanel.clearDisplay();

        try {
            if(isRequest) {
                IRequestInfo requestInfo = helpers.analyzeRequest(content);

                String path = HttpUtil.getPathRequested(requestInfo);
                infoPanel.appendText("Analyzing the path '"+path+"'");
                res = ScannerFacade.getInstance().scanScript(path, new byte[] {}, 0);
            }
            else {
                IResponseInfo responseInfo = helpers.analyzeResponse(content);
                res = ScannerFacade.getInstance().scanScript("", content, responseInfo.getBodyOffset());
            }

            infoPanel.appendText("Results:");
            for(JsLibraryResult lib : res) {
                infoPanel.appendText("==========");
                infoPanel.appendText("Lib:"+lib.getLibrary().getName());
                infoPanel.appendText("Vulnerability:"+lib.getVuln().getInfo().get(0));
            }
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
