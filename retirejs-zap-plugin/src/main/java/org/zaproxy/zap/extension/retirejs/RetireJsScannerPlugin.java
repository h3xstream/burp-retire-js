package org.zaproxy.zap.extension.retirejs;

import com.esotericsoftware.minlog.Log;
import com.h3xstream.retirejs.repo.JsLibraryResult;
import com.h3xstream.retirejs.repo.ScannerFacade;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

import java.io.IOException;
import java.util.List;

public class RetireJsScannerPlugin extends PluginPassiveScanner {

    private PassiveScanThread parent = null;

    private static final int PLUGIN_ID = 0x1337BEEF;

    private Logger logger = Logger.getLogger(RetireJsScannerPlugin.class);

    public RetireJsScannerPlugin() {
        Log.setLogger(new Log.Logger() {
            @Override
            public void log(int level, String category, String message, Throwable ex) {
                if(ex != null) {
                    logger.error(message,ex);
                }
                else {
                    logger.info(message);
                }
            }
        });
        Log.DEBUG();
    }


    @Override
    public void scanHttpRequestSend(HttpMessage httpMessage, int id) {

    }

    @Override
    public void scanHttpResponseReceive(HttpMessage httpMessage, int refId, Source source) {
        HttpResponseHeader h =  httpMessage.getResponseHeader();
        URI uri = httpMessage.getRequestHeader().getURI();

        try {
            String pathQuery = uri.getPathQuery();

            if(h.isJavaScript() || pathQuery.endsWith(".js")) {
                    scanJavaScriptFile(pathQuery, refId, httpMessage);
            }
            if(h.isHtml() || pathQuery.endsWith(".htm") //Some additional condition just in case the content-type is bogus
                    || pathQuery.endsWith(".html")
                    || pathQuery.endsWith(".aspx")
                    || pathQuery.endsWith(".asp")
                    || pathQuery.endsWith(".php")
                    || pathQuery.endsWith(".jsp")) {
                scanHtmlFile(pathQuery, refId, httpMessage);
            }
        } catch (URIException e) {
            logger.error("Unable to scan the script '"+uri.toString()+"': "+e.getMessage(),e);
        } catch (IOException e) {
            logger.error("Unable to scan the script '"+uri.toString()+"': "+e.getMessage(),e);
        }
    }

    private void scanJavaScriptFile(String scriptName,int refId,HttpMessage httpMessage) throws IOException {
        List<JsLibraryResult> librariesVuln = ScannerFacade.getInstance().scanScript(scriptName, httpMessage.getResponseBody().getBytes(), 0);
        for(JsLibraryResult libVuln : librariesVuln) {
            Alert newAlert = ZapIssueCreator.convertBugToAlert(PLUGIN_ID, libVuln, httpMessage);
            this.parent.raiseAlert(refId, newAlert);
        }
    }
    private void scanHtmlFile(String scriptName,int refId,HttpMessage httpMessage) throws IOException {
        List<JsLibraryResult> librariesVuln = ScannerFacade.getInstance().scanHtml(httpMessage.getResponseBody().getBytes(), 0);
        for(JsLibraryResult libVuln : librariesVuln) {
            Alert newAlert = ZapIssueCreator.convertBugToAlert(PLUGIN_ID, libVuln, httpMessage);
            this.parent.raiseAlert(refId, newAlert);
        }
    }

    @Override
    public void setParent(PassiveScanThread thread) {
        this.parent = thread;
    }

    @Override
    public String getName() {
        return "Retire.js";
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }
}
