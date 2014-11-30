package burp;

import burp.vuln.VulnerableLibraryIssue;
import burp.vuln.VulnerableLibraryIssueBuilder;
import com.esotericsoftware.minlog.Log;
import com.h3xstream.retirejs.repo.JsLibraryResult;
import com.h3xstream.retirejs.repo.ScannerFacade;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IScannerCheck {


    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;


    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.callbacks.setExtensionName("Retire.js");

        Log.setLogger(new Log.Logger(){
            @Override
            protected void print (String message) {
                try {
                    if(message.contains("ERROR:")) { //Not the most elegant way, but should be effective.
                        callbacks.issueAlert(message);
                    }
                    callbacks.getStdout().write(message.getBytes());
                    callbacks.getStdout().write('\n');
                } catch (IOException e) {
                    System.err.println("Error while printing the log : "+e.getMessage()); //Very unlikely
                }
            }
        });
        Log.DEBUG();

        callbacks.registerScannerCheck(this);

        //Not fully implemented (the passive scan rule is sufficient)
        //callbacks.registerMessageEditorTabFactory(this);
    }


    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse requestResponse) {
        List<IScanIssue> issues = new ArrayList<IScanIssue>();

        byte[] respBytes = requestResponse.getResponse();

        IResponseInfo responseInfo = helpers.analyzeResponse(respBytes);
        IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse.getHttpService(), requestResponse.getRequest());

        String path = HttpUtil.getPathRequested(requestInfo);
        String contentType = HttpUtil.getContentType(responseInfo);

        try {
            //Avoid NPE
            boolean jsContentType = contentType != null ? contentType.indexOf("javascript") != -1 : false;

            if (jsContentType || path.endsWith(".js")) {
                int bodyOffset = responseInfo.getBodyOffset();

                //The big analysis is spawn here..
                Log.debug("Analyzing "+path+" (body="+(respBytes.length-bodyOffset)+" bytes)");
                issues = scanJavaScript(respBytes, bodyOffset, path, requestResponse, requestInfo);
            }


            /*
            //Do we need to scan HTML for inline JavaScript ?
            else if (contentType.indexOf("html") != -1 || path.endsWith(".html")) {
            }
             */
        } catch (Exception e) {
            Log.error("Exception while scanning the script '"+path+"' (" + e.getClass().getName() + ": "+ e.getMessage()+")");
        }
        return issues;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return new ArrayList<IScanIssue>();
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        boolean bothRetireJsIssue = existingIssue instanceof VulnerableLibraryIssue && newIssue instanceof VulnerableLibraryIssue;

        if(bothRetireJsIssue) {
            VulnerableLibraryIssue issue1 = (VulnerableLibraryIssue) existingIssue;
            VulnerableLibraryIssue issue2 = (VulnerableLibraryIssue) newIssue;
            return issue1.equals(issue2) ? -1: 0;
        }

        return -1; //Unknown
    }

    private List<IScanIssue> scanJavaScript(byte[] respBytes, int offset, String scriptName, IHttpRequestResponse resp, IRequestInfo requestInfo) throws IOException {

        List<JsLibraryResult> res = ScannerFacade.getInstance().scanScript(scriptName, respBytes, offset);

        Log.debug(String.format("%d vulnerability(ies) for the script '%s'.",res.size(),scriptName));

        if(res.size() > 0) { //Transform the list of vulnerability Issue that can be display in Burp Scanner result.
            return VulnerableLibraryIssueBuilder.convert(res, resp.getHttpService(), resp, requestInfo);
        }

        return new ArrayList<IScanIssue>(); //Nothing was found
    }

}
