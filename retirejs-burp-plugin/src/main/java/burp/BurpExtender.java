package burp;

import com.h3xstream.retirejs.repo.JsLibraryResult;
import com.h3xstream.retirejs.repo.VulnerabilitiesRepository;
import com.h3xstream.retirejs.util.HashUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IScannerCheck {

    private static boolean DEBUG = true;

    public IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.callbacks.setExtensionName("RetireJS");
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
            if (contentType.indexOf("javascript") != -1 || path.endsWith(".js")) {
                int bodyOffset = responseInfo.getBodyOffset();


                issues = scanJavaScript(respBytes, bodyOffset, path, requestResponse, requestInfo);

                if(DEBUG) {
                    System.out.println("Body : " + new String(respBytes, bodyOffset, respBytes.length - bodyOffset));
                }

            }
            /*
            //Do we need to scan HTML for inline JavaScript ?
            else if (contentType.indexOf("html") != -1 || path.endsWith(".html")) {
            }
             */
        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
            e.printStackTrace();
        }
        return issues;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return new ArrayList<IScanIssue>();
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    private List<IScanIssue> scanJavaScript(byte[] respBytes, int offset, String scriptName, IHttpRequestResponse resp,IRequestInfo requestInfo) throws IOException {

        VulnerabilitiesRepository repo = new VulnerabilitiesRepository();

        //1. Search by URI (path + file name)
        List<JsLibraryResult> res = repo.findByUri(scriptName);

        if(res.size() == 0) { //2. Search by file name
            res = repo.findByFilename(scriptName);

            if(res.size() == 0) { //3. Compare the hash with known hash
                String hash = HashUtil.hashSha1(respBytes,offset);
                res = repo.findByHash(hash);

                if(res.size() == 0) { //4. Look for specific string in the content
                    String contentString = new String(respBytes,offset,respBytes.length-offset);
                    res = repo.findByFileContent(contentString);

                    if(res.size() == 0) { //5. Evaluation the script in a sandbox
                        res = repo.findByFunction(contentString);
                    }
                }
            }
        }

        if(res.size() > 0) { //Transform the list of vulnerability Issue that can be display in Burp Scanner result.
            return VulnerableLibraryIssueBuilder.convert(res, resp.getHttpService(), null, resp);
        }

        return new ArrayList<IScanIssue>(); //Nothing was found
    }
}
