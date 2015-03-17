package burp.vuln;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;
import com.esotericsoftware.minlog.Log;

import java.net.URL;

public class VulnerableLibraryIssue implements IScanIssue {

    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse httpMessage;
    private String name;
    private String detail;
    private String severity;
    private String confidence;

    private String libName;
    private String path;

    public VulnerableLibraryIssue(IHttpService httpService, URL url, IHttpRequestResponse httpMessage, String name, //
                                  String detail, String severity,String confidence, String libName, String path) {
        this.url = url;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
        this.httpService = httpService;
        this.httpMessage = httpMessage;
        this.confidence = confidence;

        this.libName = libName;
        this.path = path;
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return new IHttpRequestResponse[] {httpMessage};
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    @Override
    public boolean equals(Object obj) {
        if(obj instanceof VulnerableLibraryIssue) {
            VulnerableLibraryIssue issue = (VulnerableLibraryIssue)obj;
            //Log.debug("libName: "+issue.libName + " == " + this.libName+" ? " + issue.libName.equals(this.libName));
            //Log.debug("path   : "+issue.path + " == " + this.path+" ? " + issue.path.equals(this.path));
            return issue.libName.equals(this.libName) && issue.path.equals(this.path);
        }
        return false;
    }
}
