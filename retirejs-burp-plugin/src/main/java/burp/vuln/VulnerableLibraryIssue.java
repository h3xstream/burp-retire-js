package burp.vuln;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;

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
    private String info;

    public VulnerableLibraryIssue(IHttpService httpService, URL url, IHttpRequestResponse httpMessage, String name, //
                                  String detail, String severity,String confidence, String libName, String info) {
        this.url = url;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
        this.httpService = httpService;
        this.httpMessage = httpMessage;
        this.confidence = confidence;

        this.libName = libName;
        this.info = info;
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

    public boolean equals(Object obj) {
        if(obj instanceof VulnerableLibraryIssue) {
            VulnerableLibraryIssue issue = (VulnerableLibraryIssue)obj;
            return issue.libName == this.libName && issue.info == this.info;
        }
        return false;
    }
}
