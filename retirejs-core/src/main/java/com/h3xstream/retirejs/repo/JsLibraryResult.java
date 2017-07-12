package com.h3xstream.retirejs.repo;

public class JsLibraryResult {
    private JsLibrary library;
    private JsVulnerability vuln;

    private String detectedVersion;
    private String regexRequest;
    private String regexResponse;

    public JsLibraryResult(JsLibrary library, JsVulnerability vuln, String detectedVersion, String regexRequest, String regexResponse) {
        this.library = library;
        this.vuln = vuln;
        this.detectedVersion = detectedVersion;
        this.regexRequest = regexRequest;
        this.regexResponse = regexResponse;
    }

    public JsLibrary getLibrary() {
        return library;
    }

    public void setLibrary(JsLibrary library) {
        this.library = library;
    }

    public JsVulnerability getVuln() {
        return vuln;
    }

    public void setVuln(JsVulnerability vuln) {
        this.vuln = vuln;
    }

    public String getDetectedVersion() {
        return detectedVersion;
    }

    public void setDetectedVersion(String detectedVersion) {
        this.detectedVersion = detectedVersion;
    }

    public String getRegexRequest() {
        return regexRequest;
    }

    public void setRegexRequest(String regexRequest) {
        this.regexRequest = regexRequest;
    }

    public String getRegexResponse() {
        return regexResponse;
    }

    public void setRegexResponse(String regexResponse) {
        this.regexResponse = regexResponse;
    }
}
