package com.h3xstream.retirejs.repo;

public class JsLibraryResult {
    private JsLibrary library;
    private JsVulnerability vuln;

    private String detectedVersion;

    public JsLibraryResult(JsLibrary library, JsVulnerability vuln, String detectedVersion) {
        this.library = library;
        this.vuln = vuln;
        this.detectedVersion = detectedVersion;
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
}
