package com.h3xstream.retirejs.repo;

public class JsLibraryResult {
    private JsLibrary library;
    private JsVulnerability vuln;

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
}
