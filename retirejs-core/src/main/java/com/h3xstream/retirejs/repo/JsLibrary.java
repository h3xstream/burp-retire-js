package com.h3xstream.retirejs.repo;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class JsLibrary {

    private String name;
    private final List<JsVulnerability> vulnerabilities;
    private List<String> uris;
    private List<String> filename;
    private Map<String,String> hashes;
    private List<String> fileContents;
    private List<String> functions;

    public JsLibrary() {
        vulnerabilities = new ArrayList<JsVulnerability>();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<JsVulnerability> getVulnerabilities() {
        return vulnerabilities;
    }


    public List<String> getUris() {
        return uris;
    }

    public void setUris(List<String> uris) {
        this.uris = uris;
    }

    public List<String> getFilename() {
        return filename;
    }

    public void setFilename(List<String> filename) {
        this.filename = filename;
    }

    public Map<String,String> getHashes() {
        return hashes;
    }

    public void setHashes(Map<String,String> hashes) {
        this.hashes = hashes;
    }

    public List<String> getFileContents() {
        return fileContents;
    }

    public void setFileContents(List<String> fileContents) {
        this.fileContents = fileContents;
    }

    public List<String> getFunctions() {
        return functions;
    }

    public void setFunctions(List<String> functions) {
        this.functions = functions;
    }
}
