package com.h3xstream.retirejs.repo;

import java.util.ArrayList;
import java.util.List;

public class Repository {

    protected List<JsLibrary> jsLibrares = new ArrayList<JsLibrary>();

    public void addLibrary(JsLibrary lib) {
        jsLibrares.add(lib);
    }



    /**
     * This search mode will identify the vulnerable library base on the full uri.
     * @param uri
     * @return
     */
    public List<JsLibraryResult> findByUri(String uri) {
        return new ArrayList<JsLibraryResult>();
    }

    /**
     * This search mode will identify the library by there filename. (official distribution filename)
     * @param filename
     * @return
     */
    public List<JsLibraryResult> findByFilename(String filename) {
        return new ArrayList<JsLibraryResult>();
    }

    /**
     * This search mode will look for literal string specific to the vulnerable libraries.
     * @param scriptContent
     * @return
     */
    public List<JsLibraryResult> findByFileContent(String scriptContent) {
        return new ArrayList<JsLibraryResult>();
    }

    /**
     * This search mode will load the script in a sandbox and look for the presence of specific function.
     * @param scriptContent
     * @return
     */
    public List<JsLibraryResult> findByFunction(String scriptContent) {
        return new ArrayList<JsLibraryResult>();
    }

    public List<JsLibraryResult> findByHash(String hash) {
        return new ArrayList<JsLibraryResult>();
    }
}
