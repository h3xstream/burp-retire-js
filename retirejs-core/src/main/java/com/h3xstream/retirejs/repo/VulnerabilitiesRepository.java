package com.h3xstream.retirejs.repo;

import com.esotericsoftware.minlog.Log;
import com.h3xstream.retirejs.util.CompareVersionUtil;
import com.h3xstream.retirejs.util.RegexUtil;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VulnerabilitiesRepository {



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
        Log.debug("Analysing URI: "+uri);
        List<JsLibraryResult> res = new ArrayList<JsLibraryResult>();

        for(JsLibrary lib : jsLibrares) {
            if(lib.getUris()== null) {
                //Log.warn("The library "+lib.getName()+" doesn't have uri regex ?!!");
                continue;
            }
            for(String uriRegex : lib.getUris()) {

                //Extract version
                Pattern p = Pattern.compile(uriRegex);
                String version = RegexUtil.simpleMatch(p,uri);

                if(version != null) { //Pattern match
                    Log.debug("Pattern match "+uriRegex+" !");

                    //Look for vulnerability affecting this specific version..
                    for(JsVulnerability vuln : lib.getVulnerabilities()) {
                        if(CompareVersionUtil.isUnder(version,vuln.getBelow())) {

                            if(vuln.getAtOrAbove() == null ||
                                    CompareVersionUtil.atOrAbove(version,vuln.getAtOrAbove())) {

                                Log.debug("Vulnerability found!");
                                res.add(new JsLibraryResult(lib,vuln));
                            }
                        }
                    }
                }
            }
        }
        return res;
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
