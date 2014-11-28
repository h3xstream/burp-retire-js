package com.h3xstream.retirejs.repo;

import com.esotericsoftware.minlog.Log;
import com.h3xstream.retirejs.util.CompareVersionUtil;
import com.h3xstream.retirejs.util.RegexUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Class that hold the definition of all the libraries.
 */
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
        Log.debug("Analysing URI: \""+uri+"\"");
        List<JsLibraryResult> res = new ArrayList<JsLibraryResult>();

        long before = System.currentTimeMillis();

        libLoop: for(JsLibrary lib : jsLibrares) {
            //Log.debug(lib.getName() +" has "+lib.getUris()+" URIs");
            if(lib.getUris()== null) {
                //Log.warn("The library "+lib.getName()+" doesn't have uri regex ?!!");
                continue;
            }
            for(String uriRegex : lib.getUris()) {

                //Extract version
                Pattern p = Pattern.compile(uriRegex);
                String version = RegexUtil.simpleMatch(p,uri);

                if(version != null) { //Pattern match
                    Log.debug("Pattern match \""+uriRegex+"\" !");
                    Log.debug("Identify the library "+lib.getName()+" (version:"+version+")");

                    findVersionVulnerable(lib,version,res);
                    continue libLoop;
                }
            }
        }

        long delta = System.currentTimeMillis()-before;
        Log.debug("It took ~"+(int)(delta/1000.0)+" sec. ("+delta+" ms) to scan");
        return res;
    }

    /**
     * This search mode will identify the library by there filename. (official distribution filename)
     * @param filename
     * @return
     */
    public List<JsLibraryResult> findByFilename(String filename) {
        Log.debug("Analysing filename: \""+filename+"\"");

        long before = System.currentTimeMillis();

        List<JsLibraryResult> res = new ArrayList<JsLibraryResult>();
        libLoop: for(JsLibrary lib : jsLibrares) {
            if(lib.getFilename()== null) {
                continue;
            }
            for(String filenameRegex : lib.getFilename()) {

                //Extract version
                Pattern p = Pattern.compile(filenameRegex);
                String version = RegexUtil.simpleMatch(p,filename);

                if(version != null) { //Pattern match
                    Log.debug("Pattern match \""+filenameRegex+"\" !");
                    Log.debug("Identify the library "+lib.getName()+" (version:"+version+")");


                    findVersionVulnerable(lib,version,res);
                    continue libLoop;
                }
            }
        }


        long delta = System.currentTimeMillis()-before;
        Log.debug("It took ~"+(int)(delta/1000.0)+" sec. ("+delta+" ms) to scan");
        return res;
    }

    /**
     * This search mode will look for literal string specific to the vulnerable libraries.
     * @param scriptContent
     * @return
     */
    public List<JsLibraryResult> findByFileContent(String scriptContent) {
        String scriptStart = scriptContent.substring(0,Math.min(20,scriptContent.length())).replace("\n","");
        Log.debug("Analysing the content: \""+scriptStart+"[..]\"");

        long before = System.currentTimeMillis();

        List<JsLibraryResult> res = new ArrayList<JsLibraryResult>();
        libLoop: for(JsLibrary lib : jsLibrares) {
            if(lib.getFileContents()== null) {
                continue;
            }
            for(String contentRegex : lib.getFileContents()) {

                //Extract version
                Pattern p = Pattern.compile(contentRegex);
                String version = RegexUtil.simpleMatch(p,scriptContent);

                if(version != null) { //Pattern match
                    Log.debug("Pattern match \""+contentRegex+"\" !");
                    Log.debug("Identify the library "+lib.getName()+" (version:"+version+")");

                    findVersionVulnerable(lib,version,res);
                    continue libLoop;
                }
            }
        }

        long delta = System.currentTimeMillis()-before;
        Log.debug("It took ~"+ (int)(delta/1000.0) +" sec. (" + delta + " ms) to scan");
        return res;
    }


    public List<JsLibraryResult> findByHash(String hash) {
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


    private void findVersionVulnerable(JsLibrary lib,String version,List<JsLibraryResult> resultsFound) {
        //Look for vulnerability affecting this specific version..
        for(JsVulnerability vuln : lib.getVulnerabilities()) {
            if(CompareVersionUtil.isUnder(version,vuln.getBelow())) {

                if(vuln.getAtOrAbove() == null ||
                        CompareVersionUtil.atOrAbove(version,vuln.getAtOrAbove())) {

                    Log.info(String.format("Vulnerability found: %s below %s", lib.getName(), vuln.getBelow()));
                    resultsFound.add(new JsLibraryResult(lib,vuln,version));
                }
            }
        }
    }
}
