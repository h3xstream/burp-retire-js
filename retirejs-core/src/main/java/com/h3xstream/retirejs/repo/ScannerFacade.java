package com.h3xstream.retirejs.repo;

import com.esotericsoftware.minlog.Log;
import com.h3xstream.retirejs.util.HashUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONException;

public class ScannerFacade {
    private VulnerabilitiesRepository repo;
    private static ScannerFacade instance; //Singleton instance

    private ScannerFacade() throws IOException, JSONException {
        this.repo = new VulnerabilitiesRepositoryLoader().load();
    }

    /**
     * For testing purpose only
     * @param repo Mock repository (For testing purpose)
     * @throws IOException Unable to load the repository
     */
    public ScannerFacade(VulnerabilitiesRepository repo) throws IOException {
        this.repo = repo;
    }

    /**
     * Obtain the singleton instance. It make sure the repo is loaded the first time.
     * @return Will always return the same instance
     * @throws IOException Unable to load the repository
     */
    public static ScannerFacade getInstance() throws IOException, JSONException {
        if(instance == null) {
            instance = new ScannerFacade();
        }
        return instance;
    }

    public static ScannerFacade loadInstance(VulnerabilitiesRepository repo) throws IOException {
        if(instance == null) {
            instance = new ScannerFacade(repo);
        }
        return instance;
    }

    /**
     * Look for potential script in the HTML code &lt;script src="//cdn.server.com/jquery/1.3.3.7.js"&gt;&lt;/script&gt;
     * @param respBytes Content of the JavaScript file (exclude HTTP headers)
     * @param offset The body of the response starts at this offset
     * @return The list of vulnerable libraries
     */
    public List<JsLibraryResult> scanHtml(byte[] respBytes, int offset) {
        String contentString = new String(respBytes,offset,respBytes.length-offset);
        List<JsLibraryResult> res = new ArrayList<JsLibraryResult>();
        for(String url : findScriptUrl(contentString)) {
            res.addAll(scanPath(url));
        }
        return res;
    }

    private List<String> findScriptUrl(String source) {
        String[] tokens = source.split("</");

        List<String> urls = new ArrayList<String>();

        for(String line : tokens) {
            if (line.toLowerCase().contains("<script")) { //This precondition avoid applyig an RegEx on every line
                Pattern p = Pattern.compile(
                    "<script[^>]*" + //script tags
                        "src=" + //src attribute
                        "(?<src>\"[^\"]*?\"|'[^']*?'|\\S+)", //URL between quotes
                    Pattern.CASE_INSENSITIVE);

                Matcher m = p.matcher(line);
                if (m.find()) {
                    String src = m.group("src");
                    String urlScript = src.startsWith("\"") || src.startsWith("'")
                        ? src.substring(1, src.length() - 1) // trim quotes
                        : src;
                    urls.add(urlScript);
                }
            }
        }

        return urls;
    }


    /**
     * Analyze a script with only its path is available.
     * For example a path in a HTML pages.
     * @param path File path (ie: /js/jquery/jquery-1.3.3.7.js)
     * @return The list of vulnerable libraries
     */
    public List<JsLibraryResult> scanPath(String path) {
        return scanScript(path,"".getBytes(),0);
    }

    /**
     * Analyze script with the JavaScript file is loaded.
     * The path has been extracted from the request URI.
     * And the response is the content of the file.
     *
     * @param path File path (ie: /js/jquery/jquery-1.3.3.7.js)
     * @param respBytes Content of the JavaScript file (exclude HTTP headers)
     * @param offset The body of the response starts at this offset
     * @return The list of vulnerable libraries
     */
    public List<JsLibraryResult> scanScript(String path,byte[] respBytes,int offset) {

        //1. Search by URI (path + file name)
        List<JsLibraryResult> res = repo.findByUri(path);

        if(res.size() == 0) { //2. Search by file name
            Log.debug(String.format("No path matching the script (%s)",path));
            String filename = getFilename(path);
            res = repo.findByFilename(filename);

            if(res.size() == 0) { //3. Compare the hash with known hash
                Log.debug(String.format("No filename matching the script (%s)",filename));
                String hash = HashUtil.hashSha1(respBytes, offset);
                res = repo.findByHash(hash);

                if(res.size() == 0) { //4. Look for specific string in the content
                    Log.debug(String.format("No hash matching %s (%s)", hash, path));

                    String contentString = new String(respBytes,offset,respBytes.length-offset);
                    res = repo.findByFileContent(contentString);

                    if(res.size() == 0) { //5. Evaluation the script in a sandbox
                        Log.debug(String.format("No content matching the script \"%s\"",path));

                        /*
                        res = repo.findByFunction(contentString);
                        */
                    }
                }
            }
        }

        return res;
    }

    private static String getFilename(String path) {
        int lastSlash = path.lastIndexOf('/');
        if(lastSlash < 0) lastSlash = 0;
        return path.substring(lastSlash+1);
    }
}
