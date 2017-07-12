package com.h3xstream.retirejs.repo;

import com.esotericsoftware.minlog.Log;
import com.h3xstream.retirejs.repo.dl.DefaultDownloader;
import com.h3xstream.retirejs.repo.dl.Downloader;
import com.h3xstream.retirejs.util.RegexUtil;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.util.*;

public class VulnerabilitiesRepositoryLoader {

    /**
     * This switch will be need for the test case.
     */
    public static boolean syncWithOnlineRepository = true;
    public static boolean cachedDownloadRepository = true;

    /**
     * The default repository URL
     */
    public static final String REPO_URL = "https://raw.githubusercontent.com/Retirejs/retire.js/master/repository/jsrepository.json";

    public VulnerabilitiesRepository load(String url) throws IOException {
        return load(url, new DefaultDownloader());
    }

    public VulnerabilitiesRepository load(String url, Downloader dl) throws IOException {
        if (url == null || url.length() == 0) {
            throw new IllegalArgumentException("url is null or empty");
        }

        String homeDir = System.getProperty("user.home");
        File cacheDir = new File(homeDir, ".retirejs");
        File retireJsRepoFile = new File(cacheDir, "jsrepository.json");

        if (syncWithOnlineRepository) { //Remote repository

            if(cachedDownloadRepository) {

                if(!cacheDir.exists()) {
                    Log.info("Creating Retire.js cache directory "+cacheDir.getCanonicalPath());
                    cacheDir.mkdir();
                }
            }

            //
            try {

                if(cacheDir.exists()) {
                    Log.info("Caching Retire.js latest repository");
                    dl.downloadUrlToFile(url, retireJsRepoFile);
                    Log.info("Loading the latest Retire.js repository");
                    return loadFromInputStream(new FileInputStream(retireJsRepoFile));
                }
                else { //Permission limitation doesn't allow the creation of the cache directory ??!
                    URL remoteRepo = new URL(url);
                    URLConnection conn = remoteRepo.openConnection();
                    conn.connect();
                    InputStream inputStream = conn.getInputStream();

                    Log.info("Loading the latest Retire.js repository (not cache)");
                    return loadFromInputStream(inputStream);
                }
            } catch (UnknownHostException exception) {
                Log.error("Exception while loading the repository (Most likely unable to access the internet) " +
                        exception.getClass().getName() + ": " + exception.getMessage());
            } catch (IOException exception) { //If an problem occurs with the online file, the local repository is used.
                Log.error("Exception while loading the repository (Connection problem while loading latest repository from "
                        + url + ") " +
                        exception.getClass().getName() + ": " + exception.getMessage());
            } catch (Exception e) {
                Log.error("Exception while loading the repository (Unable to access GitHub ?) " +
                        e.getClass().getName() + ": " + e.getMessage());
                //e.printStackTrace();
            }
        }

        if(syncWithOnlineRepository && cachedDownloadRepository && retireJsRepoFile.exists()) {
            Log.info("Loading the local cached Retire.js repository (old version)");
            return loadFromInputStream(new FileInputStream(retireJsRepoFile));
        }

        //Local version of the repository
        Log.info("Loading the bundle Retire.js repository (old version)");
        InputStream inputStream = getClass().getResourceAsStream("/retirejs_repository.json");
        return loadFromInputStream(inputStream);
    }

    public VulnerabilitiesRepository load() throws IOException {
        return load(REPO_URL);
    }

    public VulnerabilitiesRepository loadFromInputStream(InputStream in) throws IOException {
        JSONObject rootJson = new JSONObject(convertStreamToString(in));


        VulnerabilitiesRepository repo = new VulnerabilitiesRepository();

        int nbLoaded = 0;
        Iterator it = rootJson.keySet().iterator(); //Iterate on each library jquery, YUI, prototypejs, ...
        while (it.hasNext()) {
            String key = (String) it.next();
            JSONObject libJson = rootJson.getJSONObject(key);

            JsLibrary lib = new JsLibrary();

            if (libJson.has("vulnerabilities")) {
                JSONArray vulnerabilities = libJson.getJSONArray("vulnerabilities");

                lib.setName(key);
                //Log.debug("Building the library " + key);

                for (int i = 0; i < vulnerabilities.length(); i++) { //Build Vulnerabilities list
                    JSONObject vuln = vulnerabilities.getJSONObject(i);
                    String atOrAbove = vuln.has("atOrAbove") ? vuln.getString("atOrAbove") : null; //Optional field
                    String below = vuln.getString("below");
                    List<String> info = objToStringList(vuln.get("info"), false);
                    Map<String,List<String>> identifiers = vuln.has("identifiers") ?
                            objToStringMapMultiValues(vuln.get("identifiers")) :
                            new HashMap<String,List<String>>();
                    String severity = vuln.has("severity") ? vuln.getString("severity") : "medium";
                    lib.getVulnerabilities().add(new JsVulnerability(atOrAbove, below, info,identifiers,severity));
                }
            }
            if (libJson.has("extractors")) {
                JSONObject extractor = libJson.getJSONObject("extractors");
                //Imports various lists
                if (extractor.has("func"))
                    lib.setFunctions(objToStringList(extractor.get("func"), false));
                if (extractor.has("filename"))
                    lib.setFilename(objToStringList(extractor.get("filename"), true));
                if (extractor.has("filecontent"))
                    lib.setFileContents(objToStringList(extractor.get("filecontent"), true));
                if (extractor.has("hashes"))
                    lib.setHashes(objToStringMap(extractor.get("hashes")));
                if (extractor.has("uri"))
                    lib.setUris(objToStringList(extractor.get("uri"), true));
            }
            //Once all the information have been collected, the library is ready to be cache.

            repo.addLibrary(lib);
            nbLoaded++;
            //System.out.println(libJson.toString());
        }
        Log.debug(nbLoaded + " loaded library.");
        return repo;
    }

    ///Convertion utility methods

    public List<String> objToStringList(Object obj, boolean replaceVersionWildcard) {
        JSONArray array = (JSONArray) obj;
        List<String> strArray = new ArrayList<String>(array.length());
        for (int i = 0; i < array.length(); i++) { //Build Vulnerabilities list

            if (replaceVersionWildcard) {
                strArray.add(RegexUtil.replaceVersion(array.getString(i)));
            } else {
                strArray.add(array.getString(i));
            }
        }
        return strArray;
    }

    public Map<String, String> objToStringMap(Object obj) {
        Map<String, String> finalMap = new HashMap<String, String>();

        JSONObject jsonObj = (JSONObject) obj;
        Iterator it = jsonObj.keySet().iterator();
        while (it.hasNext()) {
            String key = (String) it.next();

            finalMap.put(key, jsonObj.getString(key));
        }
        return finalMap;
    }

    public Map<String, List<String>> objToStringMapMultiValues(Object obj) {
        Map<String, List<String>> finalMap = new HashMap<String, List<String>>();

        JSONObject jsonObj = (JSONObject) obj;
        Iterator it = jsonObj.keySet().iterator();
        while (it.hasNext()) {
            String key = (String) it.next();

            JSONArray valuesArray = jsonObj.optJSONArray(key);
            if(valuesArray == null) {
                finalMap.put(key, Arrays.asList(jsonObj.getString(key)));
            }
            else {
                finalMap.put(key, objToStringList(valuesArray,false));
            }
        }
        return finalMap;
    }

    static String convertStreamToString(InputStream is) {
        try {
            Scanner s = new Scanner(is, "UTF-8").useDelimiter("\\A");
            return s.hasNext() ? s.next() : "";
        } finally {
            try {
                is.close();
            } catch (IOException e) {
            }
        }
    }




}
