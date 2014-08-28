package com.h3xstream.retirejs.repo;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.*;

public class RepositoryLoader {

    /**
     * This switch will be mandatory in the case.
     */
    public static boolean syncWithOnlineRepository = true;


    public Repository load() throws IOException {
        InputStream inputStream = null;

        if (syncWithOnlineRepository) {
            //TODO:Load URL from property file
            URL remoteRepo = new URL("https://raw.githubusercontent.com/bekk/retire.js/master/repository/jsrepository.json");
            URLConnection conn = remoteRepo.openConnection();
            conn.connect();
            inputStream = conn.getInputStream();

            try {
                return loadFromInputStream(inputStream);
            } catch (IOException exception) { //If an problem occurs with the online file, the local repository is used.
                //TODO:Logging
            } catch (RuntimeException exception) {
                //TODO:Logging
            }
        }

        inputStream = getClass().getResourceAsStream("/retirejs_repository.json");
        return loadFromInputStream(inputStream);
    }

    public Repository loadFromInputStream(InputStream in) throws IOException {
        JSONObject rootJson = new JSONObject(convertStreamToString(in));


        Repository repo = new Repository();


        Iterator it = rootJson.keySet().iterator(); //Iterate on each library jquery, YUI, prototypejs, ...
        while (it.hasNext()) {
            String key = (String) it.next();
            JSONObject libJson = rootJson.getJSONObject(key);

            JsLibrary lib = new JsLibrary();

            if (libJson.has("vulnerabilities")) {
                JSONArray vulnerabilities = libJson.getJSONArray("vulnerabilities");

                lib.setName(key);
                //System.out.println("Building the library " + key);

                for (int i = 0; i < vulnerabilities.length(); i++) { //Build Vulnerabilities list
                    JSONObject vuln = vulnerabilities.getJSONObject(i);
                    String below = vuln.getString("below");
                    List<String> info = objToStringList(vuln.get("info"));
                    lib.getVulnerabilities().add(new JsVulnerability(below, info));
                }
            }
            if (libJson.has("extractors")) {
                JSONObject extractor = libJson.getJSONObject("extractors");
                //Imports various lists
                if (extractor.has("func"))
                    lib.setFunctions(objToStringList(extractor.get("func")));
                if (extractor.has("filename"))
                    lib.setFilename(objToStringList(extractor.get("filename")));
                if (extractor.has("filecontent"))
                    lib.setFileContents(objToStringList(extractor.get("filecontent")));
                if (extractor.has("hashes"))
                    lib.setHashes(objToStringMap(extractor.get("hashes")));
            }
            //Once all the information have been collected, the library is ready to be cache.
            repo.addLibrary(lib);
            //System.out.println(libJson.toString());
        }

        return repo;
    }

    ///Convertion utility methods

    public List<String> objToStringList(Object obj) {
        JSONArray array = (JSONArray) obj;
        List<String> strArray = new ArrayList<String>(array.length());
        for (int i = 0; i < array.length(); i++) { //Build Vulnerabilities list
            strArray.add(array.getString(i));
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

    static String convertStreamToString(InputStream is) {
        try {
            Scanner s = new Scanner(is).useDelimiter("\\A");
            return s.hasNext() ? s.next() : "";
        } finally {
            try {
                is.close();
            } catch (IOException e) {
            }
        }
    }
}
