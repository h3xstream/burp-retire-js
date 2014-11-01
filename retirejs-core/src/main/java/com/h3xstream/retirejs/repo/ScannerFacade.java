package com.h3xstream.retirejs.repo;

import com.esotericsoftware.minlog.Log;
import com.h3xstream.retirejs.util.HashUtil;

import java.io.IOException;
import java.util.List;

public class ScannerFacade {
    private VulnerabilitiesRepository repo;
    private static ScannerFacade instance; //Singleton instance

    private ScannerFacade() throws IOException {
        this.repo = new VulnerabilitiesRepositoryLoader().load();
    }

    /**
     * Obtain the singleton instance. It make sure the repo is loaded the first time.
     * @return
     * @throws IOException
     */
    public static ScannerFacade getInstance() throws IOException {
        if(instance == null) {
            instance = new ScannerFacade();
        }
        return instance;
    }

    public List<JsLibraryResult> scanScript(String scriptName,byte[] respBytes,int offset) {

        //1. Search by URI (path + file name)
        List<JsLibraryResult> res = repo.findByUri(scriptName);

        if(res.size() == 0) { //2. Search by file name
            Log.debug(String.format("[%s] No path matching ",scriptName));
            res = repo.findByFilename(scriptName);

            if(res.size() == 0) { //3. Compare the hash with known hash
                Log.debug(String.format("[%s] No filename matching ",scriptName));
                String hash = HashUtil.hashSha1(respBytes, offset);
                res = repo.findByHash(hash);

                if(res.size() == 0) { //4. Look for specific string in the content
                    Log.debug(String.format("[%s] No hash matching ",scriptName));
                    String contentString = new String(respBytes,offset,respBytes.length-offset);
                    res = repo.findByFileContent(contentString);

                    if(res.size() == 0) { //5. Evaluation the script in a sandbox
                        Log.debug(String.format("[%s] No script snippets matching ",scriptName));
                        res = repo.findByFunction(contentString);
                    }
                }
            }
        }

        return res;
    }
}
