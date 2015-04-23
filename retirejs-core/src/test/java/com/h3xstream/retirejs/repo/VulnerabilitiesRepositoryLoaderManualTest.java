package com.h3xstream.retirejs.repo;

import com.esotericsoftware.minlog.Log;

import java.io.IOException;

import static org.testng.Assert.assertTrue;

/**
 * Used to test the lookup of the remote repository.
 */
public class VulnerabilitiesRepositoryLoaderManualTest {
    public static void main(String[] args) throws IOException {
        Log.DEBUG();

        VulnerabilitiesRepositoryLoader.syncWithOnlineRepository = true;
        VulnerabilitiesRepositoryLoader loader = new VulnerabilitiesRepositoryLoader();
        VulnerabilitiesRepository localRepoLoad = loader.load();

        assertTrue(localRepoLoad.jsLibrares.size() > 0, "No library was loaded.");
    }

}
