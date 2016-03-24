package com.h3xstream.retirejs.repo;


import com.esotericsoftware.minlog.Log;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;

import static org.testng.Assert.assertTrue;

public class VulnerabilitiesRepositoryLoaderTest {

    @BeforeClass
    public void setUp() {
        Log.DEBUG();
    }

    @Test
    public void testRepositoryLoad() throws IOException {
        VulnerabilitiesRepositoryLoader.syncWithOnlineRepository = false;


        VulnerabilitiesRepositoryLoader loader = new VulnerabilitiesRepositoryLoader();
        VulnerabilitiesRepository localRepoLoad = loader.load();

        assertTrue(localRepoLoad.jsLibrares.size() > 0, "No library was loaded.");
    }


    @Test(enabled=true) //Not sure if this test should be kept enabled by default since it create file in user dir
    public void testRepositoryLoadRemote() throws IOException {
        VulnerabilitiesRepositoryLoader.syncWithOnlineRepository = true;


        VulnerabilitiesRepositoryLoader loader = new VulnerabilitiesRepositoryLoader();
        VulnerabilitiesRepository localRepoLoad = loader.load();

        assertTrue(localRepoLoad.jsLibrares.size() > 0, "No library was loaded.");
    }
}
