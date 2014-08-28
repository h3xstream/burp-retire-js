package com.h3xstream.retirejs.repo;

import org.testng.annotations.Test;

import java.io.IOException;
import java.util.List;

import static org.testng.Assert.assertEquals;

public class SearchByUriTest {

    @Test
    public void findJqueryByUri() throws IOException {
        RepositoryLoader.syncWithOnlineRepository = false;

        Repository repo = new RepositoryLoader().load();

        List<JsLibraryResult> res = repo.findByUri("/1.6.3/jquery.js");
        assertEquals(res.size(), 1, "Jquery not found");

        repo.findByUri("/1.9.0/jquery.min.js");
        assertEquals(res.size(), 1, "Jquery not found");
    }

    @Test
    public void findEmberByUri() throws IOException {
        RepositoryLoader.syncWithOnlineRepository = false;

        Repository repo = new RepositoryLoader().load();

        List<JsLibraryResult> res = repo.findByUri("/v1.3.0-1/ember.js");
        assertEquals(res.size(), 1, "Ember not found");

        repo.findByUri("/1.2.1-1/ember.min.js");
        assertEquals(res.size(), 1, "Ember not found");
    }
}
