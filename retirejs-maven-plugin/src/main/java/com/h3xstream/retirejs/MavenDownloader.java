package com.h3xstream.retirejs;

import com.h3xstream.retirejs.repo.dl.Downloader;
import org.apache.maven.artifact.manager.WagonConfigurationException;
import org.apache.maven.artifact.manager.WagonManager;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.wagon.ConnectionException;
import org.apache.maven.wagon.UnsupportedProtocolException;
import org.apache.maven.wagon.Wagon;
import org.apache.maven.wagon.authentication.AuthenticationException;
import org.apache.maven.wagon.repository.Repository;

import java.io.File;

/**
 * Wagon is the API for Maven to download artifact or file from a Maven repository.
 *
 * When a resource is fetch "/com/test-company/artifact/1.3.3.7/pom.xml", it will prefix the repository URL.
 *
 * This API is use because it take care of Maven proxy configuration.
 */
public class MavenDownloader implements Downloader {

    private Log log;
    private WagonManager wagonManager;
    protected Repository repo;

    private static final String PREFIX_URL = "https://raw.githubusercontent.com/";

    public MavenDownloader(final Log log, final WagonManager wagonManager) throws WagonConfigurationException, UnsupportedProtocolException, ConnectionException, AuthenticationException {
        this.log = log;
        this.wagonManager = wagonManager;
        repo = new Repository(PREFIX_URL, PREFIX_URL);
    }

    @Override
    public void downloadUrlToFile(String url, File file) throws Exception {
        if (url == null || url.length() == 0) {
            throw new IllegalArgumentException("url is null or empty");
        }

        Wagon w = wagonManager.getWagon(repo);

        w.connect(repo, wagonManager.getProxy(repo.getProtocol()));
        if(url.startsWith(PREFIX_URL)) {
            url = url.replace(PREFIX_URL,"");
        }
        w.get(url, file);
    }
}
