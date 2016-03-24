package com.h3xstream.retirejs.repo.dl;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;

public interface Downloader {

    void downloadUrlToFile(String url, File file) throws Exception;
}
