package com.h3xstream.retirejs.repo;

import com.esotericsoftware.minlog.Log;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.*;
import static org.testng.Assert.assertEquals;

public class ScannerFacadeTest {

    private static List<JsLibraryResult> EMPTY_RESULT = new ArrayList<JsLibraryResult>();


    private static List<JsLibraryResult> ONE_RESULT = new ArrayList<JsLibraryResult>();
    {
        ONE_RESULT.add(mock(JsLibraryResult.class));
    }

    private static List<JsLibraryResult> MANY_RESULTS = new ArrayList<JsLibraryResult>();
    {
        MANY_RESULTS.add(mock(JsLibraryResult.class));
        MANY_RESULTS.add(mock(JsLibraryResult.class));
    }

    private static String DUMMY_SCRIPT = "/* yolo.js 1.3.3.7 */ eval(decodeURIComponent(window.location.hash))";
    private static String DUMMY_SCRIPT_SHA1 = "0158eb7c7a9cb37a3a2180edc5f159ad1c55bb05";



    @BeforeClass
    public void setUp() {
        Log.DEBUG();
    }

    @Test
    public void uriMatch() throws IOException {
        VulnerabilitiesRepositoryLoader.syncWithOnlineRepository = false;

        //Init. mock
        VulnerabilitiesRepository repo = mock(VulnerabilitiesRepository.class);
        when(repo.findByUri("/js/yolo.js")).thenReturn(ONE_RESULT);

        //Call the scanner logic
        ScannerFacade scanner = new ScannerFacade(repo);
        List<JsLibraryResult> results = scanner.scanScript("/js/yolo.js",DUMMY_SCRIPT.getBytes(),0);

        //Assertions
        assertEquals(results.size(),1,"Expect one result.");
        verify(repo).findByUri("/js/yolo.js");
        verify(repo,never()).findByFilename(anyString());
        verify(repo,never()).findByHash(anyString());
        verify(repo,never()).findByFileContent(anyString());
    }

    @Test
    public void filenameMatch() throws IOException {
        VulnerabilitiesRepositoryLoader.syncWithOnlineRepository = false;

        //Init. mock
        VulnerabilitiesRepository repo = mock(VulnerabilitiesRepository.class);
        when(repo.findByUri("/js/yolo.js")).thenReturn(EMPTY_RESULT);
        when(repo.findByFilename("yolo.js")).thenReturn(ONE_RESULT);

        //Call the scanner logic
        ScannerFacade scanner = new ScannerFacade(repo);
        List<JsLibraryResult> results = scanner.scanScript("/js/yolo.js",DUMMY_SCRIPT.getBytes(),0);

        //Assertions
        assertEquals(results.size(),1,"Expect one result.");
        verify(repo).findByUri("/js/yolo.js");
        verify(repo).findByFilename("yolo.js");
        verify(repo,never()).findByHash(anyString());
        verify(repo,never()).findByFileContent(anyString());
    }

    @Test
    public void hashMatch() throws IOException {
        VulnerabilitiesRepositoryLoader.syncWithOnlineRepository = false;

        //Init. mock
        VulnerabilitiesRepository repo = mock(VulnerabilitiesRepository.class);
        when(repo.findByUri("/js/yolo.js")).thenReturn(EMPTY_RESULT);
        when(repo.findByFilename("yolo.js")).thenReturn(EMPTY_RESULT);
        when(repo.findByHash(DUMMY_SCRIPT_SHA1)).thenReturn(ONE_RESULT);

        //Call the scanner logic
        ScannerFacade scanner = new ScannerFacade(repo);
        List<JsLibraryResult> results = scanner.scanScript("/js/yolo.js",DUMMY_SCRIPT.getBytes(),0);

        //Assertions
        assertEquals(results.size(),1,"Expect one result.");
        verify(repo).findByUri("/js/yolo.js");
        verify(repo).findByFilename("yolo.js");
        verify(repo).findByHash(DUMMY_SCRIPT_SHA1);
        verify(repo,never()).findByFileContent(anyString());
    }

    @Test
    public void contentMatch() throws IOException {
        VulnerabilitiesRepositoryLoader.syncWithOnlineRepository = false;

        //Init. mock
        VulnerabilitiesRepository repo = mock(VulnerabilitiesRepository.class);
        when(repo.findByUri("/js/yolo.js")).thenReturn(EMPTY_RESULT);
        when(repo.findByFilename("yolo.js")).thenReturn(EMPTY_RESULT);
        when(repo.findByHash(DUMMY_SCRIPT_SHA1)).thenReturn(EMPTY_RESULT);
        when(repo.findByFileContent(DUMMY_SCRIPT)).thenReturn(ONE_RESULT);

        //Call the scanner logic
        ScannerFacade scanner = new ScannerFacade(repo);
        List<JsLibraryResult> results = scanner.scanScript("/js/yolo.js",DUMMY_SCRIPT.getBytes(),0);

        //Assertions
        assertEquals(results.size(),1,"Expect one result.");
        verify(repo).findByUri("/js/yolo.js");
        verify(repo).findByFilename("yolo.js");
        verify(repo).findByHash(DUMMY_SCRIPT_SHA1);
        verify(repo).findByFileContent(DUMMY_SCRIPT);
    }

    @Test
    public void noMatch() throws IOException {
        VulnerabilitiesRepositoryLoader.syncWithOnlineRepository = false;

        //Init. mock
        VulnerabilitiesRepository repo = mock(VulnerabilitiesRepository.class);
        when(repo.findByUri("/js/yolo.js")).thenReturn(EMPTY_RESULT);
        when(repo.findByFilename("yolo.js")).thenReturn(EMPTY_RESULT);
        when(repo.findByHash(DUMMY_SCRIPT_SHA1)).thenReturn(EMPTY_RESULT);
        when(repo.findByFileContent(DUMMY_SCRIPT)).thenReturn(EMPTY_RESULT);

        //Call the scanner logic
        ScannerFacade scanner = new ScannerFacade(repo);
        List<JsLibraryResult> results = scanner.scanScript("/js/yolo.js",DUMMY_SCRIPT.getBytes(),0);

        //Assertions
        assertEquals(results.size(),0,"Expect one result.");
        verify(repo).findByUri("/js/yolo.js");
        verify(repo).findByFilename("yolo.js");
        verify(repo).findByHash(DUMMY_SCRIPT_SHA1);
        verify(repo).findByFileContent(DUMMY_SCRIPT);
    }

    @Test
    public void uriMatchToHtml() throws IOException {
        VulnerabilitiesRepositoryLoader.syncWithOnlineRepository = false;

        //Init. mock
        VulnerabilitiesRepository repo = mock(VulnerabilitiesRepository.class);
        when(repo.findByUri("/js/yolo.js")).thenReturn(ONE_RESULT);

        //Call the scanner logic
        ScannerFacade scanner = new ScannerFacade(repo);
        List<JsLibraryResult> results = scanner.scanHtml((
            "<sCrIpT sRc=\"/js/yolo.js\" type=\"text/javascript\"></sCrIpT>" + // double quote
            "<sCrIpT sRc='/js/yolo.js' type='text/javascript'></sCrIpT>" +     // single quote
            "<sCrIpT sRc=/js/yolo.js type=text/javascript></sCrIpT>"           // no quote
        ).getBytes(),0);

        //Assertions
        assertEquals(results.size(),3,"Expect one result.");
        verify(repo,times(3)).findByUri("/js/yolo.js");
        verify(repo,never()).findByFilename(anyString());
        verify(repo,never()).findByHash(anyString());
        verify(repo,never()).findByFileContent(anyString());
    }

    @Test
    public void filenameMatchToHtml() throws IOException {
        VulnerabilitiesRepositoryLoader.syncWithOnlineRepository = false;

        //Init. mock
        VulnerabilitiesRepository repo = mock(VulnerabilitiesRepository.class);
        when(repo.findByUri("/js/yolo.js")).thenReturn(EMPTY_RESULT);
        when(repo.findByFilename("yolo.js")).thenReturn(ONE_RESULT);

        //Call the scanner logic
        ScannerFacade scanner = new ScannerFacade(repo);
        List<JsLibraryResult> results = scanner.scanHtml((
            "<sCrIpT sRc=\"/js/yolo.js\" type=\"text/javascript\"></sCrIpT>" + // double quote
            "<sCrIpT sRc='/js/yolo.js' type='text/javascript'></sCrIpT>" +     // single quote
            "<sCrIpT sRc=/js/yolo.js type=text/javascript></sCrIpT>"           // no quote
        ).getBytes(),0);

        //Assertions
        assertEquals(results.size(),3,"Expect one result.");
        verify(repo,times(3)).findByUri("/js/yolo.js");
        verify(repo,times(3)).findByFilename("yolo.js");
        verify(repo,never()).findByHash(anyString());
        verify(repo,never()).findByFileContent(anyString());
    }
}