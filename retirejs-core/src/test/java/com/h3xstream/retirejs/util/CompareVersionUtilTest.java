package com.h3xstream.retirejs.util;

import org.testng.annotations.Test;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class CompareVersionUtilTest {

    //Tests for isUnder method

    @Test
    public void basicPatternsUnder() {

        assertIsUnder("1.0.1","1.0.2");
        assertIsUnder("1.0.1","2.0.1");
        assertIsNotUnder("1.3.2", "1.2.5");
        assertIsNotUnder("5.0.1","5.0.1"); //Same
    }

    @Test
    public void wildPatternsUnder() {
        assertIsUnder("1.2.0","1.2.1-*");
        assertIsUnder("1.2.0-2","1.2.1-*");
        assertIsNotUnder("1.2.0-1","1.2.0-*");
        assertIsNotUnder("1.2.0-0", "1.1.9-*");
        assertIsNotUnder("1.2.0-0", "1.1.0-*");
        assertIsNotUnder("1.2.0", "1.1.0-*");
        assertIsNotUnder("1.2.0", "1.2.0-*"); //Under is exclusive (== is not under)
    }

    @Test
    public void variousPatternsUnder() {

        assertIsUnder("1.3.0-beta.2","1.3.0-beta.3");
        assertIsNotUnder("1.3.0-alpha.1", "1.2.9-alpha.2");
        assertIsNotUnder("1.3.0-alpha.1", "1.3.0-alpha.1");
        assertIsUnder("1.3.0-alpha.1", "1.3.0-alpha.2");
        assertIsNotUnder("1.3.0-alpha.1", "1.3.0-alpha.1"); //Same
    }

    //Tests for atOrAbove method

    @Test
    public void basicPatternsAtOrAbove() {

        assertAtOrAbove("1.0.2","1.0.1");
        assertAtOrAbove("2.0.1","1.0.1");
        assertNotAtOrAbove("1.2.5","1.3.2");
        assertNotAtOrAbove("1.2.5","2.3.2");
        assertAtOrAbove("7.3.5", "7.3.5");
    }

    @Test
    public void wildPatternsAtOrAbove() {
        assertAtOrAbove("1.2.1","1.2.0-*");
        assertAtOrAbove("1.2.1-2","1.2.0-*");
        assertAtOrAbove("1.2.0-1","1.2.0-*");
        assertNotAtOrAbove("1.1.9-9","1.2.0-*");
        assertNotAtOrAbove("1.1.0-0","1.2.0-*");
        assertNotAtOrAbove("1.1.0","1.2.0-*");
        assertAtOrAbove("1.2.0","1.2.0-*"); //Under is exclusive (== is not under)
    }

    @Test
    public void variousPatternsAtOrAbove() {

        assertNotAtOrAbove("1.3.0-beta.2","1.3.0-beta.3");
        assertAtOrAbove("1.3.0-alpha.1", "1.2.9-alpha.2");
        assertAtOrAbove("1.3.0-alpha.1", "1.3.0-alpha.1");
        assertNotAtOrAbove("1.3.0-alpha.1", "1.3.0-alpha.2");
        assertAtOrAbove("1.3.0-alpha.1", "1.3.0-alpha.1"); //Same
    }

    //Utility methods to create intuitive messages when tests failed

    private void assertIsUnder(String version1,String version2){
        CompareVersionUtil v = new CompareVersionUtil();
        assertTrue(v.isUnder(version1,version2),String.format("Version '%s' should be under '%s'",version1,version2));
    }

    private void assertIsNotUnder(String version1,String version2){
        CompareVersionUtil v = new CompareVersionUtil();
        assertFalse(v.isUnder(version1,version2),String.format("Version '%s' should not be under '%s'",version1,version2));
    }

    private void assertAtOrAbove(String version1,String version2){
        CompareVersionUtil v = new CompareVersionUtil();
        assertTrue(v.atOrAbove(version1,version2),String.format("Version '%s' should be at or above '%s'",version1,version2));
    }

    private void assertNotAtOrAbove(String version1,String version2){
        CompareVersionUtil v = new CompareVersionUtil();
        assertFalse(v.atOrAbove(version1,version2),String.format("Version '%s' should not be at or above '%s'",version1,version2));
    }
}
