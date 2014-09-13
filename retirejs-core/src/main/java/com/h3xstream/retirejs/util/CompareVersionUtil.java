package com.h3xstream.retirejs.util;

/**
 * Utility to compare
 *
 */
public class CompareVersionUtil {

    /**
     * Method that calculate if [Version 1] is under [Version 2]
     * <pre>
     * 1.0.1 - 1.0.2  : YES<br/>
     * 1.0.1 - 2.0.1  : YES<br/>
     * 1.3.2 - 1.2.5  : NO<br/>
     * 1.2.3 - 1.2.3  : NO<br/>
     * </pre>
     * ===
     * Reimplementation of isAtOrAbove (but reverse)
     * https://github.com/bekk/retire.js/blob/master/node/lib/retire.js#L85
     */
    public static boolean isUnder(String version, String under) {
        String[] v1Parts = version.split("[\\.\\-]");
        String[] v2Parts = under.split("[\\.\\-]");

        int numberParts = Math.max(v1Parts.length,v2Parts.length);
        for (int i = 0; i < numberParts; i++) {
            if(v2Parts.length > i && "*".equals(v2Parts[i])) {
                continue;
            }

            int version1Segment = versionPartToInteger(v1Parts,i);
            int version2Segment = versionPartToInteger(v2Parts,i);

            if(version1Segment > version2Segment) {
                return false;
            } else if(version1Segment < version2Segment) {
                return true;
            }
            //else continue;
        }
        return false; //same version
    }

    public static boolean atOrAbove(String version, String atOrAbove) {
        String[] v1Parts = version.split("[\\.\\-]");
        String[] v2Parts = atOrAbove.split("[\\.\\-]");

        int numberParts = Math.max(v1Parts.length,v2Parts.length);
        for (int i = 0; i < numberParts; i++) {
            if(v2Parts.length > i && "*".equals(v2Parts[i])) {
                continue;
            }

            int version1Segment = versionPartToInteger(v1Parts,i);
            int version2Segment = versionPartToInteger(v2Parts,i);

            if(version1Segment < version2Segment) {
                return false;
            } else if(version1Segment > version2Segment) {
                return true;
            }
            //else continue;
        }
        return true; //same version
    }

    /**
     * Should be equivalent to:
     * https://github.com/bekk/retire.js/blob/master/node/lib/retire.js#L99
     * @param value
     * @return
     */
    private static int versionPartToInteger(String[] value,int index) {
        if(value.length <= index) {
            return 0;
        }
        try {
            return Integer.parseInt(value[index]);
        }
        catch (NumberFormatException e) {
            return 0;
        }
    }
}
