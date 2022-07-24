package com.h3xstream.retirejs.util;

import com.esotericsoftware.minlog.Log;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexUtil {

    private static Pattern PATTERN_REPLACE = Pattern.compile("^\\/(.*[^\\\\])\\/([^\\/]+)\\/$");

    /**
     *
     * @param pattern Pattern to find containing a single group to match. The group is mark in parentheses.
     * @param data The source of data to process (URI, filename, js content, ..)
     * @return Match of the first group extract
     */
    public static String simpleMatch(Pattern pattern, String data) {
        try {
            Matcher m = pattern.matcher(data);
            validateRegexResult(m);
            return m.find() ? m.group(1) : null;
        }
        catch (IllegalArgumentException iae) {
            throw iae;
        }
        catch (Throwable t) { //Some regex built are likely to create StackOverflow.. See issue #54
            return null;
        }
    }

    /**
     *
     * @param replacePattern The format expected is /(FIND_SOMETHING)/(REPLACE_BY_SOMETHING)/
     * @param data The source of data to process (URI, filename, js content, ..)
     * @return Match of the first group extract
     */
    public static String replaceMatch(String replacePattern, String data) {
        Matcher mRP = PATTERN_REPLACE.matcher(replacePattern);
        if(mRP.find() || mRP.groupCount() != 3) { //Extract the replace pattern /(FIND_SOMETHING)/(REPLACE_BY_SOMETHING)/
            String patternToFind = mRP.group(1);
            String replaceBy = mRP.group(2);
            Log.debug("Pattern to find: "+patternToFind);
            Log.debug("Replace by: "+replaceBy);

            Matcher m = Pattern.compile(patternToFind).matcher(data);
            validateRegexResult(m);
            if(m.find()) { //Do the replacement
                return m.group(0).replaceAll(patternToFind, replaceBy);
            }
            else {
                return null; //Pattern was not found..
            }
        }
        else {
            throw new RuntimeException("Invalid replace pattern.");
        }
    }

    private static void validateRegexResult(Matcher m) {
        if(m.find() && m.groupCount() == 0) throw new IllegalArgumentException("The regex is expected to contain at least one group.");
        m.reset(); //Needed to use find() again
    }

    public static String replaceVersion(String regex) {
        //Note : It is important to load the repository file in UTF-8 (as it is encoded in this file)
        regex = regex.replace("§§version§§","[0-9][0-9.a-z_\\\\\\\\-]+");
        if(regex.contains("{")) {
            regex = regex.replaceAll("\\{\\}", "\\\\{\\\\}"); //Exception {} is interpret as empty number of char as in [a-z]{1337}
        }
        if(regex.contains("\n")) {
            regex = regex.replaceAll("\n","\\\\n");
        }
        if(regex.contains("[")) {
            regex = regex.replaceAll("\\[\\]", "\\\\[\\\\]"); // see https://github.com/RetireJS/retire.js/issues/382 for jquery.datatables
        }
        return regex;
    }
}
