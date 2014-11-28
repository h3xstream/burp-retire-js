package burp.vuln;

import java.util.ArrayList;
import java.util.List;

public class DescriptionModel {

    private String libraryDetect;
    private String versionDetect;

    private final List<String> links = new ArrayList<String>();
    private String aboveVersion;
    private String belowVersion;

    public String getLibraryDetect() {
        return libraryDetect;
    }

    public void setLibraryDetect(String libraryDetect) {
        this.libraryDetect = libraryDetect;
    }

    public String getVersionDetect() {
        return versionDetect;
    }

    public void setVersionDetect(String versionDetect) {
        this.versionDetect = versionDetect;
    }

    public List<String> getLinks() {
        return links;
    }

    public String getAboveVersion() {
        return aboveVersion;
    }

    public void setAboveVersion(String aboveVersion) {
        this.aboveVersion = aboveVersion;
    }

    public String getBelowVersion() {
        return belowVersion;
    }

    public void setBelowVersion(String belowVersion) {
        this.belowVersion = belowVersion;
    }
}
