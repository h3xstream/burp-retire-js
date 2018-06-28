package com.h3xstream.retirejs;

import com.esotericsoftware.minlog.Log;
import com.h3xstream.retirejs.repo.JsLibrary;
import com.h3xstream.retirejs.repo.JsLibraryResult;
import com.h3xstream.retirejs.repo.ScannerFacade;
import com.h3xstream.retirejs.repo.VulnerabilitiesRepository;
import com.h3xstream.retirejs.repo.VulnerabilitiesRepositoryLoader;
import org.apache.commons.io.IOUtils;
import org.apache.maven.artifact.manager.WagonConfigurationException;
import org.apache.maven.artifact.manager.WagonManager;
import org.apache.maven.model.Resource;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.apache.maven.wagon.ConnectionException;
import org.apache.maven.wagon.UnsupportedProtocolException;
import org.apache.maven.wagon.authentication.AuthenticationException;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * <p>
 * Scan the JavaScript files of the selected project to identify vulnerable JavaScript libraries.
 * </p>
 * <p>
 * The original Retire.js project is open-source and maintained by Erlend Oftedal (Bekk Consulting).
 * For more information about the project visit: http://bekk.github.io/retire.js/.
 * </p>
 *
 * @goal scan
 */
public class RetireJsScan extends AbstractMojo {

    /**
     * This flag will make the build fail if at least one library is found vulnerable.
     * It can be useful to create automate verification using a build server such as Jenkins.
     * @parameter property = "retireJsBreakOnFailure" defaultValue = false
     */
    protected boolean breakOnFailure;

    /**
     * This parameter will override the default public repo URL with the one specified.
     * @parameter property = "retireJsRepoUrl"
     */
    protected String repoUrl;

    /**
     * The Maven Project. (Inject component)
     *
     * @parameter property="project"
     * @required
     * @readonly
     * @since 1.0-alpha-1
     */
    protected MavenProject project;

    /**
     * @component
     * @since 1.0-alpha-3
     */
    protected WagonManager wagonManager;

    /**
     * Directory containing web resources files (by default src/main/webapp)
     *
     * @parameter property = "retireWebAppDir" default-value="${basedir}/src/main/webapp"
     * @required
     */
    protected File webAppDirectory;

    private VulnerabilitiesRepository repo;


    private void initMiniLog() {
        Log.setLogger(new Log.Logger() {
            @Override
            public void log(int level, String category, String message, Throwable ex) {
                switch(level) {
                    case 1: //TRACE
                    case 2: //DEBUG
                    case 3: //INFO
                        getLog().debug(message);
                        break;
                    case 4: //WARN
                        getLog().warn(message);
                        break;
                    case 5: //ERROR
                        getLog().error(message,ex);
                }
            }
        });
        Log.DEBUG();
    }

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        initMiniLog();

        List<JsLibraryResult> completeResults = new ArrayList<JsLibraryResult>();

        if (repoUrl == null || repoUrl.length() == 0) {
            getLog().debug("Using default URL: "+VulnerabilitiesRepositoryLoader.REPO_URL);
            repoUrl = VulnerabilitiesRepositoryLoader.REPO_URL;
        }

        try {
            repo = new VulnerabilitiesRepositoryLoader().load(repoUrl,new MavenDownloader(getLog(),wagonManager));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        try {
            //Scanning resources
            Set<Resource> allResources = new HashSet<Resource>();
            allResources.addAll(project.getResources());
            allResources.addAll(project.getTestResources());

            for(Resource res : allResources) {
                if(res.getDirectory() == null) continue;
                File sourceDir = new File(res.getDirectory());
                if(sourceDir.exists()) {
                    getLog().info("Scanning directory: "+sourceDir.toString());
                    scanDirectory(sourceDir, completeResults);
                }
            }

            //WebApp directory
            if (webAppDirectory == null) {
                getLog().info("Not scanning webAppDirectory since it's null.");
            } else if (!webAppDirectory.exists()) {
                getLog().info("Not scanning webAppDirectory ("
                        + webAppDirectory.getAbsolutePath()
                        + ") since it doesn't exist.");
            } else {
                getLog().info("Scanning directory: " + webAppDirectory.toString());
                scanDirectory(webAppDirectory, completeResults);
            }

            //Source code

            Set<String> allSources = new HashSet<String>();
            allSources.addAll(project.getCompileSourceRoots());
            allSources.addAll(project.getTestCompileSourceRoots());
            allSources.addAll(project.getScriptSourceRoots());

            for(String path : allSources) {
                File sourceDir = new File(path);
                if(sourceDir.exists()) {
                    getLog().debug("Scanning directory: "+sourceDir.toString());
                    scanDirectory(sourceDir, completeResults);
                }
            }
        }
        catch (Exception e) {
            throw new MojoExecutionException("Unable to scan the file ",e);
        }

        if(breakOnFailure && completeResults.size()>0) {
            throw new MojoFailureException(String.format("%d known vulnerabilitie%s were identified in the JavaScript libraries.",
                    completeResults.size(),
                    completeResults.size()>1?"s":""));
        }
    }


    protected void scanDirectory(File directory,List<JsLibraryResult> results) throws IOException {
        for(File child : directory.listFiles()) {
            if(child.isDirectory()) {
                scanDirectory(child,results);
            }
            else {
                if(isJavaScriptFile(child)) {
                    scanJavaScriptFile(child,results);
                }
            }
        }
    }

    protected boolean isJavaScriptFile(File child) {
        return child.getName().endsWith(".js");
    }

    protected void scanJavaScriptFile(File javascriptFile, List<JsLibraryResult> completeResults) throws IOException {
        getLog().debug("Scanning " + javascriptFile.getCanonicalFile());

        //Scan
        byte[] fileContent = IOUtils.toByteArray(new FileInputStream(javascriptFile));

        ScannerFacade scanner = new ScannerFacade(repo);
        List<JsLibraryResult> results = scanner.scanScript(javascriptFile.getAbsolutePath(),fileContent,0);
        completeResults.addAll(results);

        //Display the results
        if(results.size()>0) {
            getLog().warn(javascriptFile.getName() + " contains a vulnerable JavaScript library.");
            getLog().info("Path: " + javascriptFile.getCanonicalPath());
            for (JsLibraryResult libraryResult : results) {
                JsLibrary lib = libraryResult.getLibrary();
                getLog().info(lib.getName() + " version " + libraryResult.getDetectedVersion() + " is vulnerable.");
                for (String url : libraryResult.getVuln().getInfo()) {
                    getLog().info("+ " + url);
                }
            }
        }

    }
}
