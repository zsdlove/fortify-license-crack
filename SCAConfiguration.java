package com.fortify.sca.cmd;

import com.fortify.licensing.Capability;
import com.fortify.licensing.LicenseException;
import com.fortify.licensing.Licensing;
import com.fortify.licensing.UnlicensedCapabilityException;
import com.fortify.logging.ILogger;
import com.fortify.logging.ILoggerMin.Level;
import com.fortify.logging.ILoggerMin.Marker;
import com.fortify.messaging.Localization;
import com.fortify.messaging.MessageManager;
import com.fortify.sca.analyzer.dotnet.winforms.ComplexDataBindingExpander;
import com.fortify.sca.analyzer.dotnet.winforms.MessageLoopExpander;
import com.fortify.sca.analyzer.dotnet.winforms.SimpleDataBindingExpander;
import com.fortify.sca.cmd.CommandLine.PrintAllOptions;
import com.fortify.sca.cmd.CommandLine.ShowRuntimeProperties;
import com.fortify.sca.cmd.MavenDirectives.AddModule;
import com.fortify.sca.cmd.MavenDirectives.BuildClassPath;
import com.fortify.sca.cmd.MavenDirectives.PurgeClassPath;
import com.fortify.sca.cmd.MavenDirectives.ShowClassPath;
import com.fortify.sca.cmd.MavenDirectives.ShowModule;
import com.fortify.sca.cmd.cparse.SCAQualifierGroup;
import com.fortify.sca.metadata.ExportBuildSession;
import com.fortify.sca.metadata.ImportBuildSession;
import com.fortify.sca.metadata.BuildSession.MakeMobile;
import com.fortify.sca.metadata.BuildSession.ShowBinaries;
import com.fortify.sca.metadata.BuildSession.ShowBuildIDs;
import com.fortify.sca.metadata.BuildSession.ShowBuildTree;
import com.fortify.sca.metadata.BuildSession.ShowBuildWarnings;
import com.fortify.sca.metadata.BuildSession.ShowFiles;
import com.fortify.sca.metadata.BuildSession.ShowLoc;
import com.fortify.sca.nst.transformer.AltcallTransformer;
import com.fortify.sca.nst.transformer.CallsPropertyTransformer;
import com.fortify.sca.nst.transformer.CppExceptionTransformer;
import com.fortify.sca.nst.transformer.DotNetCABInjectionTransformer;
import com.fortify.sca.nst.transformer.DotnetEnumBoxingTransformer;
import com.fortify.sca.nst.transformer.ELTransformingVisitorAdapter;
import com.fortify.sca.nst.transformer.ELVisibilityTransform;
import com.fortify.sca.nst.transformer.InliningJSPTransformer;
import com.fortify.sca.nst.transformer.JSPTagCallRewriter;
import com.fortify.sca.nst.transformer.PythonThisTransformer;
import com.fortify.sca.nst.transformer.StateInjectionTransformer;
import com.fortify.sca.nst.transformer.TransformerProcessor;
import com.fortify.sca.nst.transformer.WicketAllocationTransformer;
import com.fortify.sca.nst.transformer.WicketPropertyModelTransformer;
import com.fortify.sca.rules.RuleUtils;
import com.fortify.sca.rules.validation.RulePackValidator;
import com.fortify.sca.util.SCAPropertyKeys;
import com.fortify.scadev.rulegen.RuleGenerator;
import com.fortify.util.SystemUtil;
import com.fortify.util.Util;
import com.fortify.util.SCARunner.AbstractSCAExec;
import com.fortify.util.cmdline.Qualifier.Arg;
import com.fortify.util.cmdline.Qualifier.Group;
import com.fortify.util.cmdline.Qualifier.Arg.Helpers;
import com.fortify.util.cmdline.Qualifier.Arg.Path;
import com.fortify.util.cmdline.Qualifier.Arg.Single;
import com.fortify.util.cmdline.Qualifier.Arg.Path.Type;
import java.io.File;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Properties;

public class SCAConfiguration extends SharedConfiguration {
    static ILogger logger = MessageManager.getLogger(SCAConfiguration.class);
    private static final String CMDLINE_HELP_FILE = "messages/cmdline_help.txt";
    private static final String CMDLINE_SHORT_HELP_FILE = "messages/cmdline_help_short.txt";
    private static final Capability SCA_ANALYSIS = new Capability("SCA-Analysis", 1627);
    private static final Capability DEVINSPECT = new Capability("DevInspect", 1627);
    private static final String SCA_FINDBUGS_FILTER = "resources/sca-findbugs-filter.xml";
    private static final Single ANALYZER_OPTIONS;
    private static final Group SCA_QUALIFIERS;
    private static final List<String> knownAnalyzers;

    public SCAConfiguration() {
    }

    public Group getCommandLineQualifiers() {
        return new Group(new Group[]{SHARED_QUALIFIERS, SCA_QUALIFIERS});
    }

    public InputStream getFindbugsFilterContent() {
        return this.getClass().getClassLoader().getResourceAsStream("resources/sca-findbugs-filter.xml");
    }

    private void verifyDevinspectToken(String token) throws LicenseException {
        Date[] dates = new Date[5];
        Calendar cal = Calendar.getInstance();
        dates[0] = cal.getTime();

        for(int i = 1; i < 5; ++i) {
            cal.add(12, -1);
            dates[i] = cal.getTime();
        }

        String[] tokens = AbstractSCAExec.generateDevinspectTokens(dates, DEVINSPECT);
        String[] var5 = tokens;
        int var6 = tokens.length;

        for(int var7 = 0; var7 < var6; ++var7) {
            String candidate = var5[var7];
            if (candidate.equals(token)) {
                return;
            }
        }

        throw new UnlicensedCapabilityException(DEVINSPECT);
    }

    public void initialize() {

        if (!CommandLine.checkProperty(SCAPropertyKeys.PK_DISABLE_JSP_INLINING)) {
            TransformerProcessor.registerTransformer(new InliningJSPTransformer());
        }

        TransformerProcessor.registerTransformer(new JSPTagCallRewriter());
        TransformerProcessor.registerTransformer(new ELTransformingVisitorAdapter());
        TransformerProcessor.registerTransformer(new CppExceptionTransformer());
        TransformerProcessor.registerTransformer(new DotnetEnumBoxingTransformer());
        TransformerProcessor.registerTransformer(new DotNetCABInjectionTransformer());
        RuleGenerator.registerTransformer();
        if (CommandLine.checkProperty(CommandLine.PK_WINFORMS_TRANSFORM_DATA_BINDINGS, true)) {
            logger.log(Level.DEBUG, Marker.LOG, () -> {
                return "Enabling code generation: Data binding";
            });
            TransformerProcessor.registerTransformer(new SimpleDataBindingExpander());
        }

        if (CommandLine.checkProperty(CommandLine.PK_WINFORMS_TRANSFORM_STATE_INJECTIONS)) {
            logger.log(Level.DEBUG, Marker.LOG, () -> {
                return "Enabling code generation: State injections";
            });
            TransformerProcessor.registerTransformer(new StateInjectionTransformer());
        }

        if (CommandLine.checkProperty(CommandLine.PK_WINFORMS_TRANSFORM_MESSAGES_LOOPS, true)) {
            logger.log(Level.DEBUG, Marker.LOG, () -> {
                return "Enabling code generation: Event loops";
            });
            TransformerProcessor.registerTransformer(new MessageLoopExpander());
        }

        if (CommandLine.checkProperty(SCAPropertyKeys.PK_WINFORMS_TRANSFORM_CHANGE_NOTIFICATION_PATTERN, true)) {
            logger.log(Level.DEBUG, Marker.LOG, () -> {
                return "Enabling change notification transformer.";
            });
            TransformerProcessor.registerTransformer(new ComplexDataBindingExpander());
        }

        if (CommandLine.checkProperty(CommandLine.PK_CAB_ENABLE_STATE_MAP1)) {
            TransformerProcessor.registerTransformer(new StateInjectionTransformer());
        }

        TransformerProcessor.registerTransformer(new AltcallTransformer());
        TransformerProcessor.registerTransformer(new CallsPropertyTransformer());
        TransformerProcessor.registerTransformer(new PythonThisTransformer());
        if (CommandLine.checkProperty(CommandLine.PK_WICKET_ALLOCATION_TRANSFORM, false)) {
            TransformerProcessor.registerTransformer(new WicketAllocationTransformer());
        }

        if (CommandLine.checkProperty(CommandLine.PK_WICKET_PROPERTY_MODEL_TRANSFORM, true)) {
            TransformerProcessor.registerTransformer(new WicketPropertyModelTransformer());
        }

        if (CommandLine.checkProperty(CommandLine.PK_EL_FOR_SPRING_TRANSFORM, true)) {
            TransformerProcessor.registerTransformer(new ELVisibilityTransform());
        }

    }

    public String getApplicationName() {
        return Localization.getLocalString(1641, new Object[0]);
    }

    public String getCommandString() {
        return "sourceanalyzer";
    }

    public String getExecutablePath() {
        return "bin" + File.separator + this.getCommandString();
    }

    public File getLogFile() {
        String logFile = CommandLine.getProperty(SCAPropertyKeys.PK_LOG_FILE);
        return logFile == null ? new File(this.getDataDirectory(), "log" + File.separator + "sca.log") : new File(logFile);
    }

    public String getCommandlineHelpMessageFile() {
        return "messages/cmdline_help.txt";
    }

    public String getCommandlineShortHelpMessageFile() {
        return "messages/cmdline_help_short.txt";
    }


    public Properties getDefaultProperties() {
        Properties result = super.getDefaultProperties();
        result.setProperty(SCAPropertyKeys.PK_JDK_VERSION.key, "1.8");
        result.setProperty(SCAPropertyKeys.PK_DEFAULT_ANALYZERS.key, "semantic:dataflow:controlflow:nullptr:configuration:content:structural:buffer");
        result.setProperty(SCAPropertyKeys.PK_ANT_COMPILER_CLASS.key, "com.fortify.dev.ant.SCACompiler");
        result.setProperty(SCAPropertyKeys.PK_COLLECT_STATS.key, "true");
        result.setProperty(SCAPropertyKeys.PK_BYTECODE_PREVIEW.key, "true");
        return result;
    }

    public List<String> getKnownAnalyzers() {
        return knownAnalyzers;
    }

    public boolean loadScaProperties() {
        return true;
    }


    public TrimmedProperties getSystemProperties() {
        return new TrimmedProperties(SystemUtil.getProperties());
    }

    static {
        ANALYZER_OPTIONS = Helpers.PEnumC(CommandLine.ANALYZERS);
        SCAQualifierGroup g = new SCAQualifierGroup();
        g.addA("filter", SCAPropertyKeys.PK_FILTER_FILE, Helpers.PList(Helpers.PReadFile));
        g.addA("source-archive", SCAPropertyKeys.PK_SRC_ARCHIVE, Helpers.PWriteFile);
        g.addA("disable-source-rendering", SCAPropertyKeys.PK_FPR_DISABLE_SRC_HTML, (Arg)null);
        g.addA("disable-source-bundling", SCAPropertyKeys.PK_FPR_DISABLE_SRC, (Arg)null);
        g.addA("disable-metatable", SCAPropertyKeys.PK_FPR_DISABLE_METATABLE, (Arg)null);
        g.addQ("force", SCAPropertyKeys.PK_FORCE, (Arg)null);
        g.addA("exit-code-level", SCAPropertyKeys.PK_EXIT_CODE_LEVEL, Helpers.PRaw);
        g.addA("analyzers", SCAPropertyKeys.PK_DEFAULT_ANALYZERS, Helpers.PRaw);
        g.addA("enable-analyzer", SCAPropertyKeys.PK_ENABLE_ANALYZER, Helpers.PList(ANALYZER_OPTIONS));
        g.addA("disable-analyzer", SCAPropertyKeys.PK_DISABLE_ANALYZER, Helpers.PList(ANALYZER_OPTIONS));
        g.addA("format", SCAPropertyKeys.PK_RENDERER, Helpers.PEnum(new String[]{"fvdl", "fvdl-zip", "text", "fpr", "auto"}));
        g.addD("show-runtime-properties", new ShowRuntimeProperties());
        g.addD("list-options", new PrintAllOptions());
        g.addA("validate", SCAPropertyKeys.PK_VALIDATE, (Arg)null);
        g.addA((String[])L(new String[]{"bin", "binary-name"}), SCAPropertyKeys.PK_BINARY_NAME, Helpers.PList(Helpers.PRaw, Util.literalRegex(File.pathSeparator), File.pathSeparator));
        g.addD("make-mobile", new MakeMobile());
        g.addD("export-build-session", new ExportBuildSession(), Helpers.PWriteFile);
        g.addD("import-build-session", new ImportBuildSession(), Helpers.PReadFile);
        g.addD("validate-rules", new RulePackValidator());
        g.addQ("group-id", SCAPropertyKeys.PK_MAVEN_GROUP_ID, Helpers.PRaw);
        g.addQ("artifact-id", SCAPropertyKeys.PK_MAVEN_ARTIFACT_ID, Helpers.PRaw);
        g.addD("add-module", new AddModule());
        g.addD("show-module", new ShowModule());
        g.addD("build-class-path", new BuildClassPath());
        g.addD("show-class-path", new ShowClassPath());
        g.addD("purge-class-path", new PurgeClassPath());
        g.addA("quick", SCAPropertyKeys.PK_QUICK_SCAN_MODE, (Arg)null);
        g.addA("project-template", SCAPropertyKeys.PK_PROJECT_TEMPLATE, Helpers.PReadFile);
        g.addQ((String[])L(new String[]{"c", "run-compiler"}), SCAPropertyKeys.PK_RUNCOMPILER, (Arg)null);
        g.addQ("nc", SCAPropertyKeys.PK_NO_RUNCOMPILER, (Arg)null);
        g.addQ("noextension-type", SCAPropertyKeys.PK_NOEXTENSION_TYPE, Helpers.PRaw);
        g.addA("append", SCAPropertyKeys.PK_OUTPUT_APPEND, (Arg)null);
        g.addA("no-default-rules", SCAPropertyKeys.PK_NO_DEFAULT_RULES, (Arg)null);
        g.addA("ruby-on-rails", SCAPropertyKeys.PK_RUBY_ON_RAILS, (Arg)null);
        g.addA("no-default-source-rules", SCAPropertyKeys.PK_NO_DEFAULT_SOURCE_RULES, (Arg)null);
        g.addA("no-default-sink-rules", SCAPropertyKeys.PK_NO_DEFAULT_SINK_RULES, (Arg)null);
        g.addA("no-default-issue-rules", SCAPropertyKeys.PK_NO_DEFAULT_ISSUE_RULES, (Arg)null);
        g.addA("disable-default-rule-type", SCAPropertyKeys.PK_DISABLED_DEFAULT_RULE_TYPES, Helpers.PList(Helpers.PRaw));
        g.addQ("disable-funptr-analysis", SCAPropertyKeys.PK_DISABLE_FUNTPR, (Arg)null);
        g.addA("results-as-available", SCAPropertyKeys.PK_RESULTS_AS_AVAILABLE, (Arg)null);
        g.addA("html-report", SCAPropertyKeys.PK_HTML_REPORT, (Arg)null);
        g.addQ("flex-libraries", SCAPropertyKeys.PK_FLEX_LIBRARIES, Helpers.PList(new Path(Type.Any, false)));
        g.addQ("flex-namespaces", SCAPropertyKeys.PK_FLEX_NAMESPACES, Helpers.PRaw);
        g.addQ("flex-sdk-root", SCAPropertyKeys.PK_FLEX_SDK_ROOT, Helpers.PReadDir);
        g.addQ("flex-source-roots", SCAPropertyKeys.PK_FLEX_SOURCE_ROOTS, Helpers.PList(new Path(Type.Any, false)));
        g.addQ("source-base-dir", SCAPropertyKeys.PK_SOURCE_BASE_DIR, Helpers.PReadDir);
        g.addQ("copydirs", CommandLine.PK_COBOL_COPY_DIRS, Helpers.PList(new Path(Type.Any, false)));
        g.addQ("copy-extensions", CommandLine.PK_COBOL_COPY_EXTENSIONS, Helpers.PList(new Path(Type.Any, false)));
        g.addQ("fixed-format", SCAPropertyKeys.PK_COBOL_FIXED_FORMAT, (Arg)null);
        g.addQ("ruby-path", CommandLine.PK_RUBY_LIBRARY_PATHS, Helpers.PList(new Path(Type.Any, false)));
        g.addQ("rubygem-path", CommandLine.PK_RUBY_GEM_PATHS, Helpers.PList(new Path(Type.Any, false)));
        g.addQ("abap-includes", CommandLine.PK_ABAP_INCLUDES, Helpers.PList(new Path(Type.Any, false)));
        g.addQ("sql-language", SCAPropertyKeys.PK_SQL_LANGUAGE, Helpers.PRaw);
        g.addA("fvdl-no-descriptions", SCAPropertyKeys.PK_FVDL_DISABLE_DESCRIPTIONS, (Arg)null);
        g.addA("fvdl-no-progdata", SCAPropertyKeys.PK_FVDL_DISABLE_PROGRAMDATA, (Arg)null);
        g.addA("fvdl-no-snippets", SCAPropertyKeys.PK_FVDL_DISABLE_SNIPPETS, (Arg)null);
        g.addA("fvdl-no-enginedata", SCAPropertyKeys.PK_FVDL_DISABLE_ENGINEDATA, (Arg)null);
        g.addD("show-files", new ShowFiles());
        g.addD("show-build-ids", new ShowBuildIDs());
        g.addD("show-binaries", new ShowBinaries());
        g.addD("show-build-tree", new ShowBuildTree());
        g.addD("show-build-warnings", new ShowBuildWarnings());
        g.addD("show-loc", new ShowLoc());
        g.addQ("build-migration-map", SCAPropertyKeys.PK_MIGRATION_FILE, Helpers.PReadFile);
        g.addQ("appserver", SCAPropertyKeys.PK_APPSERVER, Helpers.PRaw);
        g.addQ("appserver-home", SCAPropertyKeys.PK_APPSERVER_HOME, Helpers.PReadDir);
        g.addQ("appserver-version", SCAPropertyKeys.PK_APPSERVER_VERSION, Helpers.PRaw);
        g.addQ("generated-sources", SCAPropertyKeys.PK_JSP_GENERATED_SOURCES, Helpers.PReadDir);
        g.addQ("document-root", SCAPropertyKeys.PK_JSP_DOCUMENT_ROOT, Helpers.PReadDir);
        g.addQ("disable-filtering", SCAPropertyKeys.PK_DISABLE_FILTER, (Arg)null);
        g.addQ("use-cpfe441", SCAPropertyKeys.PK_USE_CPFE_441, (Arg)null);
        g.addQ("jsp-as-top-level", SCAPropertyKeys.PK_JSP_AS_TOP_LEVEL, (Arg)null);
        g.addQ("findbugs", SCAPropertyKeys.PK_ENABLE_FINDBUGS, (Arg)null);
        g.addQ("java-build-dir", SCAPropertyKeys.PK_JAVA_BUILD_DIRECTORIES, Helpers.PList(Helpers.PReadDir));
        g.addQ("findbugs-heap-size", SCAPropertyKeys.PK_FINDBUGS_MAXHEAP, Helpers.PRaw);
        RuleGenerator.addCmdLineOptions(g);
        g.addQ("vsversion", SCAPropertyKeys.PK_VS_VERSION, Helpers.PEnum(new String[]{"7.1", "8.0", "9.0", "10.0", "11.0", "12.0", "14.0"}));
        g.addQ("dotnet-version", SCAPropertyKeys.PK_DOTNET_VERSION, Helpers.PRaw);
        g.addQ("dotnet-std-version", SCAPropertyKeys.PK_DOTNET_STD_VERSION, Helpers.PRaw);
        g.addQ("dotnet-core-version", SCAPropertyKeys.PK_DOTNET_CORE_VERSION, Helpers.PRaw);
        g.addQ("xamarin-android-version", SCAPropertyKeys.PK_XAMARIN_ANDROID_VERSION, Helpers.PRaw);
        g.addQ("xamarin-ios-version", SCAPropertyKeys.PK_XAMARIN_IOS_VERSION, Helpers.PRaw);
        g.addQ("nuget-cache-dir", SCAPropertyKeys.PK_NUGET_CACHE_DIR, Helpers.PReadDir);
        g.addQ("dotnetwebroot", SCAPropertyKeys.PK_DOTNET_WEBROOT, Helpers.PReadDir);
        g.addQ("dotnet-sources", SCAPropertyKeys.PK_SOURCE_FILES, Helpers.PReadDir);
        g.addQ("dotnet-output-dir", SCAPropertyKeys.PK_DOTNET_OUTPUT_DIR, Helpers.PReadDir);
        g.addQ("dotnet-preproc-symbols", SCAPropertyKeys.PK_DOTNET_PREPROCESSOR_SYMBOLS, Helpers.PRaw);
        g.addQ("dotnet-assembly-name", SCAPropertyKeys.PK_DOTNET_ASSEMBLY_NAME, Helpers.PRaw);
        g.addQ("dotnet-applibs", SCAPropertyKeys.PK_DOTNET_WEB_APPLIBS, Helpers.PRaw);
        g.addQ("aspnetcore", SCAPropertyKeys.PK_DOTNET_NETCORE, (Arg)null);
        g.addQ("dotnet-website", SCAPropertyKeys.PK_DOTNET_WEBSITE, (Arg)null);
        g.addQ("dotnet-codebehind", SCAPropertyKeys.PK_DOTNET_CODEBEHIND, Helpers.PRaw);
        g.addQ("dotnet-shared-files", SCAPropertyKeys.PK_DOTNET_SHARED_FILES, Helpers.PRaw);
        g.addQ("cs-extern-alias", SCAPropertyKeys.PK_DOTNET_ALIAS, Helpers.PRaw);
        g.addQ("vb-root", SCAPropertyKeys.PK_DOTNET_VB_ROOT_NAMESPACE, Helpers.PRaw);
        g.addQ("vb-imports", SCAPropertyKeys.PK_DOTNET_VB_GLOBAL_IMPORTS, Helpers.PList(new Path(Type.Any, false)));
        g.addQ("vb-mytype", SCAPropertyKeys.PK_DOTNET_VB_MYTYPE, Helpers.PRaw);
        g.addQ("vb-compile-options", SCAPropertyKeys.PK_DOTNET_VB_COMPILE_OPTIONS, Helpers.PRaw);
        g.addQ("libdirs-only", SCAPropertyKeys.PK_DOTNET_LIBDIRS_ONLY, (Arg)null);
        g.addQ("xamarin", SCAPropertyKeys.PK_XAMARIN, Helpers.PEnum(new String[]{"android", "ios"}));
        g.addQ("php-source-root", SCAPropertyKeys.PK_PHP_SOURCE_ROOT, Helpers.PReadDir);
        g.addQ("php-version", SCAPropertyKeys.PK_PHP_VERSION, Helpers.PEnum(new String[]{"5.3", "5.4", "5.5", "5.6", "7.0", "7.1"}));
        g.addQ("python-path", SCAPropertyKeys.PK_PYTHON_PATH, Helpers.PList(new Path(Type.Any, false)));
        g.addQ("python-version", SCAPropertyKeys.PK_PYTHON_VERSION, Helpers.PEnum(new String[]{"2", "3"}));
        g.addQ("python-legacy", SCAPropertyKeys.PK_PYTHON_LEGACY, (Arg)null);
        g.addQ("python-warnings-suppression", SCAPropertyKeys.PK_PYTHON_WARNINGS_SUPPRESSION, (Arg)null);
        g.addQ("python-no-file-function-optimization", SCAPropertyKeys.PK_PYTHON_NO_FILE_FUNCTION_OPTIMIZATION, (Arg)null);
        g.addQ("django-template-dirs", SCAPropertyKeys.PK_DJANGO_TEMPLATE_DIRS, Helpers.PList(new Path(Type.Any, false)));
        g.addQ("django-disable-autodiscover", SCAPropertyKeys.PK_DJANGO_DISABLE_AUTODISCOVER, (Arg)null);
        g.addQ("show-python-resolution", SCAPropertyKeys.PK_SHOW_PYTHON_FUNCTION_RESOLUTION, (Arg)null);
        g.addQ("enable-language", SCAPropertyKeys.PK_ENABLED_LANGUAGES, Helpers.PList(Helpers.PEnum(RuleUtils.getLegalLanguageSpecifiers())));
        g.addQ("disable-language", SCAPropertyKeys.PK_DISABLED_LANGUAGES, Helpers.PList(Helpers.PEnum(RuleUtils.getLegalLanguageSpecifiers())));
        g.addA("mt", SCAPropertyKeys.PK_MULTITHREAD_PHASE_ONE, (Arg)null);
        g.addA("j", SCAPropertyKeys.PK_RMI_WORKERS, Helpers.PRaw);
        g.addQ("apex", SCAPropertyKeys.PK_APEX, (Arg)null);
        g.addQ("apex-sobject-path", SCAPropertyKeys.PK_APEX_SOBJECTPATH, Helpers.PReadFile);
        SCA_QUALIFIERS = g;
        knownAnalyzers = Arrays.asList("configuration", "semantic", "dataflow", "controlflow", "content", "structural", "findbugs", "buffer", "nullptr");
    }
}
