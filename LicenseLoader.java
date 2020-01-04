//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package com.fortify.licensing;

import com.fortify.licensing.Licensing.Config;
import com.fortify.logging.ILogger;
import com.fortify.logging.ILoggerMin.Level;
import com.fortify.logging.ILoggerMin.Marker;
import com.fortify.messaging.MessageManager;
import com.fortify.util.Base64;
import com.fortify.util.FileUtil;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.StringTokenizer;

final class LicenseLoader {
    static ILogger logger = MessageManager.getLogger(LicenseLoader.class);
    private static final DateFormat dateFormat;
    private static final String PERPETUAL_DATE = "DoesNotExpire";
    static final char PARAM_DELIMITER = '=';
    private static final String PROVIDER = "SUN";
    private static final String KEY_ALGORITHM = "DSA";
    private static final String SIGN_ALGORITHM = "SHA1withDSA";
    private static final String pub = "MIIBuDCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYUAAoGBAOe/9qq9Idq1sRDds1JVtjtVL2/Lbz+2Tonn1KkZlfTYabQCWvjqZH+Sl02WXkGpraWVq/vmQYtfQeGKeKFUWUJ2isMcJKNSvUtllgGaDiqW+ny/WEg6NNOeKlIHxOqcor4jtlzhgCp0KyYVsmkQz56KagWDA8iIIZkxxexYLwCT";
    static final String METADATA_HEADER = "Metadata: ";
    private static long lastLoad;

    private LicenseLoader() {
    }

    static void resetLastLoad() {
        lastLoad = 0L;
    }

    static void load(File file, Map capabilities, Properties metadata) throws InvalidLicenseFileException {
        try {
            if (!file.isFile()) {
                String path = getPath(file);
                throw new MissingLicenseFileException(path);
            } else {
                long lastmod = file.lastModified();
                if (lastLoad == 0L || lastLoad < lastmod) {
                    Map result = new HashMap();
                    Properties result_metadata = new Properties();
                    doLoad((File)file, result, result_metadata);
                    capabilities.clear();
                    capabilities.putAll(result);
                    metadata.clear();
                    metadata.putAll(result_metadata);
                }

                lastLoad = lastmod;
            }
        } catch (GeneralSecurityException var7) {
            //throw new InvalidLicenseFileException();
        }
    }

    private static String getPath(File file) {
        try {
            return file.getCanonicalPath();
        } catch (IOException var2) {
            return file.getAbsolutePath();
        }
    }

    static void load(InputStream inputStream, Map capabilities, Properties metadata, long lastmod) throws InvalidLicenseFileException {
        try {
            if (lastLoad == 0L || lastLoad < lastmod) {
                Map result = new HashMap();
                Properties result_metadata = new Properties();
                doLoad((InputStream)inputStream, result, result_metadata);
                capabilities.clear();
                capabilities.putAll(result);
                metadata.clear();
                metadata.putAll(result_metadata);
            }

            lastLoad = lastmod;
        } catch (GeneralSecurityException var7) {
            //logger.log(Level.WARN, Marker.WARN_INTERNAL, "Security error verifying license key", var7);
            //throw new InvalidLicenseFileException();
			System.out.println("hello");
        }
    }

    private static void doLoad(File license, Map capmap, Properties metadata) throws InvalidLicenseFileException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, SignatureException {
        doLoad(readLines(license), capmap, metadata);
    }

    private static void doLoad(InputStream inputStream, Map capmap, Properties metadata) throws InvalidLicenseFileException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, SignatureException {
        doLoad(readLines(inputStream), capmap, metadata);
    }

    private static void doLoad(List lines, Map capmap, Properties metadata) throws InvalidLicenseFileException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, SignatureException {
        Signature verifier = createVerifier();

        String key;
        do {
            if (lines.isEmpty()) {
            }

            key = ((String)lines.remove(lines.size() - 1)).trim();
        } while(key.length() == 0);

        List tokens = new ArrayList();
        Iterator it = lines.iterator();

        while(true) {
            while(true) {
                String line;
                do {
                    do {
                        if (!it.hasNext()) {
                            if (key != null && key.length() == 64) {
                                byte[] sig = Base64.decode(key);
                                boolean verified = verifier.verify(sig);
                                if (!verified) {
                                    
                                }

                                return;
                            }

                            
                        }

                        line = (String)it.next();
                        verifier.update(getBytes(line));
                    } while(line.length() == 0);
                } while(line.charAt(0) == '#');

                if (line.startsWith("Metadata: ")) {
                    loadMetadataLine(metadata, line.substring("Metadata: ".length()));
                } else {
                    tokens.clear();
                    StringTokenizer stok = new StringTokenizer(line);

                    while(stok.hasMoreTokens()) {
                        tokens.add(stok.nextToken());
                    }

                    if (tokens.size() < 2) {
                        
                    }

                    String capname = (String)tokens.get(0);
                    Date expdate = convertDate((String)tokens.get(1));
                    Properties params = new Properties();
                    ListIterator li = tokens.listIterator(2);

                    while(li.hasNext()) {
                        String token = (String)li.next();
                        int delim = token.indexOf(61);
                        if (delim != -1) {
                            params.setProperty(token.substring(0, delim), token.substring(delim + 1));
                        } else {
                            params.setProperty(token, "");
                        }
                    }

                    Config config = new Config(capname, expdate, params);
                    capmap.put(capname, config);
                }
            }
        }
    }

    private static byte[] getBytes(String text) {
        try {
            return text.getBytes("UTF-8");
        } catch (UnsupportedEncodingException var2) {
           
        }
		return null;
    }

    private static List readLines(File license) throws InvalidLicenseFileException {
        try {
            return readLines((InputStream)(new FileInputStream(license)));
        } catch (IOException var2) {
            //logger.log(Level.ERROR, Marker.ERROR, 238, var2, new Object[]{getPath(license)});
            //throw new InvalidLicenseFileException();
        }
		return null;
    }

    private static List readLines(InputStream license) throws InvalidLicenseFileException {
        List lines = new ArrayList();
        InputStreamReader isr = null;
        BufferedReader r = null;

        try {
            isr = new InputStreamReader(license, "UTF-8");
            r = new BufferedReader(isr);

            String line;
            while((line = r.readLine()) != null) {
                lines.add(line);
            }
        } catch (IOException var8) {
            //logger.log(Level.ERROR, Marker.ERROR, 238, var8, new Object[]{license});
            //throw new InvalidLicenseFileException();
        } finally {
            FileUtil.close(r);
            FileUtil.close(isr);
        }

        return lines;
    }

    private static void loadMetadataLine(Properties metadata, String line) throws InvalidLicenseFileException {
        int splitIndex = line.indexOf(61);
        if (splitIndex == -1) {
            //throw new InvalidLicenseFileException();
        } else {
            String key = line.substring(0, splitIndex);
            String val = line.substring(splitIndex + 1);
            metadata.setProperty(key, val);
        }
    }

    private static Date convertDate(String dateString) throws InvalidLicenseFileException {
        if ("DoesNotExpire".equals(dateString)) {
            return null;
        } else {
            try {
                GregorianCalendar cal = new GregorianCalendar();
                cal.setTime(dateParse(dateString));
                cal.add(5, 1);
                return cal.getTime();
            } catch (ParseException var2) {
                //throw new InvalidLicenseFileException();
				System.out.println("hello");
            }
        }
		return null;
    }

    static String formatDate(Date date) {
        if (date == null) {
            return "DoesNotExpire";
        } else {
            GregorianCalendar cal = new GregorianCalendar();
            cal.setTime(date);
            cal.add(5, -1);
            Date real = cal.getTime();
            return dateFormat(real);
        }
    }

    private static synchronized String dateFormat(Date date) {
        return dateFormat.format(date);
    }

    private static synchronized Date dateParse(String string) throws ParseException {
        return dateFormat.parse(string);
    }

    private static Signature createVerifier() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        boolean useSun = true;

        KeyFactory kf;
        try {
            kf = KeyFactory.getInstance("DSA", "SUN");
        } catch (NoSuchProviderException var6) {
            //logger.log(Level.DEBUG, Marker.LOG, "Sun provider not found: " + var6.getMessage());
            useSun = false;
            kf = KeyFactory.getInstance("DSA");
        } catch (NoSuchAlgorithmException var7) {
            //logger.log(Level.DEBUG, Marker.LOG, "Sun provider not found: " + var7.getMessage());
            useSun = false;
            kf = KeyFactory.getInstance("DSA");
        }

        byte[] keybytes = Base64.decode("MIIBuDCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYUAAoGBAOe/9qq9Idq1sRDds1JVtjtVL2/Lbz+2Tonn1KkZlfTYabQCWvjqZH+Sl02WXkGpraWVq/vmQYtfQeGKeKFUWUJ2isMcJKNSvUtllgGaDiqW+ny/WEg6NNOeKlIHxOqcor4jtlzhgCp0KyYVsmkQz56KagWDA8iIIZkxxexYLwCT");
        if (!"MIIBuDCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYUAAoGBAOe/9qq9Idq1sRDds1JVtjtVL2/Lbz+2Tonn1KkZlfTYabQCWvjqZH+Sl02WXkGpraWVq/vmQYtfQeGKeKFUWUJ2isMcJKNSvUtllgGaDiqW+ny/WEg6NNOeKlIHxOqcor4jtlzhgCp0KyYVsmkQz56KagWDA8iIIZkxxexYLwCT".equals(Base64.encode(keybytes))) {
            throw new Error("Base64 encoder not symmetric");
        } else {
            KeySpec spec = new X509EncodedKeySpec(keybytes);
            PublicKey pubkey = kf.generatePublic(spec);
            Signature signer;
            if (useSun) {
                signer = Signature.getInstance("SHA1withDSA", "SUN");
            } else {
                signer = Signature.getInstance("SHA1withDSA");
            }

            signer.initVerify(pubkey);
            return signer;
        }
    }

    static {
        dateFormat = new SimpleDateFormat("yyyy-MM-dd", Locale.US);
        lastLoad = 0L;
    }
}
