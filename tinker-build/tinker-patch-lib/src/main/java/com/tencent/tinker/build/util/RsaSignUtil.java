/*
 * Tencent is pleased to support the open source community by making Tinker available.
 *
 * Copyright (C) 2016 THL A29 Limited, a Tencent company. All rights reserved.
 *
 * Licensed under the BSD 3-Clause License (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 *
 * https://opensource.org/licenses/BSD-3-Clause
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.tencent.tinker.build.util;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import com.tencent.tinker.commons.util.IOHelper;

/**
 * RSA signing for patch packages, replacing the old jarsigner based v1 signing.
 *
 * The whole package content is digested (see {@link #computePackageDigest}) and signed
 * with SHA256withRSA using the private key from the configured keystore. The Base64
 * signature is stored as the {@link #SIGNATURE_ENTRY_NAME} zip entry of the final patch.
 * The runtime counterpart is com.tencent.tinker.loader.shareutil.ShareRsaSignUtil in
 * tinker-android-loader; the digest algorithm must stay in sync with it.
 *
 * Because the digest is content based, the optional 7z repack afterwards does not
 * invalidate the signature.
 */
public final class RsaSignUtil {
    public static final String SIGNATURE_ENTRY_NAME = "assets/package_signature.txt";

    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    private RsaSignUtil() {
    }

    /**
     * Load the RSA private key from a keystore. Both JKS and PKCS12 keystores are
     * supported (some keystores carry a .jks extension while actually being PKCS12).
     */
    public static PrivateKey loadPrivateKey(File keyStoreFile, String storePass, String keyPass, String alias) throws Exception {
        KeyStore keyStore = null;
        Exception jksException = null;
        for (final String type : new String[]{"JKS", "PKCS12"}) {
            InputStream is = null;
            try {
                is = new FileInputStream(keyStoreFile);
                keyStore = KeyStore.getInstance(type);
                keyStore.load(is, storePass.toCharArray());
                break;
            } catch (Exception e) {
                jksException = e;
                keyStore = null;
            } finally {
                IOHelper.closeQuietly(is);
            }
        }
        if (keyStore == null) {
            throw new IOException("load keystore fail: " + keyStoreFile.getAbsolutePath(), jksException);
        }
        final PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyPass.toCharArray());
        if (privateKey == null) {
            throw new IOException("no private key found for alias: " + alias);
        }
        if (!"RSA".equalsIgnoreCase(privateKey.getAlgorithm())) {
            throw new IOException("private key for alias " + alias + " is not a RSA key: " + privateKey.getAlgorithm());
        }
        return privateKey;
    }

    /**
     * Sign the given package: every original entry is copied to the output and the
     * Base64 encoded SHA256withRSA signature of the package content is appended as
     * the {@link #SIGNATURE_ENTRY_NAME} entry.
     */
    public static void signApk(File input, File output, PrivateKey privateKey) throws Exception {
        final byte[] signatureBytes;
        final Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        ZipFile zipFile = null;
        try {
            zipFile = new ZipFile(input);
            signature.update(computePackageDigest(zipFile));
        } finally {
            IOHelper.closeQuietly(zipFile);
        }
        signatureBytes = signature.sign();
        final byte[] signatureEntryContent = Base64.getEncoder().encode(signatureBytes);

        if (output.exists()) {
            output.delete();
        }
        ZipFile in = null;
        ZipOutputStream out = null;
        try {
            in = new ZipFile(input);
            out = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(output)));
            final Enumeration<? extends ZipEntry> entries = in.entries();
            while (entries.hasMoreElements()) {
                final ZipEntry entry = entries.nextElement();
                if (SIGNATURE_ENTRY_NAME.equals(entry.getName())) {
                    continue;
                }
                out.putNextEntry(new ZipEntry(entry.getName()));
                if (!entry.isDirectory()) {
                    out.write(readEntry(in, entry));
                }
                out.closeEntry();
            }
            out.putNextEntry(new ZipEntry(SIGNATURE_ENTRY_NAME));
            out.write(signatureEntryContent);
            out.closeEntry();
        } finally {
            IOHelper.closeQuietly(in);
            IOHelper.closeQuietly(out);
        }
        if (!output.exists()) {
            throw new IOException("Can't Generate signed APK. Please check if your sign info is correct.");
        }
    }

    /**
     * Content based SHA-256 digest of a patch package. Entries are sorted by name;
     * directories and the signature entry are excluded. For each remaining entry the
     * UTF-8 name bytes are fed first, then the raw content bytes.
     *
     * Must stay in sync with the runtime side
     * com.tencent.tinker.loader.shareutil.ShareRsaSignUtil.
     */
    private static byte[] computePackageDigest(ZipFile zipFile) throws Exception {
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        final List<String> names = new ArrayList<>();
        final Enumeration<? extends ZipEntry> entries = zipFile.entries();
        while (entries.hasMoreElements()) {
            final ZipEntry entry = entries.nextElement();
            if (entry.isDirectory()) {
                continue;
            }
            final String name = entry.getName();
            if (SIGNATURE_ENTRY_NAME.equals(name)) {
                continue;
            }
            names.add(name);
        }
        Collections.sort(names);
        for (final String name : names) {
            digest.update(name.getBytes("UTF-8"));
            digest.update(readEntry(zipFile, zipFile.getEntry(name)));
        }
        return digest.digest();
    }

    private static byte[] readEntry(ZipFile zipFile, ZipEntry entry) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        InputStream in = null;
        try {
            in = zipFile.getInputStream(entry);
            final byte[] buffer = new byte[16384];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
        } finally {
            IOHelper.closeQuietly(in);
        }
        return out.toByteArray();
    }
}
