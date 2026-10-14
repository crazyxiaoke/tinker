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

package com.tencent.tinker.loader.shareutil;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.util.Base64;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * RSA signature verification for patch packages.
 *
 * The patch builder signs the whole patch package with the RSA private key from the
 * configured keystore and stores the Base64 signature in the {@link #SIGNATURE_ENTRY_NAME}
 * zip entry. The digest is content based: every entry (sorted by name, directories and the
 * signature entry itself excluded) feeds the SHA-256 digest with its UTF-8 name bytes first
 * and its raw content bytes second. This keeps the digest reproducible across zip tools,
 * including the optional 7z repack.
 *
 * NOTE: the digest algorithm here must stay in sync with
 * com.tencent.tinker.build.util.RsaSignUtil in tinker-patch-lib.
 */
public final class ShareRsaSignUtil {
    private static final String TAG = "Tinker.RsaSignUtil";

    public static final String SIGNATURE_ENTRY_NAME   = "assets/package_signature.txt";
    public static final String PUBLIC_KEY_ASSET_NAME  = "assets/tinker_patch_rsa_public_key.txt";

    private static final String SIGNATURE_ALGORITHM   = "SHA256withRSA";
    private static final String KEY_ALGORITHM         = "RSA";

    private ShareRsaSignUtil() {
    }

    /**
     * Load the RSA public key from the base apk file on disk. We deliberately read the raw
     * apk instead of AssetManager, because after a patch is loaded the runtime assets may
     * come from the patched resources, which must not be able to replace the trust anchor.
     */
    public static PublicKey loadPublicKeyFromBaseApk(Context context) throws Exception {
        final ApplicationInfo appInfo = context.getPackageManager()
                .getPackageInfo(context.getPackageName(), 0).applicationInfo;
        ZipFile zipFile = null;
        try {
            zipFile = new ZipFile(appInfo.sourceDir);
            final ZipEntry entry = zipFile.getEntry(PUBLIC_KEY_ASSET_NAME);
            if (entry == null) {
                throw new IOException(PUBLIC_KEY_ASSET_NAME + " not found in base apk");
            }
            final String base64 = new String(readEntry(zipFile, entry), "UTF-8").replaceAll("\\s", "");
            final byte[] keyBytes = Base64.decode(base64, Base64.DEFAULT);
            return KeyFactory.getInstance(KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(keyBytes));
        } finally {
            SharePatchFileUtil.closeQuietly(zipFile);
        }
    }

    /**
     * Verify the RSA signature entry of a patch package against its content digest.
     * Any failure (missing signature entry, io error, bad signature) results in false.
     */
    public static boolean verifyPatchSignature(File patchFile, PublicKey publicKey) {
        ZipFile zipFile = null;
        try {
            zipFile = new ZipFile(patchFile);
            final ZipEntry sigEntry = zipFile.getEntry(SIGNATURE_ENTRY_NAME);
            if (sigEntry == null) {
                ShareTinkerLog.e(TAG, "signature entry %s not found in %s", SIGNATURE_ENTRY_NAME, patchFile.getAbsolutePath());
                return false;
            }
            final String base64 = new String(readEntry(zipFile, sigEntry), "UTF-8").replaceAll("\\s", "");
            final byte[] signatureBytes = Base64.decode(base64, Base64.DEFAULT);
            final Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(computePackageDigest(zipFile));
            return signature.verify(signatureBytes);
        } catch (Throwable e) {
            ShareTinkerLog.e(TAG, "verify patch signature fail: " + patchFile.getAbsolutePath(), e);
            return false;
        } finally {
            SharePatchFileUtil.closeQuietly(zipFile);
        }
    }

    /**
     * Content based SHA-256 digest of a patch package. Entries are sorted by name;
     * directories and the signature entry are excluded. For each remaining entry the
     * UTF-8 name bytes are fed first, then the raw content bytes.
     */
    private static byte[] computePackageDigest(ZipFile zipFile) throws IOException, NoSuchAlgorithmException {
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
            SharePatchFileUtil.closeQuietly(in);
        }
        return out.toByteArray();
    }
}
