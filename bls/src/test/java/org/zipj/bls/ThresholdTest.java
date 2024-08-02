/**
 * Copyright (c) 2022-present, Dash Core Group
 * <p>
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

package org.zipj.bls;

import org.zipj.bls.Utils.ByteVector;
import org.zipj.bls.Utils.ByteVectorList;
import org.junit.Test;

import java.util.ArrayList;

import static org.zipj.bls.ZIPJBLS.privateKeyShare;
import static org.zipj.bls.ZIPJBLS.publicKeyShare;
import static org.zipj.bls.ZIPJBLS.sign;
import static org.zipj.bls.ZIPJBLS.signatureShare;
import static org.zipj.bls.ZIPJBLS.verify;
import static org.zipj.bls.Entropy.getRandomSeed;
import static org.junit.Assert.assertTrue;

public class ThresholdTest extends BaseTest {
    @Test
    public void thresholdSignatures_secretKeyShares() {

        int m = 3;
        int n = 5;

        PrivateKeyVector sks = new PrivateKeyVector(0, new PrivateKey());
        G1ElementVector pks = new G1ElementVector();
        G2ElementVector sigs = new G2ElementVector();
        ArrayList<byte[]> ids = new ArrayList<>();
        PrivateKeyVector skShares = new PrivateKeyVector();
        G1ElementVector pkShares = new G1ElementVector();
        G2ElementVector sigShares = new G2ElementVector();

        byte[] vecHash = getRandomSeed(32);

        for (int i = 0; i < n; i++) {
            ids.add(getRandomSeed(32));
        }

        for (int i = 0; i < m; i++) {
            byte[] buf = getRandomSeed(PrivateKey.PRIVATE_KEY_SIZE);

            PrivateKey sk = PrivateKey.fromBytes(buf, true);
            sks.add(sk);
            pks.add(sk.getG1Element());
            sigs.add(sign(sk, vecHash));
            assertTrue(verify(sk.getG1Element(), vecHash, sigs.get(sigs.size() - 1)));
        }

        G2Element sig = sign(sks.get(0), vecHash);

        assertTrue(verify(pks.get(0), vecHash, sig));

        for (int i = 0; i < n; i++) {
            PrivateKey skShare = privateKeyShare(sks, ids.get(i));
            G1Element pkShare = publicKeyShare(pks, ids.get(i));
            G2Element sigShare1 = signatureShare(sigs, ids.get(i));
            assertObjectEquals(skShare.getG1Element(), pkShare);

            G2Element sigShare2 = sign(skShare, vecHash);
            assertObjectEquals(sigShare1, sigShare2);
            assertTrue(verify(pkShare, vecHash, sigShare1));

            skShares.add(skShare);
            pkShares.add(pkShare);
            sigShares.add(sigShare1);
        }

        PrivateKeyVector rsks = new PrivateKeyVector();
        G1ElementVector rpks = new G1ElementVector();
        G2ElementVector rsigs = new G2ElementVector();
        ByteVectorList rids = new ByteVectorList();
        for (int i = 0; i < 2; i++) {
            rsks.add(skShares.get(i));
            rpks.add(pkShares.get(i));
            rsigs.add(sigShares.get(i));
            rids.add(ids.get(i));
        }
        PrivateKey recSk = ZIPJBLS.privateKeyRecover(rsks, rids);
        G1Element recPk = ZIPJBLS.publicKeyRecover(rpks, rids);
        G2Element recSig = ZIPJBLS.signatureRecover(rsigs, rids);
        assertObjectNotEquals(recSk, sks.get(0));
        assertObjectNotEquals(recPk, pks.get(0));
        assertObjectNotEquals(recSig, sig);

        rsks.add(skShares.get(2));
        rpks.add(pkShares.get(2));
        rsigs.add(sigShares.get(2));
        rids.add(new ByteVector(ids.get(2)));
        recSk = ZIPJBLS.privateKeyRecover(rsks, rids);
        recPk = ZIPJBLS.publicKeyRecover(rpks, rids);
        recSig = ZIPJBLS.signatureRecover(rsigs, rids);
        assertObjectEquals(recSk, sks.get(0));
        assertObjectEquals(recPk, pks.get(0));
        assertObjectEquals(recSig, sig);
    }
}
