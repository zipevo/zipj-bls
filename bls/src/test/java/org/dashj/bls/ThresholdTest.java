package org.dashj.bls;

import org.junit.Test;

import java.util.ArrayList;

import static org.dashj.bls.v1.DASHJBLS.objectEquals;
import static org.dashj.bls.v1.DASHJBLS.privateKeyRecover;
import static org.dashj.bls.v1.DASHJBLS.privateKeyShare;
import static org.dashj.bls.v1.DASHJBLS.publicKeyRecover;
import static org.dashj.bls.v1.DASHJBLS.publicKeyShare;
import static org.dashj.bls.v1.DASHJBLS.sign;
import static org.dashj.bls.v1.DASHJBLS.signatureRecover;
import static org.dashj.bls.v1.DASHJBLS.signatureShare;
import static org.dashj.bls.v1.DASHJBLS.verify;
import static org.dashj.bls.Entropy.getRandomSeed;
import static org.dashj.bls.Entropy.getRandomSeedAsUint8Vector;
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

        //Uint8Vector vecHash = getRandomSeedAsUint8Vector(32);
        byte[] vecHash = getRandomSeed(32);

        for (int i = 0; i < n; i++) {
            ids.add(getRandomSeed(32));
        }

        for (int i = 0; i < m; i++) {
            Uint8Vector buf = getRandomSeedAsUint8Vector(PrivateKey.PRIVATE_KEY_SIZE);

            PrivateKey sk = PrivateKey.fromByteVector(buf, true);
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
            assertTrue(DASHJBLS.objectEquals(skShare.getG1Element(), pkShare));

            G2Element sigShare2 = sign(skShare, vecHash);
            assertTrue(objectEquals(sigShare1, sigShare2));
            assertTrue(verify(pkShare, vecHash, sigShare1));

            skShares.add(skShare);
            pkShares.add(pkShare);
            sigShares.add(sigShare1);
        }

        PrivateKeyVector rsks = new PrivateKeyVector();
        G1ElementVector rpks = new G1ElementVector();
        G2ElementVector rsigs = new G2ElementVector();
        ArrayList<byte[]> rids = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            rsks.add(skShares.get(i));
            rpks.add(pkShares.get(i));
            rsigs.add(sigShares.get(i));
            rids.add(ids.get(i));
        }
            /*PrivateKey recSk = privateKeyRecover(rsks, rids);
            G1Element recPk = publicKeyRecover(rpks, rids);
            G2Element recSig = signatureRecover(rsigs, rids);
            assertTrue(!objectEquals(recSk, sks.get(0)));
            assertTrue(!objectEquals(recPk, pks.get(0)));
            assertTrue(!objectEquals(recSig, sig));

            rsks.add(skShares.get(2));
            rpks.add(pkShares.get(2));
            rsigs.add(sigShares.get(2));
            rids.add(ids[2]);
            recSk = privateKeyRecover(rsks, rids);
            recPk = publicKeyRecover(rpks, rids);
            recSig = signatureRecover(rsigs, rids);
            assertTrue(objectEquals(recSk, sks.get(0)));
            assertTrue(objectEquals(recPk, pks.get(0)));
            assertTrue(objectEquals(recSig, sig));*/
    }
}
