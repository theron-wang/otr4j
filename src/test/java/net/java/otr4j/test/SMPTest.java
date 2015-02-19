
package net.java.otr4j.test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import net.java.otr4j.OtrException;
import net.java.otr4j.session.Session;
import net.java.otr4j.test.dummyclient.DummyClient;

import org.junit.Test;

/**
 * test that Socialist Millionaire Protocol verification is working
 *
 * @author Hans-Christoph Steiner
 */
public class SMPTest {

    String snippets[] = {
            // TODO these currently cause an Exception when used as question:
            // "nullshere:\0\0andhere:\0",
            // "tabbackslashT\t",
            // "backslashR\r",
            // "NEWLINE\n",
            "",
            "བོད་རིགས་ཀྱི་བོད་སྐད་བརྗོད་པ་དང་ བོད་རིགས་མང་ཆེ་བ་ནི་ནང་ཆོས་བྱེད་པ་དང་",
            "تبتی قوم (Tibetan people)",
            "Учените твърдят, че тибетците нямат",
            "Câung-cŭk (藏族, Câung-ngṳ̄: བོད་པ་)",
            "チベット系民族（チベットけいみんぞく）",
            "原始汉人与原始藏缅人约在公元前4000年左右分开。",
            "Տիբեթացիներ (ինքնանվանումը՝ պյոբա),",
            "... Gezginci olarak",
            "شْتَن Xotan",
            "Tibeťané jsou",
            "ئاچاڭ- تىبەت مىللىتى",
            "Miscellaneous Symbols and Pictographs[1][2]Official Unicode Consortium code chart (PDF)",
            "Royal Thai (ราชาศัพท์)",
            "טיילאנדיש123 (ภาษาไทย)",
            "ជើងអក្សរ cheung âksâr",
            "중화인민공화국에서는 기본적으로 한족은 ",
            "पाठ्यांशः अत्र उपलभ्यतेसर्जनसामान्यलक्षणम्/Share-",
            "திபெத்துக்கு வெகள்",
            "អក្សរសាស្រ្តខែ្មរមានប្រវ៌ត្តជាងពីរពាន់ឆ្នាំមកហើយ ",
    };

    boolean runSMPTest(String question, String alicePassword, String bobPassword)
            throws InterruptedException, OtrException {
        CountDownLatch aliceLock = new CountDownLatch(1);
        CountDownLatch bobLock = new CountDownLatch(1);
        DummyClient[] convo = DummyClient.getConversation(aliceLock, bobLock);
        DummyClient alice = convo[0];
        DummyClient bob = convo[1];

        assertTrue(DummyClient.forceStartOtr(alice, bob));
        assertTrue(alice.getVerified() == DummyClient.NOTSET);
        assertTrue(bob.getVerified() == DummyClient.NOTSET);

        Session aliceSession = alice.getSession();
        Session bobSession = bob.getSession();

        assertFalse(aliceSession.isSmpInProgress());
        assertFalse(bobSession.isSmpInProgress());
        aliceSession.initSmp(question, alicePassword);

        assertTrue(aliceSession.isSmpInProgress());
        assertFalse(bobSession.isSmpInProgress());
        bob.pollReceivedMessage(); // SMP1Q

        // wait for the password prompt that is triggered by:
        // OtrEngineHost.askForSecret()
        bobLock.await(2000, TimeUnit.MILLISECONDS);

        bobSession.respondSmp(question, bobPassword);
        assertTrue(aliceSession.isSmpInProgress());
        assertTrue(bobSession.isSmpInProgress());

        alice.pollReceivedMessage(); // SMP2
        assertTrue(aliceSession.isSmpInProgress());
        assertTrue(bobSession.isSmpInProgress());

        bob.pollReceivedMessage(); // SMP3
        assertTrue(aliceSession.isSmpInProgress());
        assertFalse(bobSession.isSmpInProgress());

        alice.pollReceivedMessage(); // SMP4
        assertFalse(aliceSession.isSmpInProgress());
        assertFalse(bobSession.isSmpInProgress());

        // wait for SMP to complete
        aliceLock.await(2000, TimeUnit.MILLISECONDS);

        return alice.getVerified() == DummyClient.VERIFIED
                && bob.getVerified() == DummyClient.VERIFIED;
    }

    @Test
    public void testGoodPasswordVerify() throws OtrException, IOException, InterruptedException {
        assertTrue(runSMPTest(null, "goodPassword", "goodPassword"));
        System.out.print(".");
        for (String password : snippets) {
            assertTrue(runSMPTest(null, password, password));
            System.out.print(".");
        }
        String question = "this is the first question:";
        for (String password : snippets) {
            assertTrue(runSMPTest(question, password, password));
            question = password;
            System.out.print(".");
        }
        System.out.println("");
    }

    @Test
    public void testBadPasswordVerify() throws OtrException, IOException, InterruptedException {
        assertFalse(runSMPTest(null, "goodPassword", "BADpassword"));
        System.out.print(".");
        String previousPassword = "BADpassword";
        for (String password : snippets) {
            assertFalse(runSMPTest(null, password, previousPassword));
            previousPassword = password;
            System.out.print(".");
        }
        String question = "this is the first question:";
        for (String password : snippets) {
            assertFalse(runSMPTest(question, password, previousPassword));
            previousPassword = password;
            question = password;
            System.out.print(".");
        }
        System.out.println("");
    }
}
