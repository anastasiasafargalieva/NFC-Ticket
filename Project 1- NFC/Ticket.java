package com.ticketapp.auth.ticket;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

/**
 * TODO:
 * Complete the implementation of this class. Most of the code are already implemented. You
 * will need to change the keys, design and implement functions to issue and validate tickets. Keep
 * you code readable and write clarifying comments when necessary.
 */
public class Ticket {

    /**
     * Default keys are stored in res/values/secrets.xml
     **/
    private static final byte[] defaultAuthenticationKey = TicketActivity.outer.getString(R.string.default_auth_key).getBytes();
    private static final byte[] defaultHMACKey = TicketActivity.outer.getString(R.string.default_hmac_key).getBytes();
    private static byte[] secretkey = TicketActivity.outer.getString(R.string.secret_key).getBytes();


    /**
     * TODO: Change these according to your design. Diversify the keys.
     */
    private static byte[] authenticationKey = defaultAuthenticationKey; // 16-byte key
    private static byte[] hmacKey = defaultHMACKey; // 16-byte key
    private static byte[] secretHMACKey = TicketActivity.outer.getString(R.string.secret_hmac_key).getBytes();
    public static byte[] data = new byte[192];

    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;

    private Boolean isValid = false;
    private int remainingUses = 0;
    private int expiryTime = 0;

    private static String infoToShow = "-"; // Use this to show messages

    /**
     * Create a new ticket
     */
    public Ticket() throws GeneralSecurityException {
        // Set HMAC key for the ticket
        macAlgorithm = new TicketMac();
        macAlgorithm.setKey(hmacKey);

        ul = new Commands();
        utils = new Utilities(ul);
    }

    /**
     * After validation, get ticket status: was it valid or not?
     */
    public boolean isValid() {
        return isValid;
    }

    /**
     * After validation, get the number of remaining uses
     */
    public int getRemainingUses() {
        return remainingUses;
    }

    /**
     * After validation, get the expiry time
     */
    public int getExpiryTime() {
        return expiryTime;
    }

    /**
     * After validation/issuing, get information
     */
    public static String getInfoToShow() {
        return infoToShow;
    }

    // Used to cycle between MAC pages for tearing protection
    private boolean writeToFirstMacPage = true;

    /**
     * Issue new tickets
     * <p>
     * TODO: IMPLEMENT
     */
    private byte[] computeDiversifiedKey(byte[] masterSecretKey) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        // Retrieve card serial number(UID) as part of the key diversification
        byte[] UID = new byte[8];
        boolean res = utils.readPages(0, 2, UID, 0);
        if (!res) {
            Utilities.log("Failed to read serial number from card", true);
            return null;
        }
        // Concatenate the masterSecretKey and UID to compute the diversified key

        byte[] keyToBeHashed = new byte[masterSecretKey.length + UID.length];
        System.arraycopy(masterSecretKey, 0, keyToBeHashed, 0, masterSecretKey.length);
        System.arraycopy(UID, 0, keyToBeHashed, masterSecretKey.length, UID.length);

        byte[] diverseKey = digest.digest(keyToBeHashed);

        Utilities.log("Generated Diversified Key is " + Arrays.toString(diverseKey), false);
        return Arrays.copyOfRange(diverseKey, 0, 16);

    }

    private byte[] generateMac() {
        byte[] macInput = new byte[24];
        if (!utils.readPages(4, 6, macInput, 0)) {
            Utilities.log("Failed to read from card", true);
            return null;
        }
        // Generate MAC by calling the generateMac function in TicketMac
        byte[] mac = Arrays.copyOfRange(macAlgorithm.generateMac(macInput), 0, 4);
        //byte[] mac = macAlgorithm.generateMac(macInput);
        Utilities.log("mac generated is:" + Arrays.toString(mac), false);
        return mac;
    }

    private boolean writeMac(byte[] mac) {
        boolean writeMAC = true;
        if (writeToFirstMacPage) {
            writeMAC &= utils.writePages(mac, 0, 10, 1);
            Utilities.log("Writing to static mac", false);
        } else { //Write to backup mac
            writeMAC &= utils.writePages(mac, 0, 11, 1);
            Utilities.log("Writing to backup mac next", false);
        }

        // Make sure that next time the other MAC page is used
        if (writeMAC) {
            writeToFirstMacPage = !writeToFirstMacPage;
            Utilities.log("Write to backup mac next", false);
        }
        return writeMAC;
    }

    private static byte[] intToBytes(int i) {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.putInt(i);
        return buffer.array();
    }

    private static Integer byteArrayToInt(byte[] b) {
        try {
            return new BigInteger(b).intValue();
        } catch (Exception ex) {
            return 0;
        }
    }

    private static Date bytesToDate(byte[] b){
        try {
            int bInt;
            if (b.length == 4){
                byte[] b8 = new byte[8];
                System.arraycopy(b, 0, b8, 4, 4);
                bInt = byteArrayToInt(b8);
            }else bInt = byteArrayToInt(b);
            if (bInt <= 0) return null;
            return new Date(bInt*1000L);
        }catch (Exception ex){
            return null;
        }
    }

    public static void reverseArray(byte[] array) {
        if (array == null) {
            return;
        }
        int i = 0;
        int j = array.length - 1;
        byte tmp;
        while (j > i) {
            tmp = array[j];
            array[j] = array[i];
            array[i] = tmp;
            j--;
            i++;
        }
    }

    private boolean isFormatted() {
        byte[] tag = new byte[4];
        boolean res = utils.readPages(4, 1, tag, 0);
        for (int i = 0; i < tag.length; i++) {
            if (tag[i] != 0) return true;
        }
        return false;
    }

    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        boolean res;
        // Resetting the authentication key on the card to the default authentication key
        boolean reset = false;
        if (reset) {
            res = utils.writePages(defaultAuthenticationKey, 0, 44, 4);
            if (!res) {
                Utilities.log("Failed to reset card", true);
                infoToShow = "Failed to reset the authentication key";
                return false;
            }
            return true;
        }

        authenticationKey = computeDiversifiedKey(secretkey);

        // Authenticate using diversified key
        res = utils.authenticate(authenticationKey);

        // Configuring the auth0 and auth1
        //final byte[] auth0byte = new BigInteger("03000000",16).toByteArray(); // Configuration for AUTH0: Require authentication on all writable pages.
        final byte[] auth0byte = {0x06,0,0,0}; // Configuration for AUTH0: Require authentication on all writable pages.
        final byte[] auth1 = {0, 0, 0, 0}; // Configuration for AUTH1: Neither allow read nor write operations without authentication.
        if (!utils.writePages(auth0byte, 0, 42, 1)) {
            Utilities.log("Failed writing authentication configuration to the card", true);
            infoToShow = "Failed to lock authentication";
            return false;
        }
        if (!utils.writePages(auth1, 0, 43, 1)) {
            Utilities.log("Failed writing authentication configuration to the card", true);
            infoToShow = "Failed to lock authentication";
            return false;
        }

        if (!res) {
            Utilities.log("Authentication failed in issue() with diversified key", true);
            res = utils.authenticate(defaultAuthenticationKey);
            if (!res) {
                Utilities.log("Authentication failed using default key", true);
                infoToShow = "Authentication failed";
                return false;
            }

            // If the card is blank it authenticates with default authentication key.Issue a new ticket in this case

            // Write the diversified key to the card
            res = utils.writePages(authenticationKey, 0, 44, 4);
            if (!res) {
                Utilities.log("Failed to write diversified key to card", true);
                infoToShow = "Failed to write the diversified key";
                return false;
            }
            Utilities.log("Wrote new diversified key to card", false);
            //infoToShow = "Wrote new diversified key to card";
        }
        macAlgorithm.setKey(computeDiversifiedKey(secretHMACKey));
        // Issuing additional 5 additional rides if ticket is valid
        if (isFormatted() && isValid()) {
            // Retrieve the counterState
            byte[] counterState = new byte[4];
            res &= utils.readPages(6, 1, counterState, 0);
            //byte[] maxCounter = {counterState[0], counterState[1], 0, 0};
            //reverseArray(maxCounter);
            // Add the 5 additional rides to the Counter state
            int counterStateInt = byteArrayToInt(counterState);
            counterStateInt = counterStateInt + 5;
            counterState = intToBytes(counterStateInt);
            Utilities.log("counterStateInt in issue:"+counterStateInt,false);
            Utilities.log("counterState in issue:"+counterState,false);
            res &= utils.writePages(counterState, 0, 6, 1);
            Utilities.log("Issued 5 additional rides", false);
            // Recompute the MAC and update it
            byte[] mac = generateMac();
            res &= writeMac(mac);
            Utilities.log("Updated MAC", false);
            if (!res) {
                Utilities.log("Failed to issue additional rides", true);
                infoToShow = "Failed to issue additional rides";
                return false;
            }
            byte[] counter = new byte[4];
            res &= utils.readPages(41, 1, counter, 0);
            reverseArray(counter);
            //Utilities.log("Read Counter from 41 page:" + Arrays.toString(counter),false);
            ByteBuffer byteBuffer = ByteBuffer.wrap(counter);
            int maxRides = byteBuffer.getInt();
            int ridesLeft = counterStateInt - maxRides;
            Utilities.log("rides left="+ ridesLeft,false);
            infoToShow = "Issued 5 additional rides: Total rides=" + ridesLeft;
            return true;
        }

        // Write application tag to the card
        byte[] appTag = "SOAN".getBytes();
        res &= utils.writePages(appTag, 0, 4, 1);
        Utilities.log("Written application tag", false);

        // Write the version to the card
        byte[] version = "V.01".getBytes();
        res &= utils.writePages(version, 0, 5, 1);
        Utilities.log("Written version", false);

        // Write counter value
        byte[] initialCounter = {0, 0, 0, 0};
        res &= utils.writePages(initialCounter, 0, 41, 1);
        Utilities.log("Written initial counter value", false);
        // Retrieve the counter state from counter and add the uses
        byte[] counterState = new byte[4];
        res &= utils.readPages(41, 1, counterState, 0);
        //Increment the counter state with the uses
        byte[] maxCounter = {counterState[0], counterState[1], 0, 0};
        reverseArray(maxCounter);
        int counterStateInt = byteArrayToInt(maxCounter);
        counterStateInt = counterStateInt + 5;
        counterState = intToBytes(counterStateInt);
        Utilities.log("CounterStateInt" + counterStateInt, false);
        res &= utils.writePages(counterState, 0, 6, 1);
        Utilities.log("Written Maximum CounterState", false);

        //Retrieve the initial counter state to check if it's first use
        byte[] initialCounterState = new byte[4];
        res &= utils.readPages(41, 1, initialCounterState, 0);
        res &= utils.writePages(initialCounterState, 0, 7, 1);

        //Write the Issue Date (For security purpose and mac it)
        Date date = new Date(); // your date
        Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        cal.add(Calendar.DAY_OF_MONTH, 1);
        int year = cal.get(Calendar.YEAR);
        int month = cal.get(Calendar.MONTH);
        int day = cal.get(Calendar.DAY_OF_MONTH);
        byte[] issueDate = {(byte) (year - 2000), (byte) (month + 1), (byte) day, (byte) 0};
        res &= utils.writePages(issueDate, 0, 8, 1);
        Utilities.log("Written Issue Date" + Arrays.toString(issueDate), false);

        // Timestamp should be first set to current time when a ticket is first used
        byte[] firstUseTS = {0, 0, 0, 0};
        res &= utils.writePages(firstUseTS, 0, 9, 1);
        Utilities.log("Written first Use timestamp of zero", false);

        byte[] mac = generateMac();
        Utilities.log("Generated MAC of length " + mac.length, false);
        Utilities.log(Arrays.toString(mac), false);
        res &= writeMac(mac);
        Utilities.log("Written MAC" + Arrays.toString(mac), false);

        if (!res) {
            Utilities.log("Failed to issue ticket", true);
            infoToShow = "Failed to issue ticket";
            return false;
        }

        infoToShow = "Issued ticket with 5 rides!";
        return true;
    }

    /**
     * Use ticket once
     * <p>
     * TODO: IMPLEMENT
     */
    public boolean use() throws GeneralSecurityException {
        boolean res;
        authenticationKey = computeDiversifiedKey(secretkey);
        // Authenticate
        res = utils.authenticate(authenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            this.isValid = false;
            return false;
        } else {
            infoToShow = "Authentication Success";
        }

        //Compare the MACs and check if the ticket is valid
        macAlgorithm.setKey(computeDiversifiedKey(secretHMACKey));
        byte[] mac = generateMac();
        if (mac == null) {
            Utilities.log("Error in generated MAC", true);
            infoToShow = "A problem occurred!Please try again!";
            this.isValid = false;
            return false;
        }
        byte[] mac1 = new byte[4];
        byte[] mac2 = new byte[4];
        res &= utils.readPages(10, 1, mac1, 0);
        res &= utils.readPages(11, 1, mac2, 0);

        // Compare the macs
        if (!Arrays.equals(mac, mac1) && !Arrays.equals(mac, mac2)) {
            Utilities.log("MACs don't match!Card has been compromised", true);
            infoToShow = "Card couldn't be read!Try again";
            Utilities.log("Local MAC: " + Arrays.toString(mac), false);
            Utilities.log("MAC 1: " + Arrays.toString(mac1), false);
            Utilities.log("MAC 2: " + Arrays.toString(mac2), false);

            this.isValid = false;
            return false;
        }

        // Check if it is the first use
        byte[] zeroArray = {0, 0, 0, 0};
        byte[] firstUse = new byte[4];
        res &= utils.readPages(9, 1, firstUse, 0);
        if (Arrays.equals(zeroArray, firstUse)) {
            // Set the firstUse time to current time
            int nowSec = (int) (System.currentTimeMillis() / 1000);
            Utilities.log("Now sec: " + nowSec, false);
            ByteBuffer buffer = ByteBuffer.allocate(4);
            buffer.putInt(nowSec);
            Utilities.log("value in buffer:" + buffer.array().toString(),false);//Remove later
            res &= utils.writePages(buffer.array(), 0, 9, 1);
            firstUse = buffer.array();
            // Reset the MAC, because we changed the static information
            byte[] newMAC = generateMac();
            if (newMAC == null) {
                Utilities.log("Error in generated MAC", true);
                infoToShow = "A problem occurred!Please try again!";
                this.isValid = false;
                return false;
            }
            Utilities.log("Generated MAC of length " + newMAC.length, false);
            Utilities.log(Arrays.toString(newMAC), false);
            res &= writeMac(newMAC);
            Utilities.log("Written new MAC", false);
        }

        // Check if the ticket is expired or still valid

        int now = (int) (System.currentTimeMillis() / 1000);
        ByteBuffer byteBuffer = ByteBuffer.wrap(firstUse);
        int startValidityPeriod = byteBuffer.getInt();
        int endTime = startValidityPeriod + (1 * 60 * 60); //One hour
        Utilities.log("Expiry time: " + endTime, false);
        Utilities.log("Now:      " + now, false);
        if (now > endTime) {
            // The ticket is being used while it is expired
            Utilities.log("Ticket expired", true);
            Utilities.log("End time: " + endTime, false);
            Utilities.log("Now:      " + now, false);
            infoToShow = "Ticket expired"+" End Time "+endTime+" now "+now+ " startValidityPeriod "+ startValidityPeriod;

            this.isValid = false;
            return false;
        }

        //Validate the CounterState
        byte[] counterState = new byte[4];
        res &= utils.readPages(6, 1, counterState, 0);
        Utilities.log("counterState read from page 6:" + Arrays.toString(counterState),false);
        //byte[] maxCounter = {0, 0, counterState[2], counterState[3]};
        //reverseArray(counterState);
        Utilities.log("maxCounter:" + Arrays.toString(counterState),false);
        byte[] counter = new byte[4];
        res &= utils.readPages(41, 1, counter, 0);
        reverseArray(counter);
        Utilities.log("Read Counter from 41 page:" + Arrays.toString(counter),false);
        byteBuffer = ByteBuffer.wrap(counterState);
        int maxRides = byteBuffer.getInt();
        byteBuffer = ByteBuffer.wrap(counter);
        int currentCounter = byteBuffer.getInt();
        Utilities.log("CounterState: " + maxRides, false);
        Utilities.log("Counter: " + currentCounter, false);
        // Check if the ticket has reached its usage limit
        if (currentCounter >= maxRides) {
            Utilities.log("Ticket has no rides left", true);
            infoToShow = "No more rides left on this ticket";
            this.isValid = false;
            return false;
        }

        // Increment the rides counter
        byte[] updateCounter = {1, 0, 0, 0};
        res &= utils.writePages(updateCounter, 0, 41, 1);
        currentCounter++;
        Utilities.log("currentCounter value:"+currentCounter,false);
        if (!res) {
            Utilities.log("Updating the counter failed", true);
        }
        byte[] endTimeBytes = intToBytes(endTime);
        Date expiryDate = bytesToDate(endTimeBytes);
        Utilities.log("Expiry Date:"+expiryDate,false);
        this.isValid = true;
        this.remainingUses = maxRides - currentCounter;
        this.expiryTime = endTime;

        Utilities.log("Ticket used!", false);
        if(this.remainingUses == 0)
        {
            infoToShow = "No rides left";
        }
        else {
            infoToShow = this.remainingUses + " rides left." + " Expires on " + expiryDate.toString().substring(0,20);
        }
        return true;
    }
}

