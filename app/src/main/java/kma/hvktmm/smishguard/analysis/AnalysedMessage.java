package kma.hvktmm.smishguard.analysis;

import android.content.Context;
import android.graphics.Color;
import android.os.AsyncTask;
import android.view.View;

import kma.hvktmm.smishguard.R;
import kma.hvktmm.smishguard.bert.PredictionCallback;
import kma.hvktmm.smishguard.bert.PredictionService;
import kma.hvktmm.smishguard.contacts.Lookup;
import kma.hvktmm.smishguard.sms.SMS;
import kma.hvktmm.smishguard.util.Strings;
import retrofit2.Call;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import timber.log.Timber;
import java.util.concurrent.CountDownLatch;

import static kma.hvktmm.smishguard.analysis.URLAnalysis.extractURLs;
//import static kma.hvktmm.smishguard.bert.*;


public class AnalysedMessage {
    private static final int PHONE_NUMBER = 1;
    private static final int SHORT_CODE = 2;
    private SMS message;
    private boolean isMalicious = false;
    private boolean hasLink = false;
    private boolean hasUnknownLink = false;
    private boolean isContact = false;
    private String contactName;
    private boolean companySender = false;
    private String[] Links;
    private String LinkInfo;
    private boolean analysed = false;

    public String getContactName() {
        return contactName;
    }

    public void setContactName(String contactName) {
        this.contactName = contactName;
    }

    public boolean isCompanySender() {
        return companySender;
    }

    public void setCompanySender(boolean companySender) {
        this.companySender = companySender;
    }

    public boolean isAnalysed() {
        return analysed;
    }

    public void setAnalysed(boolean analysed) {
        this.analysed = analysed;
    }

    public String getLinkInfo() {
        return LinkInfo;
    }

    public void setLinkInfo(String linkInfo) {
        LinkInfo = linkInfo;
    }

    public String[] getLinks() {
        return Links;
    }

    public void setLinks(String[] links) {
        Links = links;
    }

    public boolean hasUnknownLink() {
        return hasUnknownLink;
    }

    public void setHasUnknownLink(boolean hasUnknownLink) {
        this.hasUnknownLink = hasUnknownLink;
    }

    public boolean isContact() {
        return isContact;
    }

    public void setContact(boolean contact) {
        isContact = contact;
    }

    private String keywords;

    private String analysis;

    public SMS getMessage() {
        return message;
    }

    public void setMessage(SMS message) {
        this.message = message;
    }

    public boolean isMalicious() {
        return isMalicious;
    }

    public void setMalicious(boolean malicious) {
        isMalicious = malicious;
    }

    public boolean hasLink() {
        return hasLink;
    }

    public void setLink(boolean hasLink) {
        this.hasLink = hasLink;
    }

    public String getKeywords() {
        return keywords;
    }

    public void setKeywords(String keywords) {
        this.keywords = keywords;
    }

    public String getAnalysis() {
        return analysis;
    }

    public void setAnalysis(String analysis) {
        this.analysis = analysis;
    }

    public static int predictionMgs;



    /**
     * Analyse a single SMS message
     * Context context for the app
     */
    public void analyse(Context context, OrganisationInfo[] orgsInfo) {

        // check sender address - all letters means its from a company
        if (isShortCode(message.getAddress()) == SHORT_CODE) {
            setCompanySender(true);
            setContact(false);

            // Ngừng phân tích nếu là công ty hợp pháp
            setAnalysed(true);
            setMalicious(false);
//            setAnalysis("Message from legal organization.");
//            Timber.d("analyse: Legal messages from the company.");
        } else {
            setCompanySender(false);
            String name = Lookup.contactDetails(context, message.getAddress());

            if (!name.equals(Lookup.NOT_A_CONTACT)) {
                Timber.d("analyse: sender number in contacts");
                setContact(true);
                setContactName(name);
            }
        }

        String msgBody = message.getMsg();
        predictionMgs = 10;
        // look for URL in the message
        String[] URLs = extractURLs(msgBody);
        // Gửi yêu cầu dự đoán

        // Gửi yêu cầu dự đoán SMS

        Timber.tag("bdpreout").d("Prediction success: %d", predictionMgs);
        setAnalysed(true);


        // no URLs in message, so benign
        if (URLs == null) {
            PredictionService predictionService = new PredictionService();
            predictionService.getPrediction(msgBody, new PredictionCallback() {
                @Override
                public void onResult(boolean isMalicious) {
                    setMalicious(isMalicious);
                    setAnalysed(true);
                    setLink(false);
                    setAnalysis("No links in message.");
                    Timber.d("Message analysis complete. Malicious: %s", isMalicious ? "Yes" : "No");
                }

                @Override
                public void onError(String error) {
                    setAnalysis("Error in prediction: " + error);
                    Timber.e("Prediction API error: %s", error);
                }

            });
            return;
        }

        // have at least one URL in message else would have returned
        setLink(true);
        setLinks(URLs);

        // compare to known domains
        int urlMatchedOrg = -1;

        for (String url : URLs) {

            // try to attribute link to a known org via the URL
            // for all the known orgs
            for (int j = 0; j < orgsInfo.length; j++) {

                // get the expected URL format
                String[] expectedURLs = orgsInfo[j].getUrl();

                for (String expectedURL: expectedURLs) {
                    // check if its contained in our URL
                    if (url.contains(expectedURL)) {
                        urlMatchedOrg = j;
                        break;
                    }
                }
            }

            if (urlMatchedOrg != -1) {
                // Link matches to one of the organisations, so don't care about body
                setAnalysis(String.format("Legitimate link for %s.", orgsInfo[urlMatchedOrg].getName()));

                Timber.d("analyseMessage - Link detected, in the format we'd expect for %s. Analysis complete.", orgsInfo[urlMatchedOrg].getName());
                setMalicious(false);
                return;
            }

            // Unknown URL, so inspect body
            Timber.d("analyseMessage - URL of unknown org, inspecting body");

            // trim the URL from the body
            String messageBodyNoURL = msgBody.replace(url, "");

            // look for keywords in the message body instead
            inspectBody(messageBodyNoURL, orgsInfo);

            // inspect the URL itself
            AnalysedURL details = URLAnalysis.analyseURL(url);

            if (details != null && details.isAnalysed() && details.isSuspicious()) {
                Timber.d(details.getAnalysis());
                setLinkInfo(details.getAnalysis());
                setMalicious(true);
                setAnalysis(getAnalysis().concat(" ").concat(details.getAnalysis()));
            }
        }
    }

    private int isShortCode(String address) {
        // check it's +[0-9]
        // Can't check it's all characters as stupid ee send messages from 'EE'
        if (address.startsWith("+") && address.substring(1).chars().allMatch(Character::isDigit)) {
            return PHONE_NUMBER;
        } else if (address.chars().allMatch(Character::isDigit)) {
            return PHONE_NUMBER;
        }

        return SHORT_CODE;
    }

    private void inspectBody(String messageBody, OrganisationInfo[] orgsInfo) {
        Timber.d("inspectBody - inspecting message body \"%s\"", messageBody);


        int matchedBody = -1;

        // for each org
        for (int i = 0; i < orgsInfo.length; i++) {
            OrganisationInfo info = orgsInfo[i];

            // Look for keywords in body
            for (String keyword : info.getKeywords()) {
                // hack to stop hitting against ee in words
                if (info.getName().equals("EE")) {
                    if (messageBody.contains(keyword)) {
                        matchedBody = i;
                        setKeywords(appendString(getKeywords(), String.format("\"%s\"", keyword)));
                        Timber.d("inspectBody - Found keyword \"%s\" in message body.", keyword);
                        break;
                    }
                } else {
                    if (messageBody.toLowerCase().contains(keyword.toLowerCase())) {
                        matchedBody = i;
                        setKeywords(appendString(getKeywords(), String.format("\"%s\"", keyword)));
                        Timber.d("inspectBody - Found keyword \"%s\" in message body.", keyword);
                        break;
                    }
                }
            }
        }

        if (matchedBody != -1) {
            // body matched a keyword, URL not matched
            Timber.d("inspectBody - Keyword matched to org %s but URL doesn't.", orgsInfo[matchedBody].getName());

            // keywords in body don't match what we'd expect for the URL
            setMalicious(true);
            setAnalysis(String.format("Warning! Potential smishing attempt. Message has keywords from %s, but URL is invalid for that organisation.", orgsInfo[matchedBody].getName()));
        } else {
            // body didn't match a keyword, URL not matched
            // found a link but couldn't attribute it to an org i.e. can't check it, so mark the message as unknown
            setAnalysis("Link detected, but doesn't match any known organisation. Can't determine if malicious or benign.");
            setHasUnknownLink(true);
        }
    }

    private static String appendString(String string1, String string2) {
        if (string1 == null || string1.length() == 0) {
            return string2;
        } else {
            return String.format("%s, %s", string2, string1);
        }
    }

}
