package burp;

import java.net.URL;

public class JsonArrayIssue implements IScanIssue {
	private final IHttpRequestResponse[] httpMessages;
	private final URL url;

	private static final String ISSUE_NAME = "Top-level Array in JSON response";
	private static final String ISSUE_DETAIL =
		"The top level element of the JSON payload returned in the HTTP response is " +
		"an Array, which is handled in a way in pre-ECMAScript 5 browsers that " +
		"can be abused to leak information to other websites." +
		"<br><br>" +
		"The contents of the payload <b>must be inspected manually</b> to see if " +
		"the response contains <b>sensitive information tied to the session</b> and " +
		"whether the input parameters (if there are any) can be replicated " +
		"by an attacker.";

	private static final String REMEDIATION =
		"<ul><li>" + String.join("</li><li>",
				"Use <b>Objects as top level entities</b> in sensitive JSON responses.",
				"Use POST to request sensitive JSON responses, and enforce this on the server.",
				"Enforce <b>XSRF countermeasures</b> for requests regarding sensitive JSON responses.")
		+ "</li></ul>";

	private static final String BACKGROUND =
		"See <a href=\"http://flask.pocoo.org/docs/security/#json-security\">" +
		"section JSON Security of the Flask Security Considerations</a> for a good " +
		"writeup on the issue.";

	public JsonArrayIssue(IHttpRequestResponse baseRequestResponse,
			URL url) {
		this.httpMessages = new IHttpRequestResponse[] { baseRequestResponse };
		this.url = url;
	}

	@Override public String getIssueDetail() { return ISSUE_DETAIL; }
	@Override public String getConfidence() { return "Tentative"; }
	@Override public IHttpRequestResponse[] getHttpMessages() { return httpMessages; }
	@Override public IHttpService getHttpService() { return httpMessages[0].getHttpService(); }
	@Override public String getIssueBackground() { return BACKGROUND; }
	@Override public String getIssueName() { return ISSUE_NAME; }
	@Override public int getIssueType() { return 0x08000000; }
	@Override public String getRemediationBackground() { return null; }
	@Override public String getRemediationDetail() { return REMEDIATION; }
	@Override public String getSeverity() { return "Medium"; }
	@Override public URL getUrl() { return url; }
}
