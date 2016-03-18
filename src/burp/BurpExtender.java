package burp;

import java.util.*;

public class BurpExtender implements IBurpExtender, IScannerCheck
{
	IExtensionHelpers helpers;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	{
		callbacks.setExtensionName("JSON Array issues");
		callbacks.registerScannerCheck(this);
		this.helpers = callbacks.getHelpers();
	}

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		byte[] response = baseRequestResponse.getResponse();
		int offset = helpers.analyzeResponse(response).getBodyOffset();
		if (response.length == offset) return null; // no response body
		if (response[offset] != (byte)'[' ||
				response[response.length - 1] != (byte)']') return null;
		IRequestInfo ri = helpers.analyzeRequest(baseRequestResponse.getHttpService(),
				baseRequestResponse.getRequest());
		return Collections.singletonList((IScanIssue)new JsonArrayIssue(
					baseRequestResponse, ri.getUrl()));
	}

	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,
			IScannerInsertionPoint insertionPoint) {
		return null;
	}

	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		return -1;
	}
}
