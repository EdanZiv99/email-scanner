// Backend URL - update this when ngrok URL changes
const BACKEND_URL = 'https://crusher-dragging-staring.ngrok-free.dev';


/**
 * Entry point - called by Gmail when a user opens an email.
 * Orchestrates the flow: extract email data -> call backend -> build card.
 *
 * @param {Object} e Event object provided by Gmail.
 * @return {Card[]} Array of cards to display in the sidebar.
 */
function onGmailMessage(e) {
  try {
    const emailData = extractEmailData(e);
    const scanResult = callBackend(emailData);
    return [buildCard(scanResult)];
  } catch (error) {
    console.error('Add-on error:', error);
    return [buildErrorCard(error.message)];
  }
}


/**
 * Extracts metadata from the currently open email.
 *
 * @param {Object} e Gmail event object.
 * @return {Object} Email data to send to backend.
 */
function extractEmailData(e) {
  const messageId = e.gmail.messageId;
  const accessToken = e.gmail.accessToken;

  // Apps Script requires this to access the message
  GmailApp.setCurrentMessageAccessToken(accessToken);

  const message = GmailApp.getMessageById(messageId);

  const rawContent = message.getRawContent();
  const headerSeparatorIndex = rawContent.indexOf('\r\n\r\n');
  const rawHeaders = headerSeparatorIndex !== -1
    ? rawContent.substring(0, headerSeparatorIndex)
    : rawContent;  // fallback: if no separator found, use entire content

  let htmlBody = '';
  let textBody = '';
  try {
    htmlBody = message.getBody();
  } catch (e) {
    console.warn('Could not retrieve HTML body:', e);
  }
  try {
    textBody = message.getPlainBody();
  } catch (e) {
    console.warn('Could not retrieve plain text body:', e);
  }

  let attachments = [];
  try {
    attachments = message.getAttachments().map(attachment => {
      const hashBytes = Utilities.computeDigest(
        Utilities.DigestAlgorithm.SHA_256,
        attachment.getBytes()
      );
      // Apps Script returns signed bytes; `b & 0xff` converts to unsigned before hex encoding.
      const sha256 = hashBytes.map(b => ('0' + (b & 0xff).toString(16)).slice(-2)).join('');
      return {
        filename: attachment.getName(),
        size: attachment.getSize(),
        sha256: sha256,
      };
    });
  } catch (e) {
    console.warn('Could not process attachments:', e);
  }

  // Payload keys are camelCase (JS convention). The Flask endpoint maps them to snake_case.
  // Required: from, subject, messageId, rawHeaders. Optional: htmlBody, textBody, attachments.
  return {
    from: message.getFrom(),
    subject: message.getSubject(),
    messageId: messageId,
    rawHeaders: rawHeaders,
    htmlBody: htmlBody,
    textBody: textBody,
    attachments: attachments,
  };
}


/**
 * Sends email data to the backend and returns the scan result.
 *
 * @param {Object} emailData Email metadata.
 * @return {Object} Backend response with score, verdict, signals.
 */
function callBackend(emailData) {
  const options = {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify(emailData),
    muteHttpExceptions: true,  // don't throw on 4xx/5xx, let us handle it
  };

  const response = UrlFetchApp.fetch(`${BACKEND_URL}/scan`, options);
  const code = response.getResponseCode();

  if (code !== 200) {
    throw new Error(`Backend returned ${code}: ${response.getContentText()}`);
  }

  return JSON.parse(response.getContentText());
}


/**
 * Builds the result card displayed to the user.
 *
 * @param {Object} scanResult Backend response.
 * @return {Card} The card to display.
 */
function buildCard(scanResult) {
  const card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle('Email Scorer')
        .setSubtitle(`Verdict: ${scanResult.verdict}`)
    );

  // Score section
  const scoreSection = CardService.newCardSection()
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Score')
        .setText(String(scanResult.score))
    );
  card.addSection(scoreSection);

  // Findings section
  const triggeredSignals = (scanResult.signals || []).filter(s => s.triggered);
  const findingsSection = CardService.newCardSection();

  if (triggeredSignals.length > 0) {
    findingsSection.setHeader(`Findings (${triggeredSignals.length})`);
    triggeredSignals.forEach(signal => {
      findingsSection.addWidget(
        CardService.newDecoratedText()
          .setText(signal.explanation)
      );
    });
  } else {
    findingsSection.addWidget(
      CardService.newTextParagraph()
        .setText('No suspicious indicators found')
    );
  }

card.addSection(findingsSection);

  return card.build();
}


/**
 * Builds an error card to display when something goes wrong.
 *
 * @param {string} message Error message.
 * @return {Card} The error card.
 */
function buildErrorCard(message) {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle('Email Scorer')
        .setSubtitle('Error')
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText(`Failed to scan email: ${message}`)
        )
    )
    .build();
}