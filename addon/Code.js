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

  return {
    from: message.getFrom(),
    subject: message.getSubject(),
    messageId: messageId,
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

  // Echo section - temporary, for verifying integration
  if (scanResult.echo) {
    const echoSection = CardService.newCardSection()
      .setHeader('Received by backend')
      .addWidget(
        CardService.newDecoratedText()
          .setTopLabel('From')
          .setText(scanResult.echo.from || '(empty)')
      )
      .addWidget(
        CardService.newDecoratedText()
          .setTopLabel('Subject')
          .setText(scanResult.echo.subject || '(empty)')
      );
    card.addSection(echoSection);
  }

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