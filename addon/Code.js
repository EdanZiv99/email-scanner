/**
 * Gmail Add-on entry point. Extracts email data, calls the Flask backend,
 * and renders the result as a Gmail sidebar card.
 */

// Backend URL - update this when ngrok URL changes
const BACKEND_URL = 'https://crusher-dragging-staring.ngrok-free.dev';

const SIGNAL_DISPLAY_NAMES = {
  "dmarc": "DMARC Authentication",
  "display_name_email_spoof": "Display Name Spoofing (Email)",
  "display_name_brand_impersonation": "Brand Impersonation",
  "lookalike_domain": "Lookalike Domain",
  "dangerous_extensions": "Dangerous Attachment",
  "url_href_mismatch": "Deceptive Link",
  "reply_to_mismatch": "Reply-To Redirect",
  "threat_intel_url": "Known Malicious URL",
};

const VERDICT_COLORS = {
  "Safe": "#0d8043",
  "Suspicious": "#f9a825",
  "High Risk": "#ef6c00",
  "Malicious": "#c62828",
};

const VERDICT_EMOJI = {
  "Safe": "🟢",
  "Suspicious": "🟡",
  "High Risk": "🟠",
  "Malicious": "🔴",
};


const MATERIAL_ICONS = {
  shield:      "https://fonts.gstatic.com/s/i/materialicons/shield/v6/24px.svg",
  barChart:    "https://fonts.gstatic.com/s/i/materialicons/bar_chart/v6/24px.svg",
  lightbulb:   "https://fonts.gstatic.com/s/i/materialicons/lightbulb/v6/24px.svg",
  search:      "https://fonts.gstatic.com/s/i/materialicons/search/v6/24px.svg",
  checkCircle: "https://fonts.gstatic.com/s/i/materialicons/check_circle/v6/24px.svg",
  warning:     "https://fonts.gstatic.com/s/i/materialicons/warning/v6/24px.svg",
  error:       "https://fonts.gstatic.com/s/i/materialicons/error/v6/24px.svg",
  dangerous:   "https://fonts.gstatic.com/s/i/materialicons/dangerous/v6/24px.svg",
};

const VERDICT_ICONS = {
  "Safe":      MATERIAL_ICONS.checkCircle,
  "Suspicious": MATERIAL_ICONS.warning,
  "High Risk": MATERIAL_ICONS.error,
  "Malicious": MATERIAL_ICONS.dangerous,
};

const VERDICT_DESCRIPTIONS = {
  "Safe":      "This email appears to be legitimate.",
  "Suspicious": "Some indicators warrant attention.",
  "High Risk": "Multiple threat indicators detected.",
  "Malicious": "Critical threat detected.",
};

const VERDICT_RISK_LABELS = {
  "Safe":      "Very Low Risk",
  "Suspicious": "Moderate Risk",
  "High Risk": "High Risk",
  "Malicious": "Critical Risk",
};

const VERDICT_ACTION_HEADLINES = {
  "Safe":      "No action needed.",
  "Suspicious": "Be cautious.",
  "High Risk": "Use caution.",
  "Malicious": "Do not interact.",
};

const VERDICT_ACTION_DETAILS = {
  "Safe":      "You can safely interact with this email.",
  "Suspicious": "Verify links before clicking.",
  "High Risk": "Do not click links or open attachments. Verify with sender via another channel.",
  "Malicious": "Report to IT and delete this email.",
};


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
 * @return {Object} The card to display.
 */
function buildCard(scanResult) {
  const verdict = scanResult.verdict;
  const color = VERDICT_COLORS[verdict] || '#000000';
  const emoji = VERDICT_EMOJI[verdict] || '';
  const score = Math.min(100, scanResult.score);
  const triggeredSignals = (scanResult.signals || []).filter(s => s.triggered);
  const triggerCount = triggeredSignals.length;
  const findingsWord = triggerCount === 1 ? 'finding' : 'findings';

  const vtSignal = (scanResult.signals || []).find(s => s.name === 'threat_intel_url');
  const vtRateLimited = vtSignal && !vtSignal.triggered &&
    (vtSignal.metadata && vtSignal.metadata.errors || []).some(e => e.includes('Rate limit exceeded'));

  const card = CardService.newCardBuilder();

  // Section 1: Header row — verdict icon, colored verdict text, score
  card.addSection(
    CardService.newCardSection()
      .addWidget(
        CardService.newDecoratedText()
          .setIconUrl(VERDICT_ICONS[verdict])
          .setText(`<b><font color="${color}" size="7">${verdict.toUpperCase()}</font></b>`)
          .setBottomLabel(`Risk Score: ${score}/100`)
          .setWrapText(true)
      )
  );

  if (vtRateLimited) {
    card.addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText('<font color="#f9a825" size="2">⚠ VirusTotal check skipped: rate limit reached</font>')
        )
    );
  }

  // Section 2: Security Verdict
  card.addSection(
    CardService.newCardSection()
      .addWidget(
        CardService.newDecoratedText()
          .setIconUrl(MATERIAL_ICONS.shield)
          .setText('<b>SECURITY VERDICT</b>')
      )
      .addWidget(
        CardService.newTextParagraph()
          .setText(`<font color="${color}"><b>${emoji} ${verdict}</b></font>`)
      )
      .addWidget(
        CardService.newTextParagraph()
          .setText(VERDICT_DESCRIPTIONS[verdict] || '')
      )
  );

  // Section 3: Risk Score
  const riskLabel = VERDICT_RISK_LABELS[verdict] || '';
  card.addSection(
    CardService.newCardSection()
      .addWidget(
        CardService.newDecoratedText()
          .setIconUrl(MATERIAL_ICONS.barChart)
          .setText('<b>RISK SCORE</b>')
      )
      .addWidget(
        CardService.newTextParagraph()
          .setText(
            `<font size="5"><b>${emoji} ${score}/100</b></font>` +
            `<font color="${color}" size="3"> (${riskLabel})</font><br>` +
            `<font color="#5f6368" size="2">${triggerCount} threat indicator(s) detected</font>`
          )
      )
  );

  // Trump card banner (only if triggered)
  if (scanResult.trump_card_triggered) {
    const trumpNames = (scanResult.trump_signals || [])
      .map(name => SIGNAL_DISPLAY_NAMES[name] || name)
      .join(', ');
    card.addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText(`<font color="#c62828"><b>⚠ Critical threat detected</b><br>${trumpNames}</font>`)
        )
    );
  }

  // Section 4: Recommended Action
  const headline = VERDICT_ACTION_HEADLINES[verdict] || '';
  const detail = VERDICT_ACTION_DETAILS[verdict] || '';
  card.addSection(
    CardService.newCardSection()
      .addWidget(
        CardService.newDecoratedText()
          .setIconUrl(MATERIAL_ICONS.lightbulb)
          .setText('<b>RECOMMENDED ACTION</b>')
      )
      .addWidget(
        CardService.newTextParagraph()
          .setText(`<font color="${color}"><b>${headline}</b></font><br>${detail}`)
      )
  );

  // Section 5: Analysis Breakdown
  const findingsSection = CardService.newCardSection()
    .addWidget(
      CardService.newDecoratedText()
        .setIconUrl(MATERIAL_ICONS.search)
        .setText(`<b>ANALYSIS BREAKDOWN (${triggerCount} ${findingsWord})</b>`)
    );

  if (triggerCount > 0) {
    triggeredSignals.forEach(signal => {
      const category = (signal.category || 'Other').toUpperCase();
      findingsSection.addWidget(
        CardService.newTextParagraph()
          .setText(
            `<font color="#5f6368" size="2">${category}</font><br>` +
            `${signal.explanation}<br>` +
            `<font color="#5f6368" size="2">+${signal.weight} points</font>`
          )
      );
    });
  } else {
    findingsSection.addWidget(
      CardService.newTextParagraph().setText('No suspicious indicators found.')
    );
  }
  card.addSection(findingsSection);

  // Section 6: AI analysis status / button
  const llmSignal = (scanResult.signals || []).find(s => s.name === 'gemini_analysis');
  if (llmSignal) {
    // LLM was already invoked — show outcome notice
    let noticeText;
    if (llmSignal.triggered) {
      noticeText = '<font color="#0d8043">✓ AI analysis complete</font>';
    } else if ((llmSignal.explanation || '').includes('unavailable')) {
      noticeText = '<font color="#f9a825">⚠ AI analysis temporarily unavailable</font>';
    } else {
      noticeText = '<font color="#0d8043">✓ AI analysis: no threats detected</font>';
    }
    card.addSection(
      CardService.newCardSection()
        .addWidget(CardService.newTextParagraph().setText(noticeText))
    );
  } else {
    // Offer on-demand LLM analysis for all verdicts
    const previousResult = {
      score: scanResult.score,
      signals: scanResult.signals,
      trump_card_triggered: scanResult.trump_card_triggered,
      trump_signals: scanResult.trump_signals,
    };
    card.addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextButton()
            .setText('🤖 Run AI Analysis')
            .setOnClickAction(
              CardService.newAction()
                .setFunctionName('runLlmAnalysis_')
                .setParameters({ previousResult: JSON.stringify(previousResult) })
            )
        )
    );
  }

  // Section 7: VirusTotal button (only if threat_intel_url triggered and permalink available)
  const threatIntelSignal = (scanResult.signals || []).find(
    s => s.name === 'threat_intel_url' && s.triggered
  );
  if (threatIntelSignal && threatIntelSignal.metadata && threatIntelSignal.metadata.permalink) {
    card.addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextButton()
            .setText('View VirusTotal Report')
            .setOpenLink(
              CardService.newOpenLink().setUrl(threatIntelSignal.metadata.permalink)
            )
        )
    );
  }

  return card.build();
}


/**
 * Action handler for the "Run AI Analysis" button.
 * Re-extracts email data, posts to /scan/llm, and pushes the updated card.
 *
 * @param {Object} e Action event object provided by Gmail.
 * @return {ActionResponse} Navigation to the updated card.
 */
function runLlmAnalysis_(e) {
  try {
    const emailData = extractEmailData(e);
    const previousResult = JSON.parse(e.parameters.previousResult || '{}');

    const options = {
      method: 'post',
      contentType: 'application/json',
      payload: JSON.stringify({ ...emailData, previousResult: previousResult }),
      muteHttpExceptions: true,
    };

    const response = UrlFetchApp.fetch(`${BACKEND_URL}/scan/llm`, options);
    const code = response.getResponseCode();

    if (code !== 200) {
      throw new Error(`Backend returned ${code}: ${response.getContentText()}`);
    }

    const scanResult = JSON.parse(response.getContentText());
    const card = buildCard(scanResult);

    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().pushCard(card))
      .build();
  } catch (error) {
    console.error('AI analysis error:', error);
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().pushCard(buildErrorCard(error.message)))
      .build();
  }
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