/**
 * Entry point - called by Gmail when a user opens an email.
 * For now, returns a simple "Hello" card to verify the add-on works.
 *
 * @param {Object} e Event object provided by Gmail.
 * @return {Card[]} Array of cards to display in the sidebar.
 */
function onGmailMessage(e) {
    const card = CardService.newCardBuilder()
        .setHeader(
            CardService.newCardHeader()
                .setTitle('Email Scorer')
                .setSubtitle('Hello, World!')
        )
        .addSection(
            CardService.newCardSection()
                .addWidget(
                    CardService.newTextParagraph()
                        .setText('If you can see this card, the add-on is working correctly.')
                )
        )
        .build();

    return [card];
}