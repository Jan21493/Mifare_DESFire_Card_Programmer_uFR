#import "ViewController.h"
#import "DFScript.h"
#import "DESFireReader.h"
#import <Security/Security.h>

@interface ViewController () <NSTextFieldDelegate, NSTabViewDelegate>
@property IBOutlet NSTabView *tabs;
@property IBOutlet NSTextView *outputView;
@property IBOutlet NSButton *connectButton;
@property IBOutlet NSButton *disconnectButton;
@property IBOutlet NSTextField *applicationAid;
@property IBOutlet NSButton *applicationPICC;
@property IBOutlet NSButton *applicationCustomAid;
@property IBOutlet NSButton *applicationRequirement;
@property IBOutlet NSPopUpButton *applicationKeyCount;
@property IBOutlet NSButton *applicationNoAuth;
@property IBOutlet NSButton *applicationAES;
@property IBOutlet NSButton *applicationReader;
@property IBOutlet NSButton *createApplicationButton;
@property IBOutlet NSButton *deleteApplicationButton;
@property IBOutlet NSButton *setApplicationSettingsButton;
@property IBOutlet NSButton *cardPICC;
@property IBOutlet NSButton *cardCustomAid;
@property IBOutlet NSTextField *cardAid;
@property IBOutlet NSPopUpButton *cardKeyNumber;
@property IBOutlet NSButton *cardAES;
@property IBOutlet NSButton *cardReader;
@property IBOutlet NSTextField *keysAid;
@property IBOutlet NSPopUpButton *targetKeyNumber;
@property IBOutlet NSPopUpButton *authenticationKeyNumber;
@property IBOutlet NSButton *keysNoAuth;
@property IBOutlet NSButton *keysAES;
@property IBOutlet NSButton *keysReader;
@property IBOutlet NSButton *changeKeyButton;
@property IBOutlet NSButton *filesNoAuth;
@property IBOutlet NSButton *filesAES;
@property IBOutlet NSButton *filesReader;
@property IBOutlet NSPopUpButton *communicationMode;
@property IBOutlet NSButton *changeAccessButton;
@property IBOutlet NSTextField *fileCapacity;
@property IBOutlet NSButton *writeFileButton;
@property IBOutlet NSButton *readFileButton;
@property IBOutlet NSButton *dumpFileButton;
@property IBOutlet NSButton *getFileSettingsButton;
@property IBOutlet NSTextField *filesAid;
@property IBOutlet NSPopUpButton *filesID;
@property IBOutlet NSTextField *filesKey;
@property IBOutlet NSPopUpButton *filesKeyNumber;
@property IBOutlet NSPopUpButton *filesReaderSlot;
@property IBOutlet NSTextField *readerKey;
@property IBOutlet NSPopUpButton *readerSlot;
@property IBOutlet NSTextField *readerPassword;
@property IBOutlet NSPopUpButton *transmitSpeed;
@property IBOutlet NSPopUpButton *receiveSpeed;
@property IBOutlet NSTextField *cardKey;
@property IBOutlet NSPopUpButton *cardReaderSlot;
@property IBOutlet NSButton *randomUID;
@property IBOutlet NSButton *disableFormatting;
@property IBOutlet NSButton *configureCardButton;
@property IBOutlet NSButton *getUIDButton;
@property IBOutlet NSTextField *applicationKey;
@property IBOutlet NSPopUpButton *applicationReaderSlot;
@property IBOutlet NSButton *applicationFrozenSettings;
@property IBOutlet NSButton *applicationFrozenMaster;
@property NSButton *applicationListingRequirement;
@property NSBox *keyChangeSettingsBox;
@property NSPopUpButton *keyChangeAuthentication;
@property IBOutlet NSButton *getApplicationSettingsButton;
@property IBOutlet NSTextField *keysKey;
@property IBOutlet NSPopUpButton *keysReaderSlot;
@property IBOutlet NSTextField *oldKey;
@property IBOutlet NSTextField *replacementKeyField;
@property IBOutlet NSPopUpButton *filesReadRight;
@property IBOutlet NSPopUpButton *filesWriteRight;
@property IBOutlet NSPopUpButton *filesReadWriteRight;
@property IBOutlet NSPopUpButton *filesChangeRight;
@property IBOutlet NSButton *createFileButton;
@property IBOutlet NSButton *deleteFileButton;
@property NSArray<NSButton *> *hardwareButtons;
@property DESFireReader *reader;
@property dispatch_queue_t readerQueue;
@property BOOL connected;
@property BOOL busy;
@property uint32_t firmwareVersion;
@property NSString *settingsContext;
@property NSTextView *scriptView;
@property NSButton *scriptPlayButton;
@property NSButton *scriptStopButton;
@property NSArray<NSButton *> *scriptEditButtons;
@property NSTextField *scriptStatus;
@property NSArray<DFScriptCommand *> *scriptCommands;
@property NSUInteger scriptIndex;
@property BOOL scriptRunning;
@property BOOL scriptStopRequested;
@property NSTimer *scriptPauseTimer;
@property NSMutableArray<NSString *> *recentAIDs;
@property NSArray<NSArray<NSButton *> *> *aidShortcutButtons;
@property NSMapTable<NSButton *, NSTextField *> *keyGeneratorFields;
@property NSLayoutConstraint *tabHeight;
@property NSDictionary<NSString *, NSNumber *> *formHeights;
+ (NSString *)hexASCIIDump:(NSData *)data;
+ (NSString *)commandTitleForOperation:(DFOperation)operation request:(DFRequest *)request dump:(BOOL)dump;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.reader = [DESFireReader new];
    self.readerQueue = dispatch_queue_create("org.desfire.reader", DISPATCH_QUEUE_SERIAL);
    NSMutableArray<NSButton *> *hardware = [NSMutableArray array];
    for (NSView *view in [self allFormViews]) {
        if ([view isKindOfClass:NSButton.class]) {
            NSButton *button = (NSButton *)view;
            if (button.action == @selector(performOperation:) || button.action == @selector(writeFile:) ||
                button.action == @selector(readFile:) || button.action == @selector(dumpFile:)) [hardware addObject:button];
            if (button.action == @selector(fillKey:) && button.tag == 2)
                button.accessibilityLabel = @"Generate random AES key";
        }
        if ([view isKindOfClass:NSTextField.class]) {
            NSTextField *field = (NSTextField *)view;
            if (field.editable) field.delegate = self;
        }
        if ([view isKindOfClass:NSPopUpButton.class]) {
            NSPopUpButton *popup = (NSPopUpButton *)view;
            if (popup.indexOfSelectedItem < 0 && popup.numberOfItems) [popup selectItemAtIndex:0];
        }
        if ([view isKindOfClass:NSScrollView.class]) {
            NSScrollView *scroll = (NSScrollView *)view;
            if ([scroll.documentView isKindOfClass:NSTextView.class]) {
                NSTextView *text = (NSTextView *)scroll.documentView;
                text.horizontallyResizable = NO;
                text.verticallyResizable = YES;
                text.autoresizingMask = NSViewWidthSizable;
                text.textContainer.widthTracksTextView = YES;
                text.textContainer.containerSize = NSMakeSize(scroll.contentSize.width, CGFLOAT_MAX);
            }
        }
    }
    self.hardwareButtons = hardware;
    self.outputView.font = [NSFont monospacedSystemFontOfSize:12 weight:NSFontWeightRegular];
    [self selectButton:self.cardPICC inGroup:@[self.cardPICC, self.cardCustomAid]];
    [self selectButton:self.cardAES inGroup:@[self.cardAES, self.cardReader]];
    [self selectButton:self.applicationNoAuth inGroup:[self applicationAuthentication]];
    [self selectButton:self.keysNoAuth inGroup:[self keyAuthentication]];
    [self selectButton:self.filesNoAuth inGroup:[self fileAuthentication]];
    [self.communicationMode selectItemAtIndex:0];
    self.cardAid.stringValue = self.applicationAid.stringValue;
    [self appendOutput:@"Reader is disconnected, connect before using reader or card operations"];
    [self endCommand];
    [self setupSecuritySettings];
    [self setupInputShortcuts];
    [self setupAutomation];
    [self setupCompactLayout];
    [self updateInterface];
    [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(applicationWillTerminate:)
        name:NSApplicationWillTerminateNotification object:nil];
}

- (void)dealloc {
    [NSNotificationCenter.defaultCenter removeObserver:self];
}

- (NSArray<NSView *> *)allFormViews {
    NSMutableOrderedSet<NSView *> *views = [NSMutableOrderedSet orderedSetWithObject:self.view];
    for (NSTabViewItem *item in self.tabs.tabViewItems) [views addObject:item.view];
    for (NSUInteger index = 0; index < views.count; index++) {
        [views addObjectsFromArray:views[index].subviews];
    }
    return views.array;
}

- (NSArray<NSButton *> *)applicationAuthentication {
    return @[self.applicationNoAuth, self.applicationAES, self.applicationReader];
}

- (NSArray<NSButton *> *)keyAuthentication {
    return @[self.keysNoAuth, self.keysAES, self.keysReader];
}

- (NSArray<NSButton *> *)fileAuthentication {
    return @[self.filesNoAuth, self.filesAES, self.filesReader];
}

- (void)selectButton:(NSButton *)selected inGroup:(NSArray<NSButton *> *)group {
    for (NSButton *button in group) button.state = button == selected ? NSControlStateValueOn : NSControlStateValueOff;
}

- (IBAction)selectionChanged:(NSButton *)sender {
    NSArray<NSArray<NSButton *> *> *groups = @[
        [self applicationAuthentication], [self keyAuthentication], [self fileAuthentication],
        @[self.cardAES, self.cardReader], @[self.cardPICC, self.cardCustomAid]
    ];
    for (NSArray<NSButton *> *group in groups) {
        if ([group containsObject:sender]) {
            [self selectButton:sender inGroup:group];
            break;
        }
    }
    if (sender == self.filesNoAuth) [self.communicationMode selectItemAtIndex:0];
    [self updateInterface];
}

- (IBAction)communicationChanged:(NSPopUpButton *)sender {
    if (sender.indexOfSelectedItem != 0 && self.filesNoAuth.state == NSControlStateValueOn) {
        [self selectButton:self.filesAES inGroup:[self fileAuthentication]];
    }
    [self updateInterface];
}

- (IBAction)optionChanged:(id)sender {
    if ([sender isKindOfClass:NSButton.class] && ((NSButton *)sender).state == NSControlStateValueMixed)
        ((NSButton *)sender).state = NSControlStateValueOff;
    [self updateInterface];
}

- (NSArray<NSArray<NSTextField *> *> *)synchronizedFields {
    return @[@[self.cardKey, self.applicationKey, self.keysKey, self.filesKey],
             @[self.cardAid, self.applicationAid, self.keysAid, self.filesAid]];
}

// Authentication keys and AIDs are shared by all tabs; reader, old and new key fields stay independent.
- (void)synchronizeField:(NSTextField *)field {
    for (NSArray<NSTextField *> *group in [self synchronizedFields]) {
        if (![group containsObject:field]) continue;
        for (NSTextField *other in group)
            if (other != field && ![other.stringValue isEqualToString:field.stringValue]) other.stringValue = field.stringValue;
    }
}

- (void)controlTextDidChange:(NSNotification *)notification {
    if ([notification.object isKindOfClass:NSTextField.class]) {
        [self synchronizeField:notification.object];
    }
    [self updateInterface];
}

- (void)controlTextDidEndEditing:(NSNotification *)notification {
    if ([@[self.cardAid, self.applicationAid, self.keysAid, self.filesAid] containsObject:notification.object]) {
        [self synchronizeField:notification.object];
        [self rememberAID:notification.object];
    }
    [self updateInterface];
}

- (NSArray<NSButton *> *)securityCheckboxes {
    return @[self.applicationRequirement, self.applicationFrozenSettings,
        self.applicationFrozenMaster, self.applicationListingRequirement];
}

- (void)updateSettingsContext {
    NSString *context = self.applicationAid.stringValue.uppercaseString;
    if ([self.settingsContext isEqual:context]) return;
    self.settingsContext = context;
    for (NSButton *button in [self securityCheckboxes]) {
        button.allowsMixedState = YES;
        button.state = NSControlStateValueMixed;
        button.toolTip = @"A dash means unknown - read the settings or explicitly choose this option";
    }
    [self.keyChangeAuthentication selectItem:nil];
    self.keyChangeAuthentication.toolTip = @"No selection means unknown - read the settings or choose a policy";
}

- (BOOL)securitySettingsKnown {
    for (NSButton *button in [self securityCheckboxes])
        if (button.state == NSControlStateValueMixed) return NO;
    uint32_t aid = 0;
    return [self parseAid:self.applicationAid value:&aid] &&
        (!aid || self.keyChangeAuthentication.indexOfSelectedItem >= 0);
}

- (BOOL)parseAid:(NSTextField *)field value:(uint32_t *)value {
    return field.stringValue.length == 6 &&
        [DESFireReader parseUnsigned:field.stringValue base:16 maximum:0xFFFFFF value:value];
}

- (void)limitKeyNumber:(NSPopUpButton *)popup picc:(BOOL)picc {
    for (NSUInteger index = 0; index < popup.numberOfItems; index++) {
        [popup itemAtIndex:index].enabled = !picc || index == 0;
    }
    popup.autoenablesItems = NO;
    if (picc) [popup selectItemAtIndex:0];
    popup.enabled = !picc && !self.busy;
}

- (void)updateInterface {
    BOOL available = self.connected && !self.busy;
    for (NSView *view in [self allFormViews])
        if ([view isKindOfClass:NSControl.class]) ((NSControl *)view).enabled = !self.busy;
    self.connectButton.enabled = !self.connected && !self.busy;
    self.disconnectButton.enabled = available;
    for (NSButton *button in self.hardwareButtons) button.enabled = available;
    uint32_t aid = 0;
    BOOL validApplication = [self parseAid:self.applicationAid value:&aid];
    BOOL picc = validApplication && aid == 0;
    [self updateSettingsContext];
    BOOL validContext = validApplication;
    self.applicationAid.enabled = !self.busy;
    self.applicationRequirement.title = picc
        ? @"Creating applications requires authentication with the PICC master key"
        : @"Creating or deleting files requires authentication with the application master key";
    self.applicationFrozenMaster.title = picc ? @"PICC master key is not changeable anymore" :
        @"Application master key is not changeable anymore";
    self.applicationFrozenSettings.title = picc ? @"PICC key settings are not changeable anymore" :
        @"Application key settings are not changeable anymore";
    self.applicationListingRequirement.title = picc ?
        @"Getting AIDs and key settings requires authentication with the PICC master key" :
        @"Getting file IDs and settings requires authentication with the application master key";
    self.keyChangeSettingsBox.hidden = !validContext || picc;
    self.applicationKeyCount.enabled = !self.busy && validContext && !picc;
    if (picc) [self.applicationKeyCount selectItemAtIndex:0];
    self.createApplicationButton.enabled = available && validContext && !picc && [self securitySettingsKnown];
    self.deleteApplicationButton.enabled = available && validContext && !picc &&
        self.applicationNoAuth.state != NSControlStateValueOn;
    self.setApplicationSettingsButton.enabled = available && validContext && [self securitySettingsKnown] &&
        self.applicationNoAuth.state != NSControlStateValueOn;
    self.getApplicationSettingsButton.enabled = available && validContext;
    uint32_t cardAid = 0;
    BOOL validCard = [self parseAid:self.cardAid value:&cardAid];
    BOOL cardPicc = validCard && cardAid == 0;
    self.cardAid.enabled = !self.busy;
    [self limitKeyNumber:self.cardKeyNumber picc:cardPicc];
    self.getUIDButton.enabled = available && validCard;
    self.configureCardButton.enabled = available &&
        (self.randomUID.state == NSControlStateValueOn || self.disableFormatting.state == NSControlStateValueOn);
    uint32_t keysAid = 0;
    BOOL validKeys = [self parseAid:self.keysAid value:&keysAid];
    [self limitKeyNumber:self.targetKeyNumber picc:validKeys && keysAid == 0];
    [self limitKeyNumber:self.authenticationKeyNumber picc:validKeys && keysAid == 0];
    self.changeKeyButton.enabled = available && validKeys && self.keysNoAuth.state != NSControlStateValueOn;
    uint32_t filesAid = 0;
    BOOL validFile = [self parseAid:self.filesAid value:&filesAid] && filesAid != 0;
    for (NSButton *button in @[self.writeFileButton, self.readFileButton, self.dumpFileButton, self.getFileSettingsButton])
        button.enabled = available && validFile;
    self.createFileButton.enabled = available && validFile;
    self.deleteFileButton.enabled = available && validFile;
    self.getFileSettingsButton.hidden = !self.connected || self.firmwareVersion < DFFileSettingsMinimumFirmware;
    self.changeAccessButton.hidden = !self.connected || self.firmwareVersion < DFChangeFileSettingsMinimumFirmware;
    self.getFileSettingsButton.enabled = available && validFile && !self.getFileSettingsButton.hidden;
    self.changeAccessButton.enabled = available && validFile && !self.changeAccessButton.hidden &&
        self.filesNoAuth.state != NSControlStateValueOn;
    self.scriptPlayButton.enabled = !self.busy;
    self.scriptStopButton.enabled = self.scriptRunning && !self.scriptStopRequested;
    self.scriptView.editable = !self.busy;
    for (NSButton *button in self.scriptEditButtons) button.enabled = !self.busy;
    if (self.formHeights) [self updateTabHeight];
}

- (void)setupCompactLayout {
    NSView *cardPanel = self.cardAid.superview;
    [self.cardPICC removeFromSuperview];
    [self.cardCustomAid removeFromSuperview];
    NSTextField *cardLabel = [NSTextField labelWithString:@"AID"];
    cardLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [cardPanel addSubview:cardLabel];
    [NSLayoutConstraint activateConstraints:@[
        [cardLabel.leadingAnchor constraintEqualToAnchor:cardPanel.leadingAnchor constant:156],
        [cardLabel.centerYAnchor constraintEqualToAnchor:self.cardAid.centerYAnchor]
    ]];
    for (NSLayoutConstraint *constraint in cardPanel.constraints)
        if (constraint.firstAttribute == NSLayoutAttributeTop && constraint.secondItem == cardPanel &&
            constraint.constant >= 46) constraint.constant -= 32;
    NSBox *uidBox = (NSBox *)cardPanel.superview;
    for (NSLayoutConstraint *constraint in uidBox.constraints)
        if (constraint.firstItem == uidBox && constraint.firstAttribute == NSLayoutAttributeHeight &&
            !constraint.secondItem) constraint.constant -= 32;
    NSView *panel = self.applicationAid.superview;
    [self.applicationPICC removeFromSuperview];
    [self.applicationCustomAid removeFromSuperview];
    NSTextField *label = [NSTextField labelWithString:@"Application ID (AID)"];
    label.translatesAutoresizingMaskIntoConstraints = NO;
    [panel addSubview:label];
    [NSLayoutConstraint activateConstraints:@[
        [label.leadingAnchor constraintEqualToAnchor:panel.leadingAnchor constant:16],
        [label.centerYAnchor constraintEqualToAnchor:self.applicationAid.centerYAnchor]
    ]];
    for (NSLayoutConstraint *constraint in panel.constraints)
        if (constraint.firstAttribute == NSLayoutAttributeTop && constraint.secondItem == panel &&
            constraint.firstItem != label && constraint.constant >= 40 &&
            ![constraint.firstItem isKindOfClass:NSScrollView.class])
            constraint.constant -= 28;
    self.tabs.delegate = self;
    NSMutableDictionary *heights = [NSMutableDictionary dictionary];
    [self.view layoutSubtreeIfNeeded];
    for (NSTabViewItem *tab in self.tabs.tabViewItems) {
        if ([tab.identifier isEqual:@"automation"]) continue;
        CGFloat bottom = 0;
        for (NSLayoutConstraint *constraint in tab.view.constraints) {
            if (constraint.firstAttribute != NSLayoutAttributeTop || constraint.secondItem != tab.view ||
                constraint.secondAttribute != NSLayoutAttributeTop || ![constraint.firstItem isKindOfClass:NSView.class]) continue;
            NSView *view = constraint.firstItem;
            if ([view isKindOfClass:NSScrollView.class] || view.hidden) continue;
            CGFloat height = view.frame.size.height;
            for (NSLayoutConstraint *dimension in view.constraints)
                if (dimension.firstItem == view && dimension.firstAttribute == NSLayoutAttributeHeight &&
                    !dimension.secondItem) height = dimension.constant;
            bottom = MAX(bottom, constraint.constant + height);
        }
        heights[tab.label] = @(ceil(bottom + 12));
    }
    self.formHeights = heights;
    for (NSLayoutConstraint *constraint in self.tabs.constraints.copy)
        if (constraint.firstItem == self.tabs && constraint.firstAttribute == NSLayoutAttributeHeight)
            constraint.active = NO;
    self.tabHeight = [self.tabs.heightAnchor constraintEqualToConstant:606];
    self.tabHeight.active = YES;
    for (NSTabViewItem *tab in self.tabs.tabViewItems)
        for (NSView *view in tab.view.subviews) {
            if (![view isKindOfClass:NSScrollView.class]) continue;
            for (NSLayoutConstraint *constraint in view.constraints)
                if (constraint.firstItem == view && constraint.firstAttribute == NSLayoutAttributeHeight)
                    constraint.active = NO;
            [view.bottomAnchor constraintEqualToAnchor:tab.view.bottomAnchor constant:-12].active = YES;
        }
    [self updateTabHeight];
}

- (void)updateTabHeight {
    if (!self.tabHeight) return;
    NSString *label = self.tabs.selectedTabViewItem.label;
    CGFloat height = [self.formHeights[label] doubleValue];
    if ([label isEqual:@"Automation"]) {
        for (NSNumber *formHeight in self.formHeights.allValues) height = MAX(height, formHeight.doubleValue);
    }
    self.tabHeight.constant = height + 46;
    self.view.needsLayout = YES;
    self.tabs.needsLayout = YES;
    [self.view layoutSubtreeIfNeeded];
}

- (void)tabView:(NSTabView *)tabView didSelectTabViewItem:(NSTabViewItem *)item {
    [self updateTabHeight];
}

- (void)viewDidLayout {
    [super viewDidLayout];
    if (self.formHeights) self.tabs.selectedTabViewItem.view.frame = self.tabs.contentRect;
}

- (void)setupSecuritySettings {
    NSView *content = self.applicationFrozenMaster.superview;
    self.applicationListingRequirement = [NSButton checkboxWithTitle:@"" target:self action:@selector(optionChanged:)];
    self.applicationListingRequirement.identifier = @"ApplicationListingRequiresAuthentication";
    self.applicationListingRequirement.translatesAutoresizingMaskIntoConstraints = NO;
    [content addSubview:self.applicationListingRequirement];
    [NSLayoutConstraint activateConstraints:@[
        [self.applicationListingRequirement.leadingAnchor constraintEqualToAnchor:self.applicationFrozenMaster.leadingAnchor],
        [self.applicationListingRequirement.topAnchor constraintEqualToAnchor:self.applicationFrozenMaster.bottomAnchor constant:8],
        [self.applicationListingRequirement.widthAnchor constraintEqualToAnchor:self.applicationFrozenMaster.widthAnchor],
        [self.applicationListingRequirement.heightAnchor constraintEqualToConstant:20]
    ]];
    NSBox *box = [NSBox new];
    box.title = @"Authentication settings for key changes";
    box.translatesAutoresizingMaskIntoConstraints = NO;
    self.keyChangeSettingsBox = box;
    NSView *panel = self.applicationAid.superview;
    [panel addSubview:box];
    [NSLayoutConstraint activateConstraints:@[
        [box.leadingAnchor constraintEqualToAnchor:panel.leadingAnchor constant:12],
        [box.topAnchor constraintEqualToAnchor:panel.topAnchor constant:260],
        [box.widthAnchor constraintEqualToConstant:608],
        [box.heightAnchor constraintEqualToConstant:64]
    ]];
    self.keyChangeAuthentication = [NSPopUpButton new];
    self.keyChangeAuthentication.identifier = @"ApplicationKeyChangeAuthentication";
    self.keyChangeAuthentication.translatesAutoresizingMaskIntoConstraints = NO;
    self.keyChangeAuthentication.target = self;
    self.keyChangeAuthentication.action = @selector(optionChanged:);
    [self.keyChangeAuthentication addItemWithTitle:@"Authentication with application master key (key 0) required"];
    for (NSUInteger key = 1; key <= 13; key++)
        [self.keyChangeAuthentication addItemWithTitle:[NSString stringWithFormat:
            @"Authentication with application key %lu required (must exist in app)", (unsigned long)key]];
    [self.keyChangeAuthentication addItemWithTitle:@"Changing a key requires authentication with that key"];
    [self.keyChangeAuthentication addItemWithTitle:@"Application keys (except key 0) cannot be changed"];
    [box.contentView addSubview:self.keyChangeAuthentication];
    [NSLayoutConstraint activateConstraints:@[
        [self.keyChangeAuthentication.leadingAnchor constraintEqualToAnchor:box.contentView.leadingAnchor constant:12],
        [self.keyChangeAuthentication.trailingAnchor constraintEqualToAnchor:box.contentView.trailingAnchor constant:-12],
        [self.keyChangeAuthentication.topAnchor constraintEqualToAnchor:box.contentView.topAnchor constant:8],
        [self.keyChangeAuthentication.heightAnchor constraintEqualToConstant:28]
    ]];
    for (NSView *view in panel.subviews) {
        if (![view isKindOfClass:NSScrollView.class]) continue;
        NSScrollView *scroll = (NSScrollView *)view;
        if (![scroll.documentView isKindOfClass:NSTextView.class]) continue;
        NSTextView *help = (NSTextView *)scroll.documentView;
        help.string = @"Select PICC (AID 000000) for card-level key settings, or a nonzero AID for application key settings.\n\n"
            @"A dash in a checkbox or an empty key-change policy means unknown. Settings start unknown and are cleared when the AID changes. Read settings or choose all options explicitly before creating an application or setting its security settings. Failed operations leave the current settings unchanged. PICC always has one master key.\n\n"
            @"Security settings are four independent bits. Checked boxes disable master-key changes (bit 0), require authentication for directory/settings queries (bit 1), require authentication for creation/deletion (bit 2), or freeze key settings (bit 3).\n\n"
            @"On PICC level, bit 2 controls application creation. Deleting an application still requires suitable master-key authentication; this tool uses the PICC master key. On application level, bit 2 controls file creation and deletion. Directory access does not grant access to file data; each file has its own access rights.\n\n"
            @"Changing key settings always requires the selected context's master key (key 0). Clearing bit 3 freezes the settings of that context: they cannot subsequently be restored with ChangeKeySettings. Disabling master-key changes with bit 0 is separate from freezing the settings.\n\n"
            @"For nonzero AIDs, bits 4-7 select authentication for changing application keys: master key 0, an existing key 1-13, the key being changed itself (E), or no changes to keys other than key 0 (F). Master-key changes remain governed separately by bit 0 and require authentication with key 0. The upper nibble is reserved and kept at zero on PICC level.\n\n"
            @"Get settings reads all bits. Set settings writes the complete byte, preserving the selected independent options. Create uses these settings for the new application; its initial keys are zero-valued AES keys. The selected application key count includes master key 0 and cannot be changed by Set settings.\n\n"
            @"Reader slots and application key numbers are different. Changing card keys does not change reader slots. Keep keys available before locking access. An application can be recreated only by deleting it (and its data), subject to the card's permissions.";
        help.font = [NSFont systemFontOfSize:11];
    }
}

- (void)setupInputShortcuts {
    self.recentAIDs = [NSMutableArray array];
    NSMutableArray *groups = [NSMutableArray array];
    for (NSTextField *field in @[self.cardAid, self.applicationAid, self.keysAid, self.filesAid]) {
        NSStackView *buttons = [NSStackView new];
        buttons.orientation = NSUserInterfaceLayoutOrientationHorizontal;
        buttons.spacing = 4;
        buttons.translatesAutoresizingMaskIntoConstraints = NO;
        NSMutableArray *group = [NSMutableArray array];
        for (NSUInteger i = 0; i < 4; i++) {
            NSButton *button = [NSButton buttonWithTitle:i ? @"" : @"PICC" target:self action:@selector(selectAID:)];
            button.identifier = [NSString stringWithFormat:@"%@Shortcut%lu", field.identifier, (unsigned long)i];
            button.tag = i;
            button.hidden = i != 0;
            button.font = [NSFont monospacedSystemFontOfSize:11 weight:NSFontWeightRegular];
            [button.widthAnchor constraintEqualToConstant:i ? 66 : 52].active = YES;
            [buttons addArrangedSubview:button];
            [group addObject:button];
        }
        [field.superview addSubview:buttons];
        [NSLayoutConstraint activateConstraints:@[
            [buttons.leadingAnchor constraintEqualToAnchor:field.trailingAnchor constant:8],
            [buttons.centerYAnchor constraintEqualToAnchor:field.centerYAnchor]
        ]];
        [groups addObject:group];
    }
    self.aidShortcutButtons = groups;
    self.keyGeneratorFields = [NSMapTable strongToWeakObjectsMapTable];
    for (NSTextField *field in @[self.oldKey, self.replacementKeyField]) {
        NSView *previous = field;
        for (NSUInteger i = 0; i < (field == self.oldKey ? 1u : 2u); i++) {
            NSButton *button = [NSButton buttonWithTitle:i ? @"⚄" : @"0" target:self action:@selector(fillKey:)];
            button.tag = i ? 2 : 0;
            button.identifier = [NSString stringWithFormat:@"%@%@", field == self.oldKey ? @"OldKey" : @"NewKey", i ? @"Random" : @"Zero"];
            button.toolTip = i ? @"Generate a random AES key." : @"Fill AES key with zeros.";
            if (i) button.accessibilityLabel = @"Generate random replacement AES key";
            button.translatesAutoresizingMaskIntoConstraints = NO;
            [field.superview addSubview:button];
            [NSLayoutConstraint activateConstraints:@[
                [button.leadingAnchor constraintEqualToAnchor:previous.trailingAnchor constant:8],
                [button.centerYAnchor constraintEqualToAnchor:field.centerYAnchor],
                [button.widthAnchor constraintEqualToConstant:40]
            ]];
            [self.keyGeneratorFields setObject:field forKey:button];
            previous = button;
        }
    }
}

- (void)rememberAID:(NSTextField *)field {
    uint32_t aid;
    if (![self parseAid:field value:&aid] || !aid) return;
    NSString *value = [NSString stringWithFormat:@"%06X", aid];
    if ([self.recentAIDs.firstObject isEqual:value]) return;
    [self.recentAIDs removeObject:value];
    [self.recentAIDs insertObject:value atIndex:0];
    if (self.recentAIDs.count > 3) [self.recentAIDs removeLastObject];
    for (NSArray<NSButton *> *group in self.aidShortcutButtons) {
        for (NSUInteger i = 1; i < group.count; i++) {
            group[i].hidden = i > self.recentAIDs.count;
            group[i].title = i <= self.recentAIDs.count ? self.recentAIDs[i - 1] : @"";
        }
    }
}

- (void)selectAID:(NSButton *)sender {
    if (self.busy) return;
    self.keysAid.stringValue = sender.tag ? sender.title : @"000000";
    [self synchronizeField:self.keysAid];
    [self updateInterface];
}

- (IBAction)fillKey:(NSButton *)sender {
    NSTextField *key = [self.keyGeneratorFields objectForKey:sender];
    for (NSView *view in key ? @[] : sender.superview.subviews) {
        if ([view isKindOfClass:NSTextField.class] && ((NSTextField *)view).editable) {
            key = (NSTextField *)view;
            break;
        }
    }
    if (!key) {
        [self appendWarning:@"Cannot locate the AES key field for this generator"];
        [self endCommand];
        return;
    }
    uint8_t bytes[16];
    if (sender.tag == 2) {
        OSStatus status = SecRandomCopyBytes(kSecRandomDefault, sizeof(bytes), bytes);
        if (status != errSecSuccess) {
            [self appendWarning:[NSString stringWithFormat:@"Random key generation failed, code %d", (int)status]];
            [self endCommand];
            return;
        }
    } else {
        memset(bytes, sender.tag == 1 ? 0xFF : 0x00, sizeof(bytes));
    }
    NSMutableString *hex = [NSMutableString stringWithCapacity:32];
    for (NSUInteger index = 0; index < sizeof(bytes); index++) [hex appendFormat:@"%02X", bytes[index]];
    key.stringValue = hex;
    [self synchronizeField:key];
    [self updateInterface];
}

- (DFRequest *)fileRequestForOperation:(DFOperation)operation {
    DFRequest *request = [DFRequest new];
    uint32_t aid = 0;
    if (![self parseAid:self.filesAid value:&aid]) {
        [self appendWarning:@"Application ID must contain exactly six hexadecimal digits"];
        return nil;
    }
    request.aid = aid;
    if (!request.aid) {
        [self appendWarning:@"Select a nonzero application ID, the PICC master application does not contain data files"];
        return nil;
    }
    request.fileID = (uint8_t)self.filesID.indexOfSelectedItem;
    request.authenticationKeyNumber = (uint8_t)self.filesKeyNumber.indexOfSelectedItem;
    request.authenticate = self.filesNoAuth.state != NSControlStateValueOn;
    request.useInternalKey = self.filesReader.state == NSControlStateValueOn;
    request.readerKeyNumber = (uint8_t)self.filesReaderSlot.indexOfSelectedItem;
    request.key = [DESFireReader hexData:self.filesKey.stringValue] ?: [NSData data];
    const uint8_t modes[] = {0, 1, 3};
    NSInteger mode = self.communicationMode.indexOfSelectedItem;
    request.communicationMode = mode >= 0 && mode < 3 ? modes[mode] : UINT8_MAX;
    request.length = 1;
    request.readKey = (uint8_t)self.filesReadRight.indexOfSelectedItem;
    request.writeKey = (uint8_t)self.filesWriteRight.indexOfSelectedItem;
    request.readWriteKey = (uint8_t)self.filesReadWriteRight.indexOfSelectedItem;
    request.changeKey = (uint8_t)self.filesChangeRight.indexOfSelectedItem;
    if (operation == DFCreateFile) {
        uint32_t size = 0;
        if (![DESFireReader parseUnsigned:self.fileCapacity.stringValue base:10 maximum:0xFFFFFF value:&size] || !size) {
            [self appendWarning:@"File capacity must be a decimal number from 1 to 16777215 bytes"];
            return nil;
        }
        request.fileSize = size;
    }
    NSString *error = [request validationErrorForOperation:operation];
    if (error) {
        [self appendWarning:error];
        return nil;
    }
    return request;
}

- (DFRequest *)fileRequest {
    return [self fileRequestForOperation:DFReadFile];
}

- (void)setAuthenticationOnRequest:(DFRequest *)request noAuth:(NSButton *)noAuth
    reader:(NSButton *)reader key:(NSTextField *)key slot:(NSPopUpButton *)slot {
    request.authenticate = noAuth.state != NSControlStateValueOn;
    request.useInternalKey = reader.state == NSControlStateValueOn;
    request.key = [DESFireReader hexData:key.stringValue] ?: [NSData data];
    request.readerKeyNumber = (uint8_t)slot.indexOfSelectedItem;
}

- (DFRequest *)requestForOperation:(DFOperation)operation {
    if (operation == DFCreateFile || operation == DFDeleteFile || operation == DFChangeFileSettings ||
        operation == DFGetFileSettings)
        return [self fileRequestForOperation:operation];
    DFRequest *request = [DFRequest new];
    if (operation == DFGetUID || operation == DFFormatCard || operation == DFConfigureCard ||
        operation == DFInspectMasterKey) {
        [self setAuthenticationOnRequest:request noAuth:nil reader:self.cardReader key:self.cardKey slot:self.cardReaderSlot];
        if (operation == DFGetUID) {
            uint32_t aid = 0;
            if (![self parseAid:self.cardAid value:&aid]) {
                [self appendWarning:@"Card AID must contain exactly six hexadecimal digits"];
                return nil;
            }
            request.aid = aid;
            request.authenticationKeyNumber = aid ? (uint8_t)self.cardKeyNumber.indexOfSelectedItem : 0;
        }
        request.randomUID = self.randomUID.state == NSControlStateValueOn;
        request.disableFormatting = self.disableFormatting.state == NSControlStateValueOn;
    } else if (operation == DFCreateApplication || operation == DFDeleteApplication ||
               operation == DFGetKeySettings || operation == DFChangeKeySettings) {
        [self setAuthenticationOnRequest:request noAuth:self.applicationNoAuth reader:self.applicationReader
            key:self.applicationKey slot:self.applicationReaderSlot];
        {
            uint32_t aid = 0;
            if (![self parseAid:self.applicationAid value:&aid]) {
                [self appendWarning:@"Application ID must contain exactly six hexadecimal digits"];
                return nil;
            }
            request.aid = aid;
        }
        [self updateSettingsContext];
        if ((operation == DFCreateApplication || operation == DFChangeKeySettings) && ![self securitySettingsKnown]) {
            [self appendWarning:@"Security settings are unknown; read them or explicitly select all options before creating/changing settings"];
            return nil;
        }
        request.maximumKeys = request.aid ? (uint8_t)(self.applicationKeyCount.indexOfSelectedItem + 1) : 1;
        request.keySettings = [DESFireReader keySettingsWithAuthentication:self.applicationRequirement.state == NSControlStateValueOn
            frozenSettings:self.applicationFrozenSettings.state == NSControlStateValueOn
            frozenMaster:self.applicationFrozenMaster.state == NSControlStateValueOn];
        request.keySettings = (request.keySettings & ~0x02) |
            (self.applicationListingRequirement.state == NSControlStateValueOn ? 0 : 0x02);
        if (request.aid) request.keySettings |= (uint8_t)(self.keyChangeAuthentication.indexOfSelectedItem << 4);
    } else if (operation == DFChangeKey) {
        [self setAuthenticationOnRequest:request noAuth:self.keysNoAuth reader:self.keysReader key:self.keysKey slot:self.keysReaderSlot];
        uint32_t aid = 0;
        if (![self parseAid:self.keysAid value:&aid]) {
            [self appendWarning:@"Application ID must contain exactly six hexadecimal digits"];
            return nil;
        }
        request.aid = aid;
        request.changedKeyNumber = (uint8_t)self.targetKeyNumber.indexOfSelectedItem;
        request.authenticationKeyNumber = (uint8_t)self.authenticationKeyNumber.indexOfSelectedItem;
        request.oldKey = [DESFireReader hexData:self.oldKey.stringValue] ?: [NSData data];
        request.replacementKey = [DESFireReader hexData:self.replacementKeyField.stringValue] ?: [NSData data];
    } else if (operation == DFStoreReaderKey) {
        request.key = [DESFireReader hexData:self.readerKey.stringValue] ?: [NSData data];
        request.readerKeyNumber = (uint8_t)self.readerSlot.indexOfSelectedItem;
    } else if (operation == DFLockReaderKeys || operation == DFUnlockReaderKeys) {
        request.password = [self.readerPassword.stringValue dataUsingEncoding:NSASCIIStringEncoding] ?: [NSData data];
    } else if (operation == DFSetSpeed) {
        request.txSpeed = (uint8_t)self.transmitSpeed.indexOfSelectedItem;
        request.rxSpeed = (uint8_t)self.receiveSpeed.indexOfSelectedItem;
    }
    NSString *error = [request validationErrorForOperation:operation];
    if (error) {
        [self appendWarning:error];
        return nil;
    }
    return request;
}

- (NSString *)confirmationForOperation:(DFOperation)operation request:(DFRequest *)request {
    switch (operation) {
        case DFDeleteApplication:
            return [NSString stringWithFormat:@"Permanently delete application %06X and all its files?\nThis API authenticates with PICC master key 0.", request.aid];
        case DFDeleteFile:
            return [NSString stringWithFormat:@"Permanently delete file %u in application %06X?", request.fileID, request.aid];
        case DFFormatCard:
            return request.formatKeyType == DFMasterKeyDES ?
                @"Permanently delete all applications and files on the card?\nAuthentication uses the factory DES null PICC master key; the entered AES key/reader slot is ignored. The key and its type are not reset." :
                @"Permanently delete all applications and files on the card?\nAuthentication uses the AES PICC master key (AID 000000, key 0). The key and its type are not reset.";
        case DFConfigureCard:
            return [NSString stringWithFormat:@"Activate these permanent card settings?\nRandom UID: %@\nDisable formatting: %@\nActivated options cannot be undone. Unchecked options are not a reset command.",
                request.randomUID ? @"activate" : @"not requested", request.disableFormatting ? @"activate" : @"not requested"];
        case DFConvertToAES:
            return @"Convert a factory card's DES null master key to an AES null master key?\nOnly for a factory DES key of eight zero bytes. Like Windows, up to 10 attempts are made; the entered AES key/reader slot is ignored. Success is checked by an authenticated AES null-key UID read.";
        case DFChangeKey:
            return [NSString stringWithFormat:@"Change AES key %u in application %06X?\nAccess may be lost without the new key.", request.changedKeyNumber, request.aid];
        case DFChangeKeySettings:
            return @"Change the selected application's key settings?\nLocked settings and a locked master key cannot be unlocked again.";
        case DFCreateApplication:
            return (request.keySettings & 9) != 9 ?
                @"Create an AES application with permanently locked settings or master key?" : nil;
        case DFStoreReaderKey:
            return [NSString stringWithFormat:@"Overwrite AES key in reader slot %u?", request.readerKeyNumber];
        case DFLockReaderKeys:
            return @"Lock the reader's key memory for writes?\nKeep the password to unlock it later. The application does not save it.";
        case DFSetSpeed:
            return @"Store the selected RF baud rates permanently in the reader?";
        case DFChangeFileSettings:
            return @"Change communication mode and access rights of this file?\nThe SDK API does not accept the selected authentication key number; it receives only the AES key/reader slot and access-right parameters. Setting change rights to 'not allowed' can permanently prevent later changes.";
        default: return nil;
    }
}

- (void)confirmMessage:(NSString *)message completion:(void (^)(BOOL))completion {
    NSAlert *alert = [NSAlert new];
    alert.alertStyle = NSAlertStyleWarning;
    alert.messageText = @"Confirm change";
    alert.informativeText = message;
    [alert addButtonWithTitle:@"Cancel"];
    [alert addButtonWithTitle:@"Continue"];
    [alert beginSheetModalForWindow:self.view.window completionHandler:^(NSModalResponse response) {
        completion(response == NSAlertSecondButtonReturn);
    }];
}

- (void)applyResult:(DFResult *)result operation:(DFOperation)operation {
    if (!result.success) return;
    if (operation == DFOpenReader) {
        self.firmwareVersion = result.firmwareVersion;
    } else if (operation == DFCloseReader) {
        self.firmwareVersion = 0;
    } else if (operation == DFGetFileSettings && result.hasFileSettings) {
        NSInteger mode = result.communicationMode == 0 ? 0 : result.communicationMode == 1 ? 1 : result.communicationMode == 3 ? 2 : -1;
        if (mode >= 0) [self.communicationMode selectItemAtIndex:mode];
        [self.filesReadRight selectItemAtIndex:result.readKey];
        [self.filesWriteRight selectItemAtIndex:result.writeKey];
        [self.filesReadWriteRight selectItemAtIndex:result.readWriteKey];
        [self.filesChangeRight selectItemAtIndex:result.changeKey];
        if (result.fileType <= 1) self.fileCapacity.stringValue = [NSString stringWithFormat:@"%u", result.fileSize];
    } else if (operation == DFGetKeySettings) {
        [self updateSettingsContext];
        self.applicationFrozenSettings.state = (result.keySettings & 8) ? NSControlStateValueOff : NSControlStateValueOn;
        self.applicationRequirement.state = (result.keySettings & 4) ? NSControlStateValueOff : NSControlStateValueOn;
        self.applicationListingRequirement.state = (result.keySettings & 2) ? NSControlStateValueOff : NSControlStateValueOn;
        [self.keyChangeAuthentication selectItemAtIndex:result.keySettings >> 4];
        self.applicationFrozenMaster.state = (result.keySettings & 1) ? NSControlStateValueOff : NSControlStateValueOn;
        uint8_t count = result.maximumKeys & 0x0F;
        if ([self.settingsContext isEqual:@"000000"]) [self.applicationKeyCount selectItemAtIndex:0];
        else if (count >= 1 && count <= 14) [self.applicationKeyCount selectItemAtIndex:count - 1];
        else [self appendOutput:[NSString stringWithFormat:@"Unexpected key count %u from card, key count menu not changed", count]];
    } else if (operation == DFGetSpeed) {
        if (result.txSpeed <= 3 && result.rxSpeed <= 3) {
            [self.transmitSpeed selectItemAtIndex:result.txSpeed];
            [self.receiveSpeed selectItemAtIndex:result.rxSpeed];
        } else [self appendOutput:@"Reader returned an unsupported RF baud rate code, menus not changed"];
    } else if (operation == DFConvertToAES) {
        self.cardKey.stringValue = @"00000000000000000000000000000000";
        [self synchronizeField:self.cardKey];
        [self selectButton:self.cardAES inGroup:@[self.cardAES, self.cardReader]];
        self.cardAid.stringValue = @"000000";
        [self synchronizeField:self.cardAid];
        [self.cardKeyNumber selectItemAtIndex:0];
        [self appendOutput:@"Authentication key fields now contain the verified AES null key, reader slots were not changed"];
    }
}

- (void)executeOperation:(DFOperation)operation request:(DFRequest *)request {
    [self recordOperation:operation request:request dump:NO output:nil];
    [self appendOutput:[request keyDescriptionForOperation:operation showKeys:YES] mark:DFInputMark];
    dispatch_async(self.readerQueue, ^{
        DFResult *result = [self.reader execute:operation request:request];
        BOOL connected = self.reader.connected;
        dispatch_async(dispatch_get_main_queue(), ^{
            self.connected = connected;
            [self appendOutput:result.message mark:DFOutputMark];
            [self applyResult:result operation:operation];
            [self endCommand];
            [self finishFileOperation];
        });
    });
}

+ (NSString *)commandNameForOperation:(DFOperation)operation {
    switch (operation) {
        case DFOpenReader: return @"Connect Reader";
        case DFCloseReader: return @"Disconnect Reader";
        case DFGetUID: return @"Get Real UID";
        case DFFreeMemory: return @"Get Free Memory";
        case DFCreateApplication: return @"Create Application";
        case DFDeleteApplication: return @"Delete Application";
        case DFCreateFile: return @"Create File";
        case DFDeleteFile: return @"Delete File";
        case DFReadFile: return @"Read File";
        case DFWriteFile: return @"Write File";
        case DFGetKeySettings: return @"Get Application settings";
        case DFChangeKeySettings: return @"Set Application settings";
        case DFChangeKey: return @"Change AES Key";
        case DFFormatCard: return @"Format Card";
        case DFRandomUID: return @"Enable Random UID";
        case DFConvertToAES: return @"Convert Card Master Key to AES";
        case DFStoreReaderKey: return @"Store AES Key in Reader";
        case DFLockReaderKeys: return @"Lock Reader Keys";
        case DFUnlockReaderKeys: return @"Unlock Reader Keys";
        case DFGetSpeed: return @"Get RF Baud Rates";
        case DFSetSpeed: return @"Set RF Baud Rates";
        case DFInspectMasterKey: return @"Get Card Info";
        case DFGetFileSize: return @"Get File Capacity";
        case DFConfigureCard: return @"Configure Card";
        case DFChangeFileSettings: return @"Change File Access Rights";
        case DFGetFileSettings: return @"Get File Settings";
    }
    return @"Unknown Operation";
}

+ (NSString *)commandTitleForOperation:(DFOperation)operation request:(DFRequest *)p dump:(BOOL)dump {
    NSString *name = dump ? @"Dump File" : [self commandNameForOperation:operation];
    NSString *context = p.aid ? [NSString stringWithFormat:@"for AID %06X", p.aid] :
        @"for PICC / master application (AID 000000)";
    if (operation == DFCreateApplication || operation == DFDeleteApplication)
        return [NSString stringWithFormat:@"%@ with ID %06X", name, p.aid];
    if (operation == DFCreateFile || operation == DFDeleteFile || operation == DFReadFile || operation == DFWriteFile)
        return [NSString stringWithFormat:@"%@ %u for AID %06X", name, p.fileID, p.aid];
    if (operation == DFGetFileSettings || operation == DFGetFileSize || operation == DFChangeFileSettings)
        return [NSString stringWithFormat:@"%@ for File %u, AID %06X", name, p.fileID, p.aid];
    if (operation == DFChangeKey)
        return [NSString stringWithFormat:@"%@ %u %@", name, p.changedKeyNumber, context];
    if (operation == DFGetKeySettings || operation == DFChangeKeySettings || operation == DFGetUID)
        return [NSString stringWithFormat:@"%@ %@", name, context];
    if (operation == DFFormatCard || operation == DFRandomUID || operation == DFConfigureCard ||
        operation == DFConvertToAES || operation == DFInspectMasterKey)
        return [name stringByAppendingString:@" for PICC / master application (AID 000000)"];
    return name;
}

- (IBAction)performOperation:(NSButton *)sender {
    if (!self.connected || self.busy || !sender.enabled) return;
    [self.view.window makeFirstResponder:nil];
    DFOperation operation = sender.tag;
    DFRequest *request = [self requestForOperation:operation];
    [self appendOutput:request ? [ViewController commandTitleForOperation:operation request:request dump:NO] :
        [ViewController commandNameForOperation:operation] mark:DFCommandMark];
    if (!request) {
        [self endCommand];
        return;
    }
    self.busy = YES;
    [self updateInterface];
    NSString *confirmation = [self confirmationForOperation:operation request:request];
    if (confirmation) {
        [self confirmMessage:confirmation completion:^(BOOL confirmed) {
            if (confirmed) [self executeOperation:operation request:request];
            else {
                [self appendOutput:@"Cancelled, no command was sent to the reader"];
                [self endCommand];
                [self finishFileOperation];
            }
        }];
    } else [self executeOperation:operation request:request];
}

- (DFRequest *)fileRequestForCommand:(NSString *)command {
    if (!self.connected || self.busy) return nil;
    [self.view.window makeFirstResponder:nil];
    DFRequest *request = [self fileRequest];
    [self appendOutput:request ? [ViewController commandTitleForOperation:[command isEqual:@"Write File"] ? DFWriteFile : DFReadFile
        request:request dump:[command isEqual:@"Dump File"]] : command mark:DFCommandMark];
    if (!request) {
        [self endCommand];
        return nil;
    }
    [self beginFileOperation];
    return request;
}

- (BOOL)beginFileOperation {
    if (!self.connected || self.busy) return NO;
    self.busy = YES;
    [self updateInterface];
    return YES;
}

- (void)finishFileOperation {
    self.busy = NO;
    [self updateInterface];
}

- (void)performFileRequest:(DFRequest *)request writing:(BOOL)writing saveURL:(NSURL *)saveURL {
    if (writing) {
        NSString *message = [NSString stringWithFormat:
            @"Write %lu bytes to AID %06X, file %u at offset 0?\nExisting bytes will be overwritten after checking the card file's capacity.",
            (unsigned long)request.data.length, request.aid, request.fileID];
        [self confirmMessage:message completion:^(BOOL confirmed) {
            if (confirmed) [self executeFileRequest:request writing:YES saveURL:nil];
            else {
                [self appendOutput:@"Cancelled, no card data was written"];
                [self endCommand];
                [self finishFileOperation];
            }
        }];
    } else [self executeFileRequest:request writing:NO saveURL:saveURL];
}

- (void)executeFileRequest:(DFRequest *)request writing:(BOOL)writing saveURL:(NSURL *)saveURL {
    [self recordOperation:writing ? DFWriteFile : DFReadFile request:request dump:!writing && !saveURL output:saveURL];
    [self appendOutput:[request keyDescriptionForOperation:writing ? DFWriteFile : DFReadFile showKeys:YES] mark:DFInputMark];
    if (writing) [self appendOutput:[ViewController hexASCIIDump:request.data] mark:DFInputMark];
    if (saveURL) [self appendOutput:[@"Output file " stringByAppendingString:saveURL.lastPathComponent] mark:DFInputMark];
    dispatch_async(self.readerQueue, ^{
        DFResult *result = [self.reader transferFile:request writing:writing];
        dispatch_async(dispatch_get_main_queue(), ^{
            [self appendOutput:result.message mark:DFOutputMark];
            if (result.success) {
                if (writing) {
                    [self appendOutput:[NSString stringWithFormat:
                        @"Wrote %u bytes at offset 0, remaining bytes of the card file unchanged", request.length]];
                } else if (saveURL) {
                    NSError *error = nil;
                    if ([result.data writeToURL:saveURL options:NSDataWritingAtomic error:&error]) {
                        [self appendOutput:[NSString stringWithFormat:@"Saved %lu bytes to %@",
                            (unsigned long)result.data.length, saveURL.lastPathComponent]];
                    } else {
                        [self appendWarning:[NSString stringWithFormat:
                            @"Card read succeeded, but saving the local file failed, %@", error.localizedDescription]];
                    }
                } else {
                    [self appendOutput:[ViewController hexASCIIDump:result.data] mark:DFOutputMark];
                }
            }
            [self endCommand];
            [self finishFileOperation];
        });
    });
}

- (IBAction)writeFile:(id)sender {
    DFRequest *request = [self fileRequestForCommand:[ViewController commandNameForOperation:DFWriteFile]];
    if (!request) return;
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    panel.title = @"Select a file to write to the card";
    panel.canChooseFiles = YES;
    panel.canChooseDirectories = NO;
    panel.allowsMultipleSelection = NO;
    [panel beginSheetModalForWindow:self.view.window completionHandler:^(NSModalResponse response) {
        if (response != NSModalResponseOK) {
            [self appendOutput:@"Cancelled, no card data was written"];
            [self endCommand];
            [self finishFileOperation];
            return;
        }
        NSError *error = nil;
        NSData *data = [NSData dataWithContentsOfURL:panel.URL options:NSDataReadingMappedIfSafe error:&error];
        if (!data) {
            [self appendWarning:[NSString stringWithFormat:@"Cannot open file, %@", error.localizedDescription]];
            [self endCommand];
            [self finishFileOperation];
            return;
        }
        if (data.length == 0 || data.length > UINT16_MAX) {
            [self appendWarning:@"Select a file containing 1 to 65535 bytes, no card data was written"];
            [self endCommand];
            [self finishFileOperation];
            return;
        }
        request.data = data;
        [self appendOutput:[@"Input file " stringByAppendingString:panel.URL.lastPathComponent] mark:DFInputMark];
        [self performFileRequest:request writing:YES saveURL:nil];
    }];
}

- (IBAction)readFile:(id)sender {
    DFRequest *request = [self fileRequestForCommand:[ViewController commandNameForOperation:DFReadFile]];
    if (!request) return;
    NSSavePanel *panel = [NSSavePanel savePanel];
    panel.title = @"Save card file";
    panel.nameFieldStringValue = [NSString stringWithFormat:@"AID-%06X-file-%u.bin", request.aid, request.fileID];
    [panel beginSheetModalForWindow:self.view.window completionHandler:^(NSModalResponse response) {
        if (response == NSModalResponseOK) {
            [self performFileRequest:request writing:NO saveURL:panel.URL];
        } else {
            [self appendOutput:@"Cancelled, no command was sent to the reader"];
            [self endCommand];
            [self finishFileOperation];
        }
    }];
}

- (IBAction)dumpFile:(id)sender {
    DFRequest *request = [self fileRequestForCommand:@"Dump File"];
    if (request) [self performFileRequest:request writing:NO saveURL:nil];
}

+ (NSString *)hexASCIIDump:(NSData *)data {
    NSMutableString *dump = [NSMutableString stringWithFormat:@"Offset    Hex                                               ASCII\n"];
    const uint8_t *bytes = data.bytes;
    for (NSUInteger offset = 0; offset < data.length; offset += 16) {
        [dump appendFormat:@"%08lX  ", (unsigned long)offset];
        NSMutableString *ascii = [NSMutableString string];
        for (NSUInteger column = 0; column < 16; column++) {
            if (column == 8) [dump appendString:@" "];
            if (offset + column < data.length) {
                if (column == 8) [ascii appendString:@" "];
                uint8_t byte = bytes[offset + column];
                [dump appendFormat:@"%02X ", byte];
                [ascii appendFormat:@"%c", byte >= 0x20 && byte <= 0x7E ? byte : '.'];
            } else {
                [dump appendString:@"   "];
            }
        }
        [dump appendFormat:@" |%@|\n", ascii];
    }
    return dump;
}

- (void)appendOutput:(NSString *)message {
    [self appendOutput:message mark:DFNoteMark];
}

- (void)appendWarning:(NSString *)message {
    [self appendOutput:message mark:DFWarningMark];
}

- (void)endCommand {
    [self appendText:@"\n"];
}

- (void)appendOutput:(NSString *)message mark:(NSString *)mark {
    NSString *text = DFMarkLines(message, mark);
    if (text.length) [self appendText:[text stringByAppendingString:@"\n"]];
}

- (void)appendText:(NSString *)text {
    [self.outputView.textStorage appendAttributedString:[[NSAttributedString alloc]
        initWithString:text attributes:@{
            NSFontAttributeName: [NSFont monospacedSystemFontOfSize:12 weight:NSFontWeightRegular],
            NSForegroundColorAttributeName: NSColor.textColor
        }]];
    [self.outputView scrollRangeToVisible:NSMakeRange(self.outputView.string.length, 0)];
}

- (void)changeReaderConnection:(DFOperation)operation {
    if (self.busy || (operation == DFOpenReader && self.connected) ||
        (operation == DFCloseReader && !self.connected)) return;
    self.busy = YES;
    [self recordOperation:operation request:[DFRequest new] dump:NO output:nil];
    [self updateInterface];
    [self appendOutput:[ViewController commandNameForOperation:operation] mark:DFCommandMark];
    dispatch_async(self.readerQueue, ^{
        DFResult *result = [self.reader execute:operation request:[DFRequest new]];
        BOOL connected = self.reader.connected;
        dispatch_async(dispatch_get_main_queue(), ^{
            self.connected = connected;
            [self applyResult:result operation:operation];
            self.busy = NO;
            [self appendOutput:result.message mark:DFOutputMark];
            [self endCommand];
            [self updateInterface];
        });
    });
}

- (IBAction)connectReader:(id)sender {
    [self changeReaderConnection:DFOpenReader];
}

- (IBAction)disconnectReader:(id)sender {
    [self changeReaderConnection:DFCloseReader];
}

- (void)setupAutomation {
    NSTabViewItem *tab = [[NSTabViewItem alloc] initWithIdentifier:@"automation"];
    tab.label = @"Automation";
    NSView *panel = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 956, 464)];
    NSBox *box = [[NSBox alloc] initWithFrame:NSZeroRect];
    box.title = @"Script";
    box.translatesAutoresizingMaskIntoConstraints = NO;
    [panel addSubview:box];
    [NSLayoutConstraint activateConstraints:@[
        [box.leadingAnchor constraintEqualToAnchor:panel.leadingAnchor constant:12],
        [box.trailingAnchor constraintEqualToAnchor:panel.trailingAnchor constant:-12],
        [box.topAnchor constraintEqualToAnchor:panel.topAnchor constant:12],
        [box.bottomAnchor constraintEqualToAnchor:panel.bottomAnchor constant:-12]
    ]];
    NSView *content = box.contentView;
    NSMutableArray<NSButton *> *edit = [NSMutableArray array];
    NSStackView *buttons = [[NSStackView alloc] initWithFrame:NSZeroRect];
    buttons.spacing = 8;
    buttons.orientation = NSUserInterfaceLayoutOrientationHorizontal;
    buttons.translatesAutoresizingMaskIntoConstraints = NO;
    NSArray<NSString *> *titles = @[@"Play", @"Stop", @"Save", @"Load", @"Clear"];
    NSArray<NSString *> *actions = @[@"playScript:", @"stopScript:", @"saveScript:", @"loadScript:", @"clearScript:"];
    for (NSUInteger i = 0; i < titles.count; i++) {
        NSButton *button = [NSButton buttonWithTitle:titles[i] target:self action:NSSelectorFromString(actions[i])];
        button.identifier = [@"Script" stringByAppendingString:titles[i]];
        [buttons addArrangedSubview:button];
        if (i == 0) self.scriptPlayButton = button;
        else if (i == 1) self.scriptStopButton = button;
        else [edit addObject:button];
    }
    self.scriptEditButtons = edit;
    [content addSubview:buttons];
    self.scriptStatus = [NSTextField labelWithString:@"One card per Play - stops on the first error"];
    self.scriptStatus.translatesAutoresizingMaskIntoConstraints = NO;
    [content addSubview:self.scriptStatus];
    NSTextField *label = [NSTextField labelWithString:@"Commands"];
    label.translatesAutoresizingMaskIntoConstraints = NO;
    [content addSubview:label];
    NSScrollView *scroll = [[NSScrollView alloc] initWithFrame:NSZeroRect];
    scroll.translatesAutoresizingMaskIntoConstraints = NO;
    scroll.hasVerticalScroller = YES;
    scroll.hasHorizontalScroller = YES;
    scroll.borderType = NSBezelBorder;
    self.scriptView = [[NSTextView alloc] initWithFrame:NSMakeRect(0, 0, 880, 300)];
    self.scriptView.accessibilityIdentifier = @"ScriptCommands";
    self.scriptView.richText = NO;
    self.scriptView.font = [NSFont monospacedSystemFontOfSize:12 weight:NSFontWeightRegular];
    self.scriptView.automaticQuoteSubstitutionEnabled = NO;
    self.scriptView.automaticDashSubstitutionEnabled = NO;
    self.scriptView.automaticTextReplacementEnabled = NO;
    self.scriptView.continuousSpellCheckingEnabled = NO;
    self.scriptView.autoresizingMask = NSViewNotSizable;
    self.scriptView.horizontallyResizable = YES;
    self.scriptView.textContainer.widthTracksTextView = NO;
    self.scriptView.textContainer.containerSize = NSMakeSize(CGFLOAT_MAX, CGFLOAT_MAX);
    self.scriptView.minSize = NSMakeSize(0, 0);
    self.scriptView.maxSize = NSMakeSize(CGFLOAT_MAX, CGFLOAT_MAX);
    self.scriptView.verticallyResizable = YES;
    self.scriptView.string = @"# DESFire Script 1\n# GUI commands are recorded here. Keys and passwords are plaintext.\n";
    scroll.documentView = self.scriptView;
    [content addSubview:scroll];
    [NSLayoutConstraint activateConstraints:@[
        [buttons.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:12],
        [buttons.topAnchor constraintEqualToAnchor:content.topAnchor constant:8],
        [self.scriptStatus.leadingAnchor constraintEqualToAnchor:buttons.trailingAnchor constant:16],
        [self.scriptStatus.centerYAnchor constraintEqualToAnchor:buttons.centerYAnchor],
        [self.scriptStatus.trailingAnchor constraintLessThanOrEqualToAnchor:content.trailingAnchor constant:-12],
        [label.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:12],
        [label.topAnchor constraintEqualToAnchor:buttons.bottomAnchor constant:12],
        [scroll.leadingAnchor constraintEqualToAnchor:label.leadingAnchor],
        [scroll.trailingAnchor constraintEqualToAnchor:content.trailingAnchor constant:-12],
        [scroll.topAnchor constraintEqualToAnchor:label.bottomAnchor constant:6],
        [scroll.bottomAnchor constraintEqualToAnchor:content.bottomAnchor constant:-12]
    ]];
    tab.view = panel;
    [self.tabs addTabViewItem:tab];
}

- (void)recordOperation:(DFOperation)operation request:(DFRequest *)request dump:(BOOL)dump output:(NSURL *)output {
    if (self.scriptRunning) return;
    NSString *line = [DFScript recordOperation:operation request:request dump:dump output:output];
    NSString *script = self.scriptView.string;
    self.scriptView.string = [NSString stringWithFormat:@"%@%@%@\n", script,
        script.length && ![script hasSuffix:@"\n"] ? @"\n" : @"", line];
}

- (void)saveScript:(id)sender {
    if (self.busy) return;
    self.busy = YES;
    [self updateInterface];
    [self confirmMessage:@"Scripts may contain plaintext keys, passwords and card data. Save this script to disk?"
        completion:^(BOOL confirmed) {
        if (!confirmed) { [self finishFileOperation]; return; }
        NSSavePanel *panel = [NSSavePanel savePanel];
        panel.nameFieldStringValue = @"card.desfire";
        [panel beginSheetModalForWindow:self.view.window completionHandler:^(NSModalResponse response) {
            if (response == NSModalResponseOK) {
                NSError *error = nil;
                if (![self.scriptView.string writeToURL:panel.URL atomically:YES encoding:NSUTF8StringEncoding error:&error])
                    [self appendWarning:[@"Cannot save script, " stringByAppendingString:error.localizedDescription]];
                else [self appendOutput:@"Script saved"];
            }
            [self finishFileOperation];
        }];
    }];
}

- (void)loadScript:(id)sender {
    if (self.busy) return;
    self.busy = YES;
    [self updateInterface];
    [self confirmMessage:@"Replace the Commands text with a script from disk? Unsaved edits will be lost."
        completion:^(BOOL confirmed) {
        if (!confirmed) { [self finishFileOperation]; return; }
        NSOpenPanel *panel = [NSOpenPanel openPanel];
        panel.canChooseDirectories = NO;
        panel.allowsMultipleSelection = NO;
        [panel beginSheetModalForWindow:self.view.window completionHandler:^(NSModalResponse response) {
            if (response == NSModalResponseOK) {
                NSError *error = nil;
                NSString *script = [NSString stringWithContentsOfURL:panel.URL encoding:NSUTF8StringEncoding error:&error];
                if (!script) [self appendWarning:[@"Cannot load script, " stringByAppendingString:error.localizedDescription]];
                else {
                    self.scriptView.string = script;
                    self.scriptStatus.stringValue = @"Script loaded - not executed";
                }
            }
            [self finishFileOperation];
        }];
    }];
}

- (void)clearScript:(id)sender {
    if (self.busy) return;
    self.busy = YES;
    [self updateInterface];
    [self confirmMessage:@"Clear all script commands? Unsaved edits will be lost." completion:^(BOOL confirmed) {
        if (confirmed) self.scriptView.string = @"";
        [self finishFileOperation];
    }];
}

- (void)playScript:(id)sender {
    if (self.busy) return;
    [self scrollScriptToLeft];
    NSString *error = nil;
    NSArray<DFScriptCommand *> *commands = [DFScript parse:self.scriptView.string error:&error];
    if (!commands) {
        self.scriptStatus.stringValue = error;
        [self appendWarning:error];
        return;
    }
    BOOL connected = self.connected;
    for (DFScriptCommand *c in commands) {
        if (c.pause) continue;
        if (c.operation == DFOpenReader) connected = YES;
        else if (c.operation == DFCloseReader) connected = NO;
        else if (!connected) {
            [self appendWarning:[NSString stringWithFormat:@"Line %lu - ConnectReader is required before this command", (unsigned long)c.line]];
            return;
        }
    }
    self.scriptCommands = commands;
    self.scriptIndex = 0;
    self.scriptRunning = YES;
    self.scriptStopRequested = NO;
    self.busy = YES;
    [self updateInterface];
    [self runNextScriptCommand];
}

- (void)stopScript:(id)sender {
    self.scriptStopRequested = YES;
    if (self.scriptPauseTimer) {
        [self finishScript:@"Script stopped during pause"];
        return;
    }
    self.scriptStatus.stringValue = @"Stopping after the current command";
    [self updateInterface];
}

- (void)scrollScriptToLeft {
    NSScrollView *scroll = self.scriptView.enclosingScrollView;
    NSPoint origin = scroll.contentView.bounds.origin;
    origin.x = 0;
    [scroll.contentView scrollToPoint:origin];
    [scroll reflectScrolledClipView:scroll.contentView];
}

- (void)finishScript:(NSString *)status {
    [self scrollScriptToLeft];
    [self.scriptPauseTimer invalidate];
    self.scriptPauseTimer = nil;
    self.scriptStatus.stringValue = status;
    [self appendOutput:status];
    [self endCommand];
    self.scriptCommands = nil;
    self.scriptRunning = NO;
    self.busy = NO;
    [self updateInterface];
}

- (void)runNextScriptCommand {
    if (self.scriptStopRequested) { [self finishScript:@"Script stopped"]; return; }
    if (self.scriptIndex == self.scriptCommands.count) { [self finishScript:@"Script completed - ready for the next card"]; return; }
    DFScriptCommand *c = self.scriptCommands[self.scriptIndex];
    self.scriptStatus.stringValue = [NSString stringWithFormat:@"Line %lu - %@", (unsigned long)c.line, c.name];
    __block NSUInteger line = 0;
    NSString *script = self.scriptView.string;
    [script enumerateSubstringsInRange:NSMakeRange(0, script.length)
        options:NSStringEnumerationByLines | NSStringEnumerationSubstringNotRequired
        usingBlock:^(NSString *substring, NSRange range, NSRange enclosingRange, BOOL *stop) {
            if (++line != c.line) return;
            self.scriptView.selectedRange = range;
            [self.scriptView scrollRangeToVisible:range];
            [self scrollScriptToLeft];
            *stop = YES;
        }];
    if (c.pause) {
        [self appendOutput:[NSString stringWithFormat:@"Pause - line %lu, %.15g seconds", (unsigned long)c.line, c.seconds] mark:DFCommandMark];
        __weak ViewController *weakSelf = self;
        self.scriptPauseTimer = [NSTimer scheduledTimerWithTimeInterval:c.seconds repeats:NO block:^(NSTimer *timer) {
            ViewController *controller = weakSelf;
            controller.scriptPauseTimer = nil;
            [controller endCommand];
            controller.scriptIndex++;
            [controller runNextScriptCommand];
        }];
        return;
    }

    NSString *message = [self confirmationForOperation:c.operation request:c.request];
    if (!message && [@[@(DFCreateFile), @(DFCreateApplication), @(DFWriteFile), @(DFUnlockReaderKeys), @(DFRandomUID)] containsObject:@(c.operation)])
        message = @"Execute this script command? It changes the card or reader.";
    if (c.ask && message) {
        [self confirmMessage:message completion:^(BOOL confirmed) {
            if (!confirmed || self.scriptStopRequested) [self finishScript:@"Script stopped before command execution"];
            else [self executeScriptCommand:c];
        }];
    } else [self executeScriptCommand:c];
}

- (void)executeScriptCommand:(DFScriptCommand *)c {
    [self appendOutput:[NSString stringWithFormat:@"%@ - line %lu",
        [ViewController commandTitleForOperation:c.operation request:c.request dump:c.dump], (unsigned long)c.line] mark:DFCommandMark];
    [self appendOutput:[c.request keyDescriptionForOperation:c.operation showKeys:YES] mark:DFInputMark];
    if (c.operation == DFWriteFile) [self appendOutput:[ViewController hexASCIIDump:c.request.data] mark:DFInputMark];
    dispatch_async(self.readerQueue, ^{
        BOOL fileRead = c.operation == DFReadFile;
        DFResult *result;
        NSString *saveError = nil;
        if (fileRead && !c.dump && !c.overwrite && [NSFileManager.defaultManager fileExistsAtPath:c.output]) {
            result = [DFResult new];
            result.status = 1;
            result.message = [DFWarningMark stringByAppendingString:@"Output file exists, overwrite=no"];
        } else {
            result = fileRead || c.operation == DFWriteFile ?
                [self.reader transferFile:c.request writing:c.operation == DFWriteFile] :
                [self.reader execute:c.operation request:c.request];
            if (result.success && fileRead && !c.dump) {
                NSError *error = nil;
                NSDataWritingOptions options = c.overwrite ? NSDataWritingAtomic : NSDataWritingWithoutOverwriting;
                if (![result.data writeToURL:[NSURL fileURLWithPath:c.output] options:options error:&error])
                    saveError = [@"Cannot save output file, " stringByAppendingString:error.localizedDescription];
            }
        }
        BOOL connected = self.reader.connected;
        dispatch_async(dispatch_get_main_queue(), ^{
            self.connected = connected;
            [self appendOutput:result.message mark:DFOutputMark];
            if (saveError) [self appendWarning:saveError];
            if (result.success && !saveError) {
                uint32_t currentAID = 0;
                BOOL settingsMatch = c.operation == DFGetKeySettings ?
                    [self parseAid:self.applicationAid value:&currentAID] && currentAID == c.request.aid :
                    c.operation == DFGetFileSettings ?
                    [self parseAid:self.filesAid value:&currentAID] && currentAID == c.request.aid &&
                        self.filesID.indexOfSelectedItem == c.request.fileID : YES;
                if (settingsMatch) [self applyResult:result operation:c.operation];
                if (fileRead && c.dump) [self appendOutput:[ViewController hexASCIIDump:result.data] mark:DFOutputMark];
                if (fileRead && !c.dump) [self appendOutput:[@"Saved output file " stringByAppendingString:c.output]];
                [self endCommand];
                self.scriptIndex++;
                [self runNextScriptCommand];
            } else [self finishScript:[NSString stringWithFormat:@"Script failed at line %lu - earlier changes were not rolled back", (unsigned long)c.line]];
        });
    });
}

- (void)applicationWillTerminate:(NSNotification *)notification {
    dispatch_sync(self.readerQueue, ^{
        if (!self.reader.connected) return;
        DFResult *result = [self.reader execute:DFCloseReader request:[DFRequest new]];
        if (!result.success) NSLog(@"ReaderClose: %@", result.message);
    });
}

@end
