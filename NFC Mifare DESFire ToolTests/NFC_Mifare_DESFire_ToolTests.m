//
//  NFC_Mifare_DESFire_ToolTests.m
//  NFC Mifare DESFire ToolTests
//
//  Created by Jan Wachsmuth on 04.07.16.
//  Copyright © 2016 desfire. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "../NFC Mifare DESFire Tool/DESFireReader.h"
#import "../NFC Mifare DESFire Tool/ViewController.h"
#import "../NFC Mifare DESFire Tool/DFScript.h"

@interface ViewController (Testing)
- (void)selectionChanged:(NSButton *)sender;
- (void)communicationChanged:(NSPopUpButton *)sender;
- (void)updateInterface;
- (void)controlTextDidChange:(NSNotification *)notification;
- (void)controlTextDidEndEditing:(NSNotification *)notification;
- (void)optionChanged:(id)sender;
- (void)scrollScriptToLeft;
- (void)fillKey:(NSButton *)sender;
- (NSArray<NSView *> *)allFormViews;
- (DFRequest *)fileRequest;
- (DFRequest *)requestForOperation:(DFOperation)operation;
- (NSString *)confirmationForOperation:(DFOperation)operation request:(DFRequest *)request;
- (void)applyResult:(DFResult *)result operation:(DFOperation)operation;
- (void)performOperation:(NSButton *)sender;
- (void)dumpFile:(id)sender;
- (void)performFileRequest:(DFRequest *)request writing:(BOOL)writing saveURL:(NSURL *)saveURL;
- (void)executeFileRequest:(DFRequest *)request writing:(BOOL)writing saveURL:(NSURL *)saveURL;
- (void)playScript:(id)sender;
- (void)stopScript:(id)sender;
- (void)selectAID:(NSButton *)sender;
+ (NSString *)hexASCIIDump:(NSData *)data;
+ (NSString *)commandNameForOperation:(DFOperation)operation;
+ (NSString *)commandTitleForOperation:(DFOperation)operation request:(DFRequest *)request dump:(BOOL)dump;
@end

@interface ScriptTestReader : DESFireReader
@property BOOL testConnected;
@property NSMutableArray<NSNumber *> *operations;
@property DFOperation failOperation;
@property BOOL shouldFail;
@property DFRequest *lastRequest;
@end
@implementation ScriptTestReader
- (BOOL)connected { return self.testConnected; }
- (DFResult *)execute:(DFOperation)operation request:(DFRequest *)request {
    if (!self.operations) self.operations = [NSMutableArray array];
    [self.operations addObject:@(operation)];
    self.lastRequest = request;
    DFResult *result = [DFResult new];
    result.message = @"Simulated script command";
    if (self.shouldFail && self.failOperation == operation) { result.status = 1; return result; }
    if (operation == DFOpenReader) self.testConnected = YES;
    if (operation == DFCloseReader) self.testConnected = NO;
    if (operation == DFGetFileSize) result.fileSize = 16;
    if (operation == DFReadFile) result.data = [NSMutableData dataWithLength:request.length];
    return result;
}
@end

@interface DESFireReader (ConversionTesting)
- (uint32_t)factoryConversionStatus;
- (DFResult *)convertFactoryCard;
- (DFResult *)verifyFactoryAESKey;
@end

@interface ConversionTestReader : DESFireReader
@property NSUInteger attempts;
@property NSUInteger successOnAttempt;
@property BOOL verificationFails;
@property NSUInteger verifications;
@end
@implementation ConversionTestReader
- (uint32_t)factoryConversionStatus {
    self.attempts++;
    return self.attempts == self.successOnAttempt ? 0 : 0x0E;
}
- (DFResult *)verifyFactoryAESKey {
    self.verifications++;
    DFResult *result = [DFResult new];
    result.hasCardStatus = YES;
    result.cardStatus = self.verificationFails ? 3002 : 3001;
    result.message = @"AES-Lesepruefung";
    return result;
}
@end

@interface ConnectionTestReader : DESFireReader
@property BOOL testConnected;
@property BOOL failOpening;
@property NSMutableArray<NSNumber *> *operations;
@property DFRequest *lastRequest;
@property DFResult *response;
@end
@implementation ConnectionTestReader
- (BOOL)connected { return self.testConnected; }
- (DFResult *)execute:(DFOperation)operation request:(DFRequest *)request {
    if (!self.operations) self.operations = [NSMutableArray array];
    [self.operations addObject:@(operation)];
    self.lastRequest = request;
    if (self.response) return self.response;
    DFResult *result = [DFResult new];
    result.message = @"Connection test";
    if (operation == DFOpenReader && self.failOpening) result.status = 0x54;
    else self.testConnected = operation == DFOpenReader;
    return result;
}
@end

@interface FileTransferTestReader : DESFireReader
@property uint32_t capacity;
@property BOOL sizeFails;
@property BOOL transferFails;
@property BOOL shortRead;
@property NSMutableArray<NSNumber *> *operations;
@property NSData *writtenData;
@property NSData *readData;
@end
@implementation FileTransferTestReader
- (DFResult *)execute:(DFOperation)operation request:(DFRequest *)request {
    if (!self.operations) self.operations = [NSMutableArray array];
    [self.operations addObject:@(operation)];
    DFResult *result = [DFResult new];
    result.message = @"Simulated file operation";
    if (operation == DFGetFileSize) {
        result.status = self.sizeFails ? 1 : 0;
        result.fileSize = self.capacity;
    } else {
        result.status = self.transferFails ? 1 : 0;
        if (operation == DFWriteFile) self.writtenData = request.data;
        else result.data = self.readData ?: [NSMutableData dataWithLength:self.shortRead ? request.length - 1 : request.length];
    }
    return result;
}
@end

@interface NFC_Mifare_DESFire_ToolTests : XCTestCase

@end

@implementation NFC_Mifare_DESFire_ToolTests

- (void)testContextTitlesAndInputDoNotDuplicateAIDOrFile {
    DFRequest *p = [self validRequest];
    p.fileID = 3;
    XCTAssertEqualObjects([ViewController commandTitleForOperation:DFReadFile request:p dump:YES],
        @"Dump File 3 for AID F00010");
    XCTAssertEqualObjects([ViewController commandTitleForOperation:DFCreateApplication request:p dump:NO],
        @"Create Application with ID F00010");
    XCTAssertEqualObjects([ViewController commandTitleForOperation:DFGetKeySettings request:p dump:NO],
        @"Get Application settings for AID F00010");
    for (NSNumber *op in @[@(DFCreateApplication), @(DFDeleteApplication), @(DFCreateFile), @(DFDeleteFile),
        @(DFReadFile), @(DFWriteFile), @(DFGetKeySettings), @(DFChangeKeySettings), @(DFChangeKey), @(DFGetFileSettings)]) {
        NSString *input = [p keyDescriptionForOperation:op.integerValue showKeys:YES];
        XCTAssertTrue([input hasPrefix:@"Authenticate with"], @"%@", input);
        XCTAssertFalse([input containsString:@"AID"], @"%@", input);
        XCTAssertFalse([input containsString:@"file 3"], @"%@", input);
    }
    p.aid = 0;
    XCTAssertEqualObjects([ViewController commandTitleForOperation:DFChangeKeySettings request:p dump:NO],
        @"Set Application settings for PICC / master application (AID 000000)");
}

- (void)testCompactTabsKeepControlsInsideAndAutomationDoesNotWrap {
    NSWindowController *window = [self guiWindow];
    [window showWindow:nil];
    ViewController *controller = (ViewController *)window.contentViewController;
    NSTabView *tabs = [controller valueForKey:@"tabs"];
    ((NSTextField *)[controller valueForKey:@"applicationAid"]).stringValue = @"F00010";
    [controller updateInterface];
    XCTAssertTrue(((NSTextField *)[controller valueForKey:@"applicationAid"]).enabled);
    XCTAssertNil(((NSButton *)[controller valueForKey:@"applicationPICC"]).superview);
    XCTAssertNil(((NSButton *)[controller valueForKey:@"applicationCustomAid"]).superview);
    NSMutableSet<NSNumber *> *heights = [NSMutableSet set];
    NSMutableArray<NSString *> *outside = [NSMutableArray array];
    XCTAssertNotNil([controller valueForKey:@"tabHeight"]);
    [window.window setContentSize:NSMakeSize(1000, 740)];
    for (NSTabViewItem *tab in tabs.tabViewItems) {
        [tabs selectTabViewItem:tab];
        [controller.view layoutSubtreeIfNeeded];
        [heights addObject:@(tabs.frame.size.height)];
        for (NSView *view in tab.view.subviews) {
            if (view.hidden || [view isKindOfClass:NSScrollView.class]) continue;
            if (NSMinY(view.frame) < 0 || NSMaxY(view.frame) > tab.view.bounds.size.height)
                [outside addObject:[NSString stringWithFormat:@"%@ %@ %@ content %@ form %@", tab.label, view.identifier,
                    NSStringFromRect(view.frame), NSStringFromRect(tab.view.bounds),
                    [controller valueForKey:@"formHeights"]]];
        }
    }
    XCTAssertGreaterThan(heights.count, 1u, @"Forms %@ height %@ delegate %@", [controller valueForKey:@"formHeights"], heights, tabs.delegate);
    XCTAssertEqual(outside.count, 0u, @"%@", outside);
    NSTextView *editor = [controller valueForKey:@"scriptView"];
    XCTAssertTrue(editor.enclosingScrollView.hasHorizontalScroller);
    XCTAssertTrue(editor.horizontallyResizable);
    XCTAssertFalse(editor.textContainer.widthTracksTextView);
    XCTAssertEqual(editor.textContainer.containerSize.width, CGFLOAT_MAX);
    editor.string = [@"" stringByPaddingToLength:1000 withString:@"A" startingAtIndex:0];
    [editor.layoutManager ensureLayoutForTextContainer:editor.textContainer];
    NSRect line = [editor.layoutManager lineFragmentRectForGlyphAtIndex:0 effectiveRange:NULL];
    NSRect used = [editor.layoutManager usedRectForTextContainer:editor.textContainer];
    XCTAssertGreaterThan(used.size.width, editor.enclosingScrollView.contentSize.width);
    XCTAssertLessThanOrEqual(used.size.height, line.size.height + 1);
    NSTextField *aid = [controller valueForKey:@"cardAid"];
    NSView *uidContent = aid.superview;
    NSPopUpButton *keyNumber = [controller valueForKey:@"cardKeyNumber"];
    XCTAssertGreaterThanOrEqual(NSMinY(keyNumber.frame), 0);
    XCTAssertLessThan(NSMidY(keyNumber.frame), NSMidY(aid.frame));
    XCTAssertLessThanOrEqual(NSMaxY(keyNumber.frame), uidContent.bounds.size.height);
    [window close];
}

- (void)testAllSecuritySettingsRoundTripThroughGUIAndScript {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    [controller selectionChanged:[controller valueForKey:@"applicationAES"]];
    NSButton *listing = [controller valueForKey:@"applicationListingRequirement"];
    NSBox *box = [controller valueForKey:@"keyChangeSettingsBox"];
    NSPopUpButton *policy = [controller valueForKey:@"keyChangeAuthentication"];
    XCTAssertEqual(policy.numberOfItems, 16);
    XCTAssertTrue(box.hidden);
    XCTAssertEqualObjects(((NSButton *)[controller valueForKey:@"applicationFrozenMaster"]).title,
        @"PICC master key is not changeable anymore");
    XCTAssertEqualObjects(listing.title, @"Getting AIDs and key settings requires authentication with the PICC master key");
    for (NSUInteger settings = 0; settings < 16; settings++) {
        DFResult *result = [DFResult new];
        result.keySettings = settings;
        result.maximumKeys = 1;
        [controller applyResult:result operation:DFGetKeySettings];
        DFRequest *request = [controller requestForOperation:DFChangeKeySettings];
        XCTAssertNotNil(request);
        XCTAssertEqual(request.keySettings, settings);
        XCTAssertEqual(listing.state == NSControlStateValueOn, !(settings & 2));
    }
    ((NSTextField *)[controller valueForKey:@"applicationAid"]).stringValue = @"F00010";
    [controller selectionChanged:[controller valueForKey:@"applicationCustomAid"]];
    XCTAssertFalse(box.hidden);
    XCTAssertEqualObjects(listing.title, @"Getting file IDs and settings requires authentication with the application master key");
    for (NSUInteger settings = 0; settings < 256; settings++) {
        DFResult *result = [DFResult new];
        result.keySettings = settings;
        result.maximumKeys = 14;
        [controller applyResult:result operation:DFGetKeySettings];
        DFRequest *request = [controller requestForOperation:DFChangeKeySettings];
        XCTAssertNotNil(request);
        XCTAssertEqual(request.keySettings, settings);
        NSString *error = nil;
        NSString *script = [DFScript recordOperation:DFChangeKeySettings request:request dump:NO output:nil];
        NSArray<DFScriptCommand *> *commands = [DFScript parse:script error:&error];
        XCTAssertNotNil(commands, @"%@", error);
        XCTAssertEqual(commands.firstObject.request.keySettings, settings);
        DFRequest *create = [controller requestForOperation:DFCreateApplication];
        XCTAssertNotNil(create);
        XCTAssertEqual(create.keySettings, settings);
    }
    ((NSTextField *)[controller valueForKey:@"applicationAid"]).stringValue = @"000000";
    [controller updateInterface];
    XCTAssertTrue(box.hidden);
    XCTAssertEqual([controller requestForOperation:DFChangeKeySettings].keySettings & 0xF0, 0);
}

- (void)testSecuritySettingsValidatePICCReservedBitsAndCreateKeyExistence {
    DFRequest *request = [self validRequest];
    request.keySettings = 0xEF;
    XCTAssertNil([request validationErrorForOperation:DFChangeKeySettings]);
    request.aid = 0;
    XCTAssertNotNil([request validationErrorForOperation:DFChangeKeySettings]);
    request.aid = 0xF00010;
    request.maximumKeys = 3;
    request.keySettings = 0x2F;
    XCTAssertNil([request validationErrorForOperation:DFCreateApplication]);
    request.keySettings = 0x3F;
    XCTAssertNotNil([request validationErrorForOperation:DFCreateApplication]);
    request.keySettings = 0xEF;
    XCTAssertNil([request validationErrorForOperation:DFCreateApplication]);
    request.keySettings = 0xFF;
    XCTAssertNil([request validationErrorForOperation:DFCreateApplication]);
}

- (void)testSecuritySettingsStartUnknownAndInvalidateOnEverySharedAIDChange {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    NSArray<NSButton *> *checkboxes = @[[controller valueForKey:@"applicationRequirement"],
        [controller valueForKey:@"applicationFrozenSettings"], [controller valueForKey:@"applicationFrozenMaster"],
        [controller valueForKey:@"applicationListingRequirement"]];
    for (NSButton *checkbox in checkboxes) {
        XCTAssertTrue(checkbox.allowsMixedState);
        XCTAssertEqual(checkbox.state, NSControlStateValueMixed);
    }
    [controller selectionChanged:[controller valueForKey:@"applicationAES"]];
    XCTAssertNil([controller requestForOperation:DFChangeKeySettings]);
    DFResult *known = [DFResult new];
    known.keySettings = 0xAF;
    known.maximumKeys = 14;
    NSUInteger aid = 1;
    for (NSString *name in @[@"cardAid", @"keysAid", @"filesAid", @"applicationAid"]) {
        NSTextField *field = [controller valueForKey:name];
        field.stringValue = [NSString stringWithFormat:@"%06lX", (unsigned long)aid++];
        [controller controlTextDidChange:[NSNotification notificationWithName:NSControlTextDidChangeNotification object:field]];
        for (NSButton *checkbox in checkboxes) XCTAssertEqual(checkbox.state, NSControlStateValueMixed);
        XCTAssertEqual(((NSPopUpButton *)[controller valueForKey:@"keyChangeAuthentication"]).indexOfSelectedItem, -1);
        [controller applyResult:known operation:DFGetKeySettings];
        NSArray *states = [checkboxes valueForKey:@"state"];
        DFResult *failure = [DFResult new];
        failure.status = 1;
        failure.keySettings = 0;
        [controller applyResult:failure operation:DFGetKeySettings];
        [controller updateInterface];
        XCTAssertEqualObjects([checkboxes valueForKey:@"state"], states);
        XCTAssertEqual([controller requestForOperation:DFChangeKeySettings].keySettings, 0xAF);
    }
    NSTextField *field = [controller valueForKey:@"applicationAid"];
    field.stringValue = @"000000";
    [controller controlTextDidChange:[NSNotification notificationWithName:NSControlTextDidChangeNotification object:field]];
    NSPopUpButton *count = [controller valueForKey:@"applicationKeyCount"];
    XCTAssertEqual(count.indexOfSelectedItem, 0);
    XCTAssertFalse(count.enabled);
    for (NSButton *checkbox in checkboxes) {
        checkbox.state = NSControlStateValueMixed;
        [controller optionChanged:checkbox];
        XCTAssertEqual(checkbox.state, NSControlStateValueOff);
    }
    XCTAssertEqual([controller requestForOperation:DFChangeKeySettings].keySettings, 0x0F);
    XCTAssertEqual([controller requestForOperation:DFChangeKeySettings].maximumKeys, 1);
}

- (void)testFileSettingsFirmwareThresholdsAndDisconnect {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    ((NSTextField *)[controller valueForKey:@"filesAid"]).stringValue = @"123456";
    [controller setValue:@YES forKey:@"connected"];
    [controller selectionChanged:[controller valueForKey:@"filesAES"]];
    NSButton *get = [controller valueForKey:@"getFileSettingsButton"];
    NSButton *change = [controller valueForKey:@"changeAccessButton"];
    for (NSNumber *version in @[@0, @0x030937, @0x05004B, @0x05004C, @0x050050, @0x050051, @0x050100, @0x060000]) {
        DFResult *open = [DFResult new];
        open.firmwareVersion = version.unsignedIntValue;
        [controller applyResult:open operation:DFOpenReader];
        [controller updateInterface];
        XCTAssertEqual(get.hidden, version.unsignedIntValue < 0x05004C);
        XCTAssertEqual(change.hidden, version.unsignedIntValue < 0x050051);
        XCTAssertEqual(get.enabled, !get.hidden);
        XCTAssertEqual(change.enabled, !change.hidden);
    }
    DFResult *failedOpen = [DFResult new];
    failedOpen.status = 1;
    [controller applyResult:failedOpen operation:DFOpenReader];
    [controller updateInterface];
    XCTAssertFalse(change.hidden);
    [controller setValue:@NO forKey:@"connected"];
    [controller applyResult:[DFResult new] operation:DFCloseReader];
    [controller updateInterface];
    XCTAssertTrue(get.hidden);
    XCTAssertTrue(change.hidden);
}

- (void)testBackendRejectsUnsupportedFirmwareWithoutCallingTheCard {
    DESFireReader *reader = [DESFireReader new];
    [reader setValue:@YES forKey:@"connected"];
    DFRequest *request = [self validRequest];
    for (NSNumber *operation in @[@(DFGetFileSettings), @(DFChangeFileSettings)]) {
        for (NSNumber *firmware in @[@0, @0x030937, @0x05004B]) {
            [reader setValue:firmware forKey:@"firmwareVersion"];
            DFResult *result = [reader execute:operation.integerValue request:request];
            XCTAssertFalse(result.success);
            XCTAssertEqual(result.status, 0x09u);
            XCTAssertTrue([result.message containsString:@"requires reader firmware"]);
        }
    }
    [reader setValue:@0x050051 forKey:@"firmwareVersion"];
    DFResult *open = [reader execute:DFOpenReader request:[DFRequest new]];
    XCTAssertTrue(open.success);
    XCTAssertEqual(open.firmwareVersion, 0x050051u);
}

- (void)testCardUIDUsesOnlyAIDFieldAndPICCKeyZero {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    NSTextField *aid = [controller valueForKey:@"cardAid"];
    NSPopUpButton *key = [controller valueForKey:@"cardKeyNumber"];
    aid.stringValue = @"123456";
    [key selectItemAtIndex:3];
    DFRequest *request = [controller requestForOperation:DFGetUID];
    XCTAssertEqual(request.aid, 0x123456u);
    XCTAssertEqual(request.authenticationKeyNumber, 3);
    aid.stringValue = @"000000";
    request = [controller requestForOperation:DFGetUID];
    XCTAssertEqual(request.authenticationKeyNumber, 0);
    aid.stringValue = @"invalid";
    XCTAssertNil([controller requestForOperation:DFGetUID]);
}

- (void)testAutomationPlayKeepsColumnOneVisible {
    NSWindowController *window = [self guiWindow];
    [window showWindow:nil];
    ViewController *controller = (ViewController *)window.contentViewController;
    [(NSTabView *)[controller valueForKey:@"tabs"] selectTabViewItemAtIndex:5];
    NSTextView *script = [controller valueForKey:@"scriptView"];
    script.string = [@"Pause sec=0 # " stringByAppendingString:[@"" stringByPaddingToLength:3000 withString:@"x" startingAtIndex:0]];
    [script.layoutManager ensureLayoutForTextContainer:script.textContainer];
    [script scrollRangeToVisible:NSMakeRange(script.string.length, 0)];
    XCTAssertGreaterThan(script.enclosingScrollView.contentView.bounds.origin.x, 0);
    [controller playScript:nil];
    NSPredicate *idle = [NSPredicate predicateWithBlock:^BOOL(id object, NSDictionary *bindings) {
        return ![[object valueForKey:@"scriptRunning"] boolValue];
    }];
    [self waitForExpectations:@[[[XCTNSPredicateExpectation alloc] initWithPredicate:idle object:controller]] timeout:3];
    XCTAssertEqualWithAccuracy(script.enclosingScrollView.contentView.bounds.origin.x, 0, 0.1);
    [window close];
}

- (void)testSecuritySettingsLayoutAndOfflineEditing {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    ((NSTextField *)[controller valueForKey:@"applicationAid"]).stringValue = @"F00010";
    [controller selectionChanged:[controller valueForKey:@"applicationCustomAid"]];
    NSTabView *tabs = [controller valueForKey:@"tabs"];
    [tabs selectTabViewItemAtIndex:2];
    NSBox *box = [controller valueForKey:@"keyChangeSettingsBox"];
    NSPopUpButton *policy = [controller valueForKey:@"keyChangeAuthentication"];
    NSButton *listing = [controller valueForKey:@"applicationListingRequirement"];
    XCTAssertTrue(policy.enabled);
    XCTAssertTrue(listing.enabled);
    XCTAssertFalse(box.hidden);
    for (NSValue *size in @[[NSValue valueWithSize:NSMakeSize(1000, 740)], [NSValue valueWithSize:NSMakeSize(1200, 940)]]) {
        [window.window setContentSize:size.sizeValue];
        [controller.view layoutSubtreeIfNeeded];
        XCTAssertFalse(policy.hasAmbiguousLayout);
        XCTAssertFalse(listing.hasAmbiguousLayout);
        NSView *panel = box.superview;
        for (NSView *sibling in panel.subviews)
            if (sibling != box && !sibling.hidden)
                XCTAssertFalse(NSIntersectsRect(box.frame, sibling.frame), @"Key settings overlap %@", sibling.identifier);
        NSRect listingRect = [listing.superview convertRect:listing.bounds fromView:listing];
        XCTAssertLessThanOrEqual(NSMaxY(listingRect), listing.superview.bounds.size.height);
        XCTAssertGreaterThanOrEqual(NSMinY(listingRect), 0);
        CGFloat textWidth = [listing.title sizeWithAttributes:@{NSFontAttributeName: listing.font}].width;
        XCTAssertGreaterThanOrEqual(listing.frame.size.width, textWidth + 18);
    }
    [controller setValue:@YES forKey:@"busy"];
    [controller updateInterface];
    XCTAssertFalse(policy.enabled);
    XCTAssertFalse(listing.enabled);
}
- (void)testAIDShortcutsShareRecentEntriesAndSelectPICC {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    NSArray<NSTextField *> *fields = @[[controller valueForKey:@"keysAid"], [controller valueForKey:@"filesAid"],
        [controller valueForKey:@"applicationAid"], [controller valueForKey:@"cardAid"]];
    NSArray<NSArray<NSButton *> *> *groups = [controller valueForKey:@"aidShortcutButtons"];
    XCTAssertEqual(groups.count, 4u);
    for (NSArray<NSButton *> *group in groups) {
        XCTAssertEqualObjects(group.firstObject.title, @"PICC");
        XCTAssertTrue(group[1].hidden);
    }
    NSArray *values = @[@"F00010", @"abcdef", @"123456", @"654321"];
    for (NSUInteger i = 0; i < values.count; i++) {
        fields[i].stringValue = values[i];
        [controller controlTextDidChange:[NSNotification notificationWithName:NSControlTextDidChangeNotification object:fields[i]]];
        if (i == 0) XCTAssertTrue(groups[0][1].hidden);
        [controller controlTextDidEndEditing:[NSNotification notificationWithName:NSControlTextDidEndEditingNotification object:fields[i]]];
    }
    for (NSArray<NSButton *> *group in groups) {
        XCTAssertEqualObjects(([@[group[1], group[2], group[3]] valueForKey:@"title"]), (@[@"654321", @"123456", @"ABCDEF"]));
        for (NSButton *button in group) XCTAssertFalse(button.hidden);
    }
    fields[0].stringValue = @"invalid";
    [controller controlTextDidChange:[NSNotification notificationWithName:NSControlTextDidChangeNotification object:fields[0]]];
    XCTAssertEqualObjects(groups[0][1].title, @"654321");
    [controller selectAID:groups[0][2]];
    for (NSTextField *field in fields) XCTAssertEqualObjects(field.stringValue, @"123456");
    XCTAssertNil(((NSButton *)[controller valueForKey:@"cardCustomAid"]).superview);
    [controller selectAID:groups[1][0]];
    for (NSTextField *field in fields) XCTAssertEqualObjects(field.stringValue, @"000000");
    XCTAssertNil(((NSButton *)[controller valueForKey:@"cardPICC"]).superview);
    XCTAssertEqualObjects(groups[0][1].title, @"654321");
    fields[0].stringValue = @"abcdef";
    [controller controlTextDidChange:[NSNotification notificationWithName:NSControlTextDidChangeNotification object:fields[0]]];
    XCTAssertEqualObjects(groups[0][1].title, @"654321");
    [controller controlTextDidEndEditing:[NSNotification notificationWithName:NSControlTextDidEndEditingNotification object:fields[0]]];
    XCTAssertEqualObjects(([@[groups[0][1], groups[0][2], groups[0][3]] valueForKey:@"title"]), (@[@"ABCDEF", @"654321", @"123456"]));
    [controller setValue:@YES forKey:@"busy"];
    [controller updateInterface];
    for (NSArray<NSButton *> *group in groups)
        for (NSButton *button in group) XCTAssertFalse(button.enabled);
}

- (void)testOldAndNewKeyGeneratorsDoNotChangeAuthenticationOrEachOther {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    NSTextField *old = [controller valueForKey:@"oldKey"];
    NSTextField *replacement = [controller valueForKey:@"replacementKeyField"];
    NSTextField *auth = [controller valueForKey:@"keysKey"];
    old.stringValue = @"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    replacement.stringValue = @"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    NSString *authValue = auth.stringValue;
    NSMutableDictionary<NSString *, NSButton *> *buttons = [NSMutableDictionary dictionary];
    for (NSView *view in [controller allFormViews])
        if ([view isKindOfClass:NSButton.class] && view.identifier) buttons[view.identifier] = (NSButton *)view;
    XCTAssertNotNil(buttons[@"OldKeyZero"]);
    XCTAssertNotNil(buttons[@"NewKeyZero"]);
    XCTAssertNotNil(buttons[@"NewKeyRandom"]);
    [buttons[@"OldKeyZero"] performClick:nil];
    XCTAssertEqualObjects(old.stringValue, @"00000000000000000000000000000000");
    XCTAssertEqualObjects(replacement.stringValue, @"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    [buttons[@"NewKeyZero"] performClick:nil];
    XCTAssertEqualObjects(replacement.stringValue, @"00000000000000000000000000000000");
    [buttons[@"NewKeyRandom"] performClick:nil];
    XCTAssertEqual([DESFireReader hexData:replacement.stringValue].length, 16u);
    XCTAssertNotEqualObjects(replacement.stringValue, @"00000000000000000000000000000000");
    XCTAssertEqualObjects(old.stringValue, @"00000000000000000000000000000000");
    XCTAssertEqualObjects(auth.stringValue, authValue);
}

- (void)testAIDShortcutsFitBesideFieldsWithoutOverlappingExistingControls {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    NSTextField *keys = [controller valueForKey:@"keysAid"];
    for (NSString *value in @[@"F00010", @"123456", @"654321"]) {
        keys.stringValue = value;
        [controller controlTextDidChange:[NSNotification notificationWithName:NSControlTextDidChangeNotification object:keys]];
        [controller controlTextDidEndEditing:[NSNotification notificationWithName:NSControlTextDidEndEditingNotification object:keys]];
    }
    NSArray<NSTextField *> *fields = @[[controller valueForKey:@"cardAid"], [controller valueForKey:@"applicationAid"],
        keys, [controller valueForKey:@"filesAid"]];
    NSArray<NSArray<NSButton *> *> *groups = [controller valueForKey:@"aidShortcutButtons"];
    NSTabView *tabs = [controller valueForKey:@"tabs"];
    for (NSValue *size in @[[NSValue valueWithSize:NSMakeSize(1000, 740)], [NSValue valueWithSize:NSMakeSize(1200, 940)]]) {
        [window.window setContentSize:size.sizeValue];
        for (NSUInteger i = 0; i < groups.count; i++) {
            [tabs selectTabViewItemAtIndex:i + 1];
            [controller.view layoutSubtreeIfNeeded];
            NSView *container = fields[i].superview;
            for (NSButton *button in groups[i]) {
                NSRect rect = [container convertRect:button.bounds fromView:button];
                XCTAssertGreaterThanOrEqual(NSMinX(rect), NSMaxX(fields[i].frame));
                XCTAssertLessThanOrEqual(NSMaxX(rect), container.bounds.size.width);
                XCTAssertFalse(button.hasAmbiguousLayout);
                for (NSView *sibling in container.subviews) {
                    if (![sibling isKindOfClass:NSControl.class] || sibling.hidden) continue;
                    XCTAssertFalse(NSIntersectsRect(rect, sibling.frame), @"%@ overlaps %@", button.identifier, sibling.identifier);
                }
            }
        }
    }
}

- (void)testPauseParsesDefaultAndFractionalSecondsAndRejectsInvalidSyntax {
    NSString *error = nil;
    NSArray<DFScriptCommand *> *commands = [DFScript parse:@"Pause\nPause sec=0.25\nPause sec=0" error:&error];
    XCTAssertNotNil(commands, @"%@", error);
    XCTAssertTrue(commands.firstObject.pause);
    XCTAssertEqual(commands.firstObject.seconds, 1);
    XCTAssertEqual(commands[1].seconds, 0.25);
    XCTAssertEqual(commands[2].seconds, 0);
    for (NSString *invalid in @[@"Pause sec=-1", @"Pause sec=nan", @"Pause sec=inf", @"Pause sec=1x",
        @"Pause sec=1.2.3", @"Pause sec=", @"Pause sec=1 sec=2", @"Pause typo=1", @"Pause sec=1 ask=no"]) {
        XCTAssertNil([DFScript parse:invalid error:&error], @"%@", invalid);
    }
}

- (void)testPauseRunsOfflineWithoutReaderCallsAndStopsImmediately {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    ScriptTestReader *reader = [ScriptTestReader new];
    [controller setValue:reader forKey:@"reader"];
    NSTextView *editor = [controller valueForKey:@"scriptView"];
    editor.string = @"Pause sec=0.1\nPause sec=0";
    NSTimeInterval start = NSProcessInfo.processInfo.systemUptime;
    [controller playScript:nil];
    XCTAssertTrue([[controller valueForKey:@"busy"] boolValue]);
    XCTAssertNotNil([controller valueForKey:@"scriptPauseTimer"]);
    [self waitForScript:controller];
    XCTAssertGreaterThanOrEqual(NSProcessInfo.processInfo.systemUptime - start, 0.1);
    XCTAssertEqual(reader.operations.count, 0u);
    XCTAssertEqualObjects(editor.string, @"Pause sec=0.1\nPause sec=0");
    editor.string = @"Pause sec=60\nConnectReader";
    [controller playScript:nil];
    [controller stopScript:nil];
    XCTAssertFalse([[controller valueForKey:@"busy"] boolValue]);
    XCTAssertNil([controller valueForKey:@"scriptPauseTimer"]);
    editor.string = @"Pause sec=0\nConnectReader\nPause sec=0.05\nDisconnectReader";
    [controller playScript:nil];
    [self waitForScript:controller];
    XCTAssertEqualObjects(reader.operations, (@[@(DFOpenReader), @(DFCloseReader)]));
}

- (void)testChangeKeyResultDoesNotPrintRemovedReminder {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    NSTextView *output = [controller valueForKey:@"outputView"];
    NSString *before = output.string;
    DFResult *result = [DFResult new];
    [controller applyResult:result operation:DFChangeKey];
    XCTAssertEqualObjects(output.string, before);
}

- (void)testScriptMixedWriteSegmentsPaddingAndEscapes {
    NSString *error = nil;
    NSArray<DFScriptCommand *> *commands = [DFScript parse:
        @"# DESFire Script 1\nWriteFile aid=F00010 file=0 comm=plain authKey=2 auth=reader slot=7 text=\"AB\\\"\\\\\" data=0D0A text=\"CD\" data=00 size=12 offset=0 ask=no"
        error:&error];
    XCTAssertNotNil(commands, @"%@", error);
    DFScriptCommand *c = commands.firstObject;
    const uint8_t expected[] = {'A', 'B', '"', '\\', 13, 10, 'C', 'D', 0, 0, 0, 0};
    XCTAssertEqualObjects(c.request.data, [NSData dataWithBytes:expected length:sizeof expected]);
    XCTAssertEqual(c.request.length, 12);
    XCTAssertFalse(c.ask);
    XCTAssertEqual(c.line, 2u);
    XCTAssertEqual(c.request.readerKeyNumber, 7);
    NSString *recorded = [DFScript recordOperation:DFWriteFile request:c.request dump:NO output:nil];
    XCTAssertTrue([recorded containsString:@"text=\"AB\\\"\\\\\" data=0D0A text=\"CD\" data=00000000"]);
    NSArray<DFScriptCommand *> *roundTrip = [DFScript parse:recorded error:&error];
    XCTAssertEqualObjects(roundTrip.firstObject.request.data, c.request.data);
    XCTAssertTrue(roundTrip.firstObject.ask);
}

- (void)testScriptValidationRejectsInvalidEntireScripts {
    NSArray *invalid = @[
        @"GetFreeMemory\nTypoCommand",
        @"CreateFile aid=F00010 file=256 size=32 comm=plain readKey=1 writeKey=2 readWriteKey=2 changeKey=0 auth=none",
        @"DeleteFile aid=F00010 file=1 auth=reader slot=16",
        @"DeleteFile aid=F00010 file=1 auth=aes key=00",
        @"DeleteFile aid=F00010 file=1 auth=reader slot=5 slot=6",
        @"DeleteFile aid=F00010 file=1 auth=reader slot=5 typo=yes",
        @"WriteFile aid=F00010 file=0 comm=plain authKey=0 auth=none text=\"ABC\" size=2",
        @"WriteFile aid=F00010 file=0 comm=plain authKey=0 auth=none data=0",
        @"WriteFile aid=F00010 file=0 comm=plain authKey=0 auth=none text=\"ä\"",
        @"WriteFile aid=F00010 file=0 comm=plain authKey=0 auth=none text=\"A\" offset=1",
        @"WriteFile aid=F00010 file=0 comm=plain authKey=0 auth=none text=\"unterminated",
        @"ReadFile aid=F00010 file=0 comm=plain authKey=0 auth=none output=\"relative.bin\"",
        @"ReadFile aid=F00010 file=0 comm=plain authKey=0 auth=none output=\"/tmp/test\" overwrite=maybe"
    ];
    for (NSString *script in invalid) {
        NSString *error = nil;
        XCTAssertNil([DFScript parse:script error:&error], @"%@", script);
        XCTAssertTrue([error hasPrefix:@"Line "], @"%@", error);
    }
}

- (void)testScriptLineNumbersAndSelectionUseLogicalLinesForCRLF {
    NSString *error = nil;
    NSString *script = @"# Windows line endings\r\n\r\nConnectReader\r\nGetFreeMemory\r\n";
    NSArray<DFScriptCommand *> *commands = [DFScript parse:script error:&error];
    XCTAssertNotNil(commands, @"%@", error);
    XCTAssertEqual(commands.firstObject.line, 3u);
    XCTAssertEqual(commands.lastObject.line, 4u);
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    [controller setValue:[ScriptTestReader new] forKey:@"reader"];
    NSTextView *editor = [controller valueForKey:@"scriptView"];
    editor.string = script;
    [controller playScript:nil];
    [self waitForScript:controller];
    XCTAssertEqualObjects([editor.string substringWithRange:editor.selectedRange], @"GetFreeMemory");
}

- (void)testScriptWriteDefaultsToConfirmationAndCanBeCancelled {
    NSWindowController *window = [self guiWindow];
    [window showWindow:nil];
    ViewController *controller = (ViewController *)window.contentViewController;
    ScriptTestReader *reader = [ScriptTestReader new];
    reader.testConnected = YES;
    [controller setValue:reader forKey:@"reader"];
    [controller setValue:@YES forKey:@"connected"];
    NSTextView *editor = [controller valueForKey:@"scriptView"];
    editor.string = @"WriteFile aid=F00010 file=0 auth=none authKey=0 comm=plain text=\"Hi\"";
    [controller playScript:nil];
    XCTAssertNotNil(window.window.attachedSheet);
    XCTAssertEqual(reader.operations.count, 0u);
    [NSApp endSheet:window.window.attachedSheet returnCode:NSAlertFirstButtonReturn];
    [self waitForScript:controller];
    XCTAssertEqual(reader.operations.count, 0u);
    [window close];
}

- (void)testEveryOperationRecordsAParseableSelfContainedCommand {
    for (DFOperation operation = DFOpenReader; operation <= DFGetFileSettings; operation++) {
        for (NSNumber *internal in @[@NO, @YES]) {
            DFRequest *p = [self validRequest];
            p.useInternalKey = internal.boolValue;
            p.readerKeyNumber = 5;
            NSString *line = [DFScript recordOperation:operation request:p dump:NO output:[NSURL fileURLWithPath:@"/tmp/output file.bin"]];
            NSString *error = nil;
            NSArray<DFScriptCommand *> *commands = [DFScript parse:line error:&error];
            XCTAssertNotNil(commands, @"%@ - %@", line, error);
            XCTAssertEqual(commands.firstObject.operation, operation);
        }
    }
}

- (void)testScriptRecorderPreservesAllBytesOldKeyAndNoAuthRead {
    DFRequest *p = [self validRequest];
    NSMutableData *data = [NSMutableData data];
    for (NSUInteger i = 0; i < 256; i++) {
        uint8_t byte = (uint8_t)i;
        [data appendBytes:&byte length:1];
    }
    p.data = data;
    p.length = 256;
    NSString *error = nil;
    NSString *line = [DFScript recordOperation:DFWriteFile request:p dump:NO output:nil];
    NSArray<DFScriptCommand *> *parsed = [DFScript parse:line error:&error];
    XCTAssertNotNil(parsed, @"%@", error);
    XCTAssertEqualObjects(parsed.firstObject.request.data, data);
    p.changedKeyNumber = 2;
    p.oldKey = [NSData dataWithBytes:"abcdefghijklmnop" length:16];
    line = [DFScript recordOperation:DFChangeKey request:p dump:NO output:nil];
    parsed = [DFScript parse:line error:&error];
    XCTAssertNotNil(parsed, @"%@", error);
    XCTAssertEqualObjects(parsed.firstObject.request.oldKey, p.oldKey);
    XCTAssertEqual(parsed.firstObject.request.changedKeyNumber, 2);
    p.authenticate = NO;
    line = [DFScript recordOperation:DFReadFile request:p dump:YES output:nil];
    parsed = [DFScript parse:line error:&error];
    XCTAssertNotNil(parsed, @"%@", error);
    XCTAssertTrue(parsed.firstObject.dump);
    XCTAssertFalse(parsed.firstObject.request.authenticate);
    line = [DFScript recordOperation:DFReadFile request:p dump:NO output:[NSURL fileURLWithPath:@"/tmp/recorded.bin"]];
    XCTAssertTrue([line containsString:@"overwrite=no"]);
    parsed = [DFScript parse:line error:&error];
    XCTAssertNotNil(parsed, @"%@", error);
    XCTAssertFalse(parsed.firstObject.overwrite);
}

- (void)waitForScript:(ViewController *)controller {
    NSPredicate *idle = [NSPredicate predicateWithBlock:^BOOL(id object, NSDictionary *bindings) {
        return ![[object valueForKey:@"busy"] boolValue];
    }];
    [self waitForExpectations:@[[[XCTNSPredicateExpectation alloc] initWithPredicate:idle object:controller]] timeout:5];
}

- (void)testScriptPlayRepeatsOnceWithoutRecordingItselfAndRejectsLateSyntaxErrors {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    ScriptTestReader *reader = [ScriptTestReader new];
    [controller setValue:reader forKey:@"reader"];
    NSTextView *editor = [controller valueForKey:@"scriptView"];
    NSString *script = @"ConnectReader\nGetFreeMemory\nDisconnectReader";
    editor.string = script;
    [controller playScript:nil];
    [self waitForScript:controller];
    XCTAssertEqualObjects(reader.operations, (@[@(DFOpenReader), @(DFFreeMemory), @(DFCloseReader)]));
    XCTAssertEqualObjects(editor.string, script);
    [controller playScript:nil];
    [self waitForScript:controller];
    XCTAssertEqual(reader.operations.count, 6u);
    editor.string = @"ConnectReader\nInvalidCommand";
    [controller playScript:nil];
    XCTAssertEqual(reader.operations.count, 6u);
}

- (void)testScriptStopsOnFailureAndManualStop {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    ScriptTestReader *reader = [ScriptTestReader new];
    reader.shouldFail = YES;
    reader.failOperation = DFFreeMemory;
    [controller setValue:reader forKey:@"reader"];
    NSTextView *editor = [controller valueForKey:@"scriptView"];
    editor.string = @"ConnectReader\nGetFreeMemory\nDisconnectReader";
    [controller playScript:nil];
    [self waitForScript:controller];
    XCTAssertEqualObjects(reader.operations, (@[@(DFOpenReader), @(DFFreeMemory)]));
    reader.operations = [NSMutableArray array];
    [controller setValue:@NO forKey:@"connected"];
    [controller playScript:nil];
    XCTAssertTrue(((NSButton *)[controller valueForKey:@"scriptStopButton"]).enabled);
    [controller stopScript:nil];
    [self waitForScript:controller];
    XCTAssertEqualObjects(reader.operations, (@[@(DFOpenReader)]));
}

- (void)testScriptWriteAskNoAndReadOverwriteProtection {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    ScriptTestReader *reader = [ScriptTestReader new];
    reader.testConnected = YES;
    [controller setValue:reader forKey:@"reader"];
    [controller setValue:@YES forKey:@"connected"];
    NSTextView *editor = [controller valueForKey:@"scriptView"];
    editor.string = @"WriteFile aid=F00010 file=0 auth=none authKey=0 comm=plain text=\"Hi\" data=00 size=16 ask=no";
    [controller playScript:nil];
    [self waitForScript:controller];
    XCTAssertEqualObjects(reader.operations, (@[@(DFGetFileSize), @(DFWriteFile)]));
    XCTAssertEqual(reader.lastRequest.data.length, 16u);
    NSURL *url = [[NSURL fileURLWithPath:NSTemporaryDirectory()] URLByAppendingPathComponent:NSUUID.UUID.UUIDString];
    NSError *error = nil;
    NSData *original = [@"keep" dataUsingEncoding:NSASCIIStringEncoding];
    XCTAssertTrue([original writeToURL:url options:0 error:&error]);
    NSString *line = [NSString stringWithFormat:@"ReadFile aid=F00010 file=0 auth=none authKey=0 comm=plain output=\"%@\" overwrite=no", url.path];
    reader.operations = [NSMutableArray array];
    editor.string = line;
    [controller playScript:nil];
    [self waitForScript:controller];
    XCTAssertEqual(reader.operations.count, 0u);
    XCTAssertEqualObjects([NSData dataWithContentsOfURL:url], original);
    editor.string = [line stringByReplacingOccurrencesOfString:@"overwrite=no" withString:@"overwrite=yes"];
    [controller playScript:nil];
    [self waitForScript:controller];
    XCTAssertEqual([NSData dataWithContentsOfURL:url].length, 16u);
    XCTAssertTrue([NSFileManager.defaultManager removeItemAtURL:url error:&error]);
    reader.operations = [NSMutableArray array];
    editor.string = line;
    [controller playScript:nil];
    [self waitForScript:controller];
    XCTAssertEqual([NSData dataWithContentsOfURL:url].length, 16u);
    XCTAssertTrue([NSFileManager.defaultManager removeItemAtURL:url error:&error]);
}

- (DFRequest *)validRequest {
    DFRequest *p = [DFRequest new];
    p.aid = 0xF00010;
    p.key = [NSMutableData dataWithLength:16];
    p.replacementKey = p.key;
    p.oldKey = p.key;
    p.fileSize = 128;
    p.length = 128;
    p.data = [NSMutableData dataWithLength:128];
    p.password = [@"12345678" dataUsingEncoding:NSASCIIStringEncoding];
    p.randomUID = YES;
    return p;
}

- (void)testHexParsingPreservesByteOrderAndWhitespace {
    NSData *data = [DESFireReader hexData:@"00 01 7f\n80 FF"];
    const uint8_t expected[] = {0, 1, 0x7F, 0x80, 0xFF};
    XCTAssertEqualObjects(data, [NSData dataWithBytes:expected length:sizeof(expected)]);
    XCTAssertEqual([DESFireReader hexData:@"00000000000000000000000000000000"].length, 16u);
    for (NSString *invalid in @[@"0", @"GG", @"0X01", @"-1", @"01:02", @"1z", @"\uFF10\uFF10"]) {
        XCTAssertNil([DESFireReader hexData:invalid], @"%@", invalid);
    }
}

- (void)testUnsignedParsingRejectsPartialInputsAndOverflow {
    uint32_t value = 0;
    XCTAssertTrue([DESFireReader parseUnsigned:@"f00010" base:16 maximum:0xFFFFFF value:&value]);
    XCTAssertEqual(value, 0xF00010u);
    XCTAssertTrue([DESFireReader parseUnsigned:@"FFFFFF" base:16 maximum:0xFFFFFF value:&value]);
    XCTAssertEqual(value, 0xFFFFFFu);
    XCTAssertTrue([DESFireReader parseUnsigned:@"65535" base:10 maximum:UINT16_MAX value:&value]);
    XCTAssertEqual(value, 65535u);
    for (NSString *invalid in @[@"", @"-1", @"+1", @"128foo", @" 128", @"1.0", @"65536", @"4294967296"]) {
        XCTAssertFalse([DESFireReader parseUnsigned:invalid base:10 maximum:UINT16_MAX value:&value], @"%@", invalid);
    }
    XCTAssertFalse([DESFireReader parseUnsigned:@"1000000" base:16 maximum:0xFFFFFF value:&value]);
    XCTAssertFalse([DESFireReader parseUnsigned:@"1" base:10 maximum:0 value:&value]);
    XCTAssertTrue([DESFireReader parseUnsigned:@"0" base:10 maximum:0 value:&value]);
    XCTAssertTrue([DESFireReader parseUnsigned:@"4294967295" base:10 maximum:UINT32_MAX value:&value]);
    XCTAssertFalse([DESFireReader parseUnsigned:@"4294967296" base:10 maximum:UINT32_MAX value:&value]);
}

- (void)testAllDemoOperationsHaveValidRequests {
    for (DFOperation operation = DFOpenReader; operation <= DFChangeFileSettings; operation++) {
        XCTAssertNil([[self validRequest] validationErrorForOperation:operation], @"Operation %ld", (long)operation);
    }
}

- (void)testAuthenticationVariants {
    DFRequest *p = [self validRequest];
    p.key = [NSData data];
    XCTAssertNotNil([p validationErrorForOperation:DFReadFile]);
    p.useInternalKey = YES;
    p.readerKeyNumber = 15;
    XCTAssertNil([p validationErrorForOperation:DFReadFile]);
    p.readerKeyNumber = 16;
    XCTAssertNotNil([p validationErrorForOperation:DFReadFile]);
    p.useInternalKey = NO;
    p.authenticate = NO;
    for (NSNumber *operation in @[@(DFCreateApplication), @(DFCreateFile), @(DFDeleteFile), @(DFReadFile), @(DFWriteFile)]) {
        XCTAssertNil([p validationErrorForOperation:operation.integerValue]);
    }
    p.communicationMode = 1;
    XCTAssertNotNil([p validationErrorForOperation:DFReadFile]);
    p.communicationMode = 3;
    XCTAssertNotNil([p validationErrorForOperation:DFWriteFile]);
    p.authenticate = YES;
    p.key = [NSMutableData dataWithLength:16];
    XCTAssertNil([p validationErrorForOperation:DFWriteFile]);
    p.communicationMode = 2;
    XCTAssertNotNil([p validationErrorForOperation:DFWriteFile]);
}

- (void)testApplicationAndFileBoundaries {
    DFRequest *p = [self validRequest];
    p.aid = 0;
    XCTAssertNotNil([p validationErrorForOperation:DFCreateApplication]);
    XCTAssertNotNil([p validationErrorForOperation:DFDeleteApplication]);
    XCTAssertNil([p validationErrorForOperation:DFGetUID]);
    p.aid = 0x1000000;
    XCTAssertNotNil([p validationErrorForOperation:DFGetUID]);
    p.aid = 0xFFFFFF;
    p.maximumKeys = 14;
    XCTAssertNil([p validationErrorForOperation:DFCreateApplication]);
    p.maximumKeys = 15;
    XCTAssertNotNil([p validationErrorForOperation:DFCreateApplication]);
    p.maximumKeys = 0;
    XCTAssertNotNil([p validationErrorForOperation:DFCreateApplication]);
    p.fileID = 31;
    p.fileSize = 0xFFFFFF;
    p.readKey = p.writeKey = p.readWriteKey = p.changeKey = 15;
    XCTAssertNil([p validationErrorForOperation:DFCreateFile]);
    p.fileID = 32;
    XCTAssertNotNil([p validationErrorForOperation:DFCreateFile]);
    p.fileID = 0;
    p.fileSize = 0;
    XCTAssertNotNil([p validationErrorForOperation:DFCreateFile]);
    p.fileSize = 0x1000000;
    XCTAssertNotNil([p validationErrorForOperation:DFCreateFile]);
    p.fileSize = 128;
    p.readKey = 16;
    XCTAssertNotNil([p validationErrorForOperation:DFCreateFile]);
}

- (void)testTransferLengthsAndOldKeyRequirement {
    DFRequest *p = [self validRequest];
    p.offset = UINT16_MAX;
    p.length = UINT16_MAX;
    p.data = [NSMutableData dataWithLength:UINT16_MAX];
    XCTAssertNil([p validationErrorForOperation:DFReadFile]);
    XCTAssertNil([p validationErrorForOperation:DFWriteFile]);
    p.length = 0;
    XCTAssertNotNil([p validationErrorForOperation:DFReadFile]);
    XCTAssertNotNil([p validationErrorForOperation:DFWriteFile]);
    p.length = 1;
    XCTAssertNotNil([p validationErrorForOperation:DFWriteFile]);
    p.oldKey = [NSData data];
    XCTAssertNil([p validationErrorForOperation:DFChangeKey]);
    p.changedKeyNumber = 1;
    XCTAssertNotNil([p validationErrorForOperation:DFChangeKey]);
    p.oldKey = p.key;
    XCTAssertNil([p validationErrorForOperation:DFChangeKey]);
    p.replacementKey = [NSMutableData dataWithLength:15];
    XCTAssertNotNil([p validationErrorForOperation:DFChangeKey]);
}

- (void)testReaderPasswordAndSpeedValidation {
    DFRequest *p = [self validRequest];
    p.password = [@"1234567" dataUsingEncoding:NSASCIIStringEncoding];
    XCTAssertNotNil([p validationErrorForOperation:DFLockReaderKeys]);
    p.password = [@"123456789" dataUsingEncoding:NSASCIIStringEncoding];
    XCTAssertNotNil([p validationErrorForOperation:DFUnlockReaderKeys]);
    const uint8_t invalidPassword[8] = {0, '2', '3', '4', '5', '6', '7', '8'};
    p.password = [NSData dataWithBytes:invalidPassword length:8];
    XCTAssertNotNil([p validationErrorForOperation:DFLockReaderKeys]);
    p.txSpeed = 3;
    p.rxSpeed = 3;
    XCTAssertNil([p validationErrorForOperation:DFSetSpeed]);
    p.txSpeed = 4;
    XCTAssertNotNil([p validationErrorForOperation:DFSetSpeed]);
}

- (void)testKeySettingMappingMatchesWindowsDemo {
    const uint8_t expected[] = {0x0F, 0x0E, 0x09, 0x08, 0x07, 0x06, 0x01, 0x00};
    for (NSUInteger i = 0; i < 8; i++) {
        XCTAssertEqual([DESFireReader keySettingsWithAuthentication:(i & 2) != 0
            frozenSettings:(i & 4) != 0 frozenMaster:(i & 1) != 0], expected[i]);
    }
}

- (void)testTransportAndCardStatusBothMustSucceed {
    DFResult *r = [DFResult new];
    XCTAssertTrue(r.success);
    r.hasCardStatus = YES;
    XCTAssertFalse(r.success);
    r.cardStatus = 3001;
    XCTAssertTrue(r.success);
    r.cardStatus = 3000;
    XCTAssertFalse(r.success);
    r.cardStatus = 3001;
    r.status = 1;
    XCTAssertFalse(r.success);
}

- (void)testDisconnectedReaderCannotReturnReadData {
    DESFireReader *reader = [DESFireReader new];
    DFResult *result = [reader execute:DFReadFile request:[self validRequest]];
    XCTAssertFalse(result.success);
    XCTAssertEqual(result.data.length, 0u);
    XCTAssertTrue([result.message containsString:@"not connected"]);
    XCTAssertFalse(reader.connected);
    XCTAssertTrue([reader execute:DFCloseReader request:[DFRequest new]].success);
}

- (void)testInvalidRequestNeverReachesReader {
    DFRequest *p = [self validRequest];
    p.length = 0;
    DFResult *result = [[DESFireReader new] execute:DFReadFile request:p];
    XCTAssertFalse(result.success);
    XCTAssertEqual(result.data.length, 0u);
    XCTAssertTrue([result.message containsString:@"65535"]);
}

- (void)testDESFormattingAlwaysUsesFactoryNullKey {
    DFRequest *p = [self validRequest];
    p.formatKeyType = DFMasterKeyDES;
    p.key = [NSData data];
    XCTAssertNil([p validationErrorForOperation:DFFormatCard]);
    p.useInternalKey = YES;
    p.readerKeyNumber = 255;
    XCTAssertNil([p validationErrorForOperation:DFFormatCard]);
    XCTAssertTrue([[p keyDescriptionForOperation:DFFormatCard showKeys:YES] containsString:@"Authenticate with DES null key 0000000000000000 as PICC master key (key 0)"]);
    p.useInternalKey = NO;
    p.formatKeyType = DFMasterKeyAES;
    XCTAssertNotNil([p validationErrorForOperation:DFFormatCard]);
    p.key = [NSMutableData dataWithLength:16];
    XCTAssertNil([p validationErrorForOperation:DFFormatCard]);
}

- (void)testWindowsFactoryConversionStopsOnSuccessAndLimitsRetries {
    for (NSUInteger successfulAttempt = 1; successfulAttempt <= 10; successfulAttempt++) {
        ConversionTestReader *reader = [ConversionTestReader new];
        reader.successOnAttempt = successfulAttempt;
        DFResult *result = [reader convertFactoryCard];
        XCTAssertTrue(result.success);
        XCTAssertTrue(result.hasCardStatus);
        XCTAssertEqual(reader.attempts, successfulAttempt);
        XCTAssertEqual(reader.verifications, 1u);
    }
    ConversionTestReader *reader = [ConversionTestReader new];
    DFResult *failed = [reader convertFactoryCard];
    XCTAssertFalse(failed.success);
    XCTAssertEqual(reader.attempts, 10u);
    XCTAssertEqual(reader.verifications, 0u);
    XCTAssertEqual(failed.status, 0x0Eu);
    XCTAssertTrue([failed.message containsString:@"after 10 attempts"]);
    ConversionTestReader *unverified = [ConversionTestReader new];
    unverified.successOnAttempt = 1;
    unverified.verificationFails = YES;
    DFResult *unconfirmed = [unverified convertFactoryCard];
    XCTAssertFalse(unconfirmed.success);
    XCTAssertEqual(unconfirmed.cardStatus, 3002);
    XCTAssertEqual(unverified.attempts, 1u);
    XCTAssertEqual(unverified.verifications, 1u);
    XCTAssertTrue([unconfirmed.message containsString:@"The card may already be changed"]);
}

- (void)testStatusLinesAndOutputMarks {
    DFResult *ok = [DFResult new];
    ok.hasCardStatus = YES;
    ok.cardStatus = 3001;
    ok.executionTime = 12;
    XCTAssertEqualObjects(ok.statusText, @"Status OK (3001, 12 ms)");
    DFResult *failed = [DFResult new];
    failed.hasCardStatus = YES;
    failed.cardStatus = 3232;
    XCTAssertEqualObjects(failed.statusText, @"Reader UFR_OK (0)\nStatus DESFIRE_CARD_APPLICATION_NOT_FOUND (3232)");
    XCTAssertFalse([failed.statusText containsString:@"["]);
    XCTAssertEqualObjects(DFMarkLines(@"a\n\n\u2022 b", DFOutputMark), @"\u2190 a\n\u2022 b");
    XCTAssertEqualObjects([DESFireReader keySettingsText:0x0F maximumKeys:1 picc:YES],
        @"master key changeable, free listing, free creation of applications; deletion still needs master authentication, settings changeable");
    XCTAssertEqualObjects([DESFireReader cardTypeName:0x47], @"MIFARE DESFire EV3 8K");
}

- (void)testAuthenticationKeysAndAIDsAreSynchronizedAcrossTabs {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    NSTextField *cardKey = [controller valueForKey:@"cardKey"];
    cardKey.stringValue = @"0123456789ABCDEF0123456789ABCDEF";
    [controller controlTextDidChange:[NSNotification notificationWithName:NSControlTextDidChangeNotification object:cardKey]];
    for (NSString *name in @[@"applicationKey", @"keysKey", @"filesKey"])
        XCTAssertEqualObjects(((NSTextField *)[controller valueForKey:name]).stringValue, cardKey.stringValue, @"%@", name);
    NSTextField *filesAid = [controller valueForKey:@"filesAid"];
    filesAid.stringValue = @"F00010";
    [controller controlTextDidChange:[NSNotification notificationWithName:NSControlTextDidChangeNotification object:filesAid]];
    for (NSString *name in @[@"cardAid", @"applicationAid", @"keysAid"])
        XCTAssertEqualObjects(((NSTextField *)[controller valueForKey:name]).stringValue, @"F00010", @"%@", name);
    XCTAssertNotEqualObjects(((NSTextField *)[controller valueForKey:@"readerKey"]).stringValue, cardKey.stringValue);
}

- (void)testKeyDescriptionsRespectOptInAndActualKeySource {
    DFRequest *p = [self validRequest];
    p.key = [DESFireReader hexData:@"0123456789ABCDEF0123456789ABCDEF"];
    NSString *hidden = [p keyDescriptionForOperation:DFReadFile showKeys:NO];
    XCTAssertTrue([hidden containsString:@"Authenticate with Key * hidden * as application master key (key 0)"]);
    XCTAssertFalse([hidden containsString:@"0123456789ABCDEF"]);
    XCTAssertTrue([[p keyDescriptionForOperation:DFReadFile showKeys:YES] containsString:@"0123456789ABCDEF0123456789ABCDEF"]);
    p.useInternalKey = YES;
    p.readerKeyNumber = 7;
    NSString *internal = [p keyDescriptionForOperation:DFReadFile showKeys:YES];
    XCTAssertTrue([internal containsString:@"Authenticate with Key from reader in slot 7 as"]);
    XCTAssertFalse([internal containsString:@"0123456789ABCDEF"]);
    p.authenticate = NO;
    XCTAssertTrue([[p keyDescriptionForOperation:DFReadFile showKeys:YES] containsString:@"No authentication used"]);
    XCTAssertTrue([[p keyDescriptionForOperation:DFFormatCard showKeys:NO] containsString:@"PICC master key (key 0)"]);
    p.useInternalKey = NO;
    p.formatKeyType = DFMasterKeyDES;
    NSString *des = [p keyDescriptionForOperation:DFFormatCard showKeys:YES];
    XCTAssertTrue([des containsString:@"Authenticate with DES null key 0000000000000000 as PICC master key"]);
    XCTAssertFalse([des containsString:@"0123456789ABCDEF"]);
    NSString *conversion = [p keyDescriptionForOperation:DFConvertToAES showKeys:YES];
    XCTAssertTrue([conversion containsString:@"DES null key 0000000000000000"]);
    XCTAssertTrue([conversion containsString:@"New AES PICC master key 00000000000000000000000000000000"]);
    XCTAssertFalse([conversion containsString:@"FEDCBA"]);
    p.changedKeyNumber = 1;
    p.authenticate = YES;
    NSString *change = [p keyDescriptionForOperation:DFChangeKey showKeys:NO];
    XCTAssertTrue([change containsString:@"New key 1 * hidden *"]);
    XCTAssertTrue([change containsString:@"Old key 1 * hidden *"]);
    XCTAssertTrue([[p keyDescriptionForOperation:DFStoreReaderKey showKeys:NO] containsString:@"stored in reader slot 7"]);
}

- (NSWindowController *)guiWindow {
    NSWindowController *window = [[NSStoryboard storyboardWithName:@"Main" bundle:nil] instantiateInitialController];
    ViewController *controller = (ViewController *)window.contentViewController;
    XCTAssertNotNil(controller.view);
    return window;
}

- (void)testZipInterfaceAndDisconnectedButtons {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    NSTabView *tabs = [controller valueForKey:@"tabs"];
    XCTAssertEqualObjects([tabs.tabViewItems valueForKey:@"label"],
        (@[@"Reader", @"Card", @"Applications", @"App Keys", @"Files", @"Automation"]));
    XCTAssertEqualObjects(((NSButton *)[controller valueForKey:@"connectButton"]).identifier, @"BtnConnectReader");
    XCTAssertTrue(((NSButton *)[controller valueForKey:@"connectButton"]).enabled);
    XCTAssertFalse(((NSButton *)[controller valueForKey:@"disconnectButton"]).enabled);
    NSArray<NSButton *> *hardware = [controller valueForKey:@"hardwareButtons"];
    XCTAssertGreaterThan(hardware.count, 15u);
    for (NSButton *button in hardware) XCTAssertFalse(button.enabled, @"%@", button.title);
    for (NSView *view in [controller allFormViews]) {
        XCTAssertFalse([view isKindOfClass:NSSecureTextField.class]);
        if ([view isKindOfClass:NSButton.class])
            XCTAssertNotEqualObjects(((NSButton *)view).title, @"Get key settings");
    }
}

- (void)testEveryStoryboardHardwareActionIsWiredAndUsesTheCorrectOperation {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    NSDictionary<NSString *, NSNumber *> *expected = @{
        @"BtnRealUidCard": @(DFGetUID), @"BtnFreeMemCard": @(DFFreeMemory),
        @"BtnCreateApp": @(DFCreateApplication), @"BtnDeleteApp": @(DFDeleteApplication),
        @"BtnCreateFiles": @(DFCreateFile), @"BtnDeleteFiles": @(DFDeleteFile),
        @"BtnGetSettingsApp": @(DFGetKeySettings), @"BtnSetSettingsApp": @(DFChangeKeySettings),
        @"BtnChangeAesKeys": @(DFChangeKey), @"BtnFormatCard": @(DFFormatCard),
        @"BtnDesToAes": @(DFConvertToAES), @"BtnStoreAesKeyIntoReader": @(DFStoreReaderKey),
        @"BtnLockReader": @(DFLockReaderKeys), @"BtnUnlockReader": @(DFUnlockReaderKeys),
        @"BtnGetBaud": @(DFGetSpeed), @"BtnSetBaud": @(DFSetSpeed),
        @"BtnInspectCard": @(DFInspectMasterKey), @"BtnChangeAccessFiles": @(DFChangeFileSettings)
    };
    NSMutableSet *found = [NSMutableSet set];
    NSUInteger configurationButtons = 0;
    for (NSView *view in [controller allFormViews]) {
        if (![view isKindOfClass:NSButton.class]) continue;
        NSButton *button = (NSButton *)view;
        XCTAssertNotEqual(button.action, NSSelectorFromString(@"pendingOperation:"));
        NSNumber *operation = button.identifier ? expected[button.identifier] : nil;
        if (operation) {
            XCTAssertEqual(button.action, @selector(performOperation:));
            XCTAssertEqual(button.tag, operation.integerValue, @"%@", button.identifier);
            [found addObject:button.identifier];
        }
        if (button.action == @selector(performOperation:) && button.tag == DFConfigureCard) configurationButtons++;
    }
    XCTAssertEqual(found.count, expected.count);
    XCTAssertEqual(configurationButtons, 1u);
}

- (void)testRequestsUseTheKeyFieldsAndSlotsFromTheirOwnTab {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    ((NSTextField *)[controller valueForKey:@"readerKey"]).stringValue = @"11111111111111111111111111111111";
    ((NSTextField *)[controller valueForKey:@"cardKey"]).stringValue = @"22222222222222222222222222222222";
    ((NSTextField *)[controller valueForKey:@"applicationKey"]).stringValue = @"33333333333333333333333333333333";
    ((NSTextField *)[controller valueForKey:@"keysKey"]).stringValue = @"44444444444444444444444444444444";
    [(NSPopUpButton *)[controller valueForKey:@"readerSlot"] selectItemAtIndex:15];
    [(NSPopUpButton *)[controller valueForKey:@"cardReaderSlot"] selectItemAtIndex:14];
    [(NSPopUpButton *)[controller valueForKey:@"applicationReaderSlot"] selectItemAtIndex:13];
    [(NSPopUpButton *)[controller valueForKey:@"keysReaderSlot"] selectItemAtIndex:12];
    DFRequest *reader = [controller requestForOperation:DFStoreReaderKey];
    DFRequest *card = [controller requestForOperation:DFFormatCard];
    XCTAssertEqualObjects(reader.key, [DESFireReader hexData:@"11111111111111111111111111111111"]);
    XCTAssertEqualObjects(card.key, [DESFireReader hexData:@"22222222222222222222222222222222"]);
    XCTAssertEqual(reader.readerKeyNumber, 15);
    XCTAssertEqual(card.readerKeyNumber, 14);
    XCTAssertEqual(card.aid, 0u);
    XCTAssertEqual(card.authenticationKeyNumber, 0);
    [controller selectionChanged:[controller valueForKey:@"applicationAES"]];
    DFRequest *application = [controller requestForOperation:DFGetKeySettings];
    XCTAssertEqualObjects(application.key, [DESFireReader hexData:@"33333333333333333333333333333333"]);
    XCTAssertEqual(application.readerKeyNumber, 13);
    [controller selectionChanged:[controller valueForKey:@"keysReader"]];
    DFRequest *keys = [controller requestForOperation:DFChangeKey];
    XCTAssertTrue(keys.useInternalKey);
    XCTAssertEqual(keys.readerKeyNumber, 12);
    XCTAssertEqualObjects(keys.key, [DESFireReader hexData:@"44444444444444444444444444444444"]);
    XCTAssertEqualObjects(keys.replacementKey, [NSMutableData dataWithLength:16]);
    [controller selectionChanged:[controller valueForKey:@"cardReader"]];
    XCTAssertTrue([controller requestForOperation:DFFormatCard].useInternalKey);
    XCTAssertNotNil([controller requestForOperation:DFConvertToAES]);
    DFResult *conversion = [DFResult new];
    [controller applyResult:conversion operation:DFConvertToAES];
    XCTAssertFalse([controller requestForOperation:DFFormatCard].useInternalKey);
    XCTAssertEqualObjects([controller requestForOperation:DFFormatCard].key, [NSMutableData dataWithLength:16]);
    XCTAssertEqualObjects(((NSTextField *)[controller valueForKey:@"readerKey"]).stringValue,
        @"11111111111111111111111111111111");
}

- (void)testApplicationsSettingsRoundTripAndNoAuthentication {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    DFRequest *publicSettings = [controller requestForOperation:DFGetKeySettings];
    XCTAssertNotNil(publicSettings);
    XCTAssertFalse(publicSettings.authenticate);
    XCTAssertNil([controller requestForOperation:DFChangeKeySettings]);
    [controller selectionChanged:[controller valueForKey:@"applicationAES"]];
    const uint8_t expected[] = {0x0F, 0x0E, 0x09, 0x08, 0x07, 0x06, 0x01, 0x00};
    for (NSUInteger index = 0; index < 8; index++) {
        DFResult *result = [DFResult new];
        result.keySettings = expected[index];
        result.maximumKeys = 0x8E;
        [controller applyResult:result operation:DFGetKeySettings];
        DFRequest *request = [controller requestForOperation:DFChangeKeySettings];
        XCTAssertEqual(request.keySettings, expected[index]);
        XCTAssertEqual(request.maximumKeys, 1);
    }
    [controller selectionChanged:[controller valueForKey:@"applicationCustomAid"]];
    ((NSTextField *)[controller valueForKey:@"applicationAid"]).stringValue = @"A10000";
    [controller updateInterface];
    DFResult *settings = [DFResult new];
    settings.keySettings = 0x0F;
    settings.maximumKeys = 14;
    [controller applyResult:settings operation:DFGetKeySettings];
    DFRequest *create = [controller requestForOperation:DFCreateApplication];
    XCTAssertEqual(create.aid, 0xA10000u);
    XCTAssertEqual(create.maximumKeys, 14);
    ((NSTextField *)[controller valueForKey:@"applicationAid"]).stringValue = @"000000";
    [controller updateInterface];
    XCTAssertNil([controller requestForOperation:DFCreateApplication]);
    XCTAssertEqual([controller requestForOperation:DFGetKeySettings].aid, 0u);
}

- (void)testCardFlagsAndFileCreationAreNotIgnored {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    XCTAssertNil([controller requestForOperation:DFConfigureCard]);
    ((NSButton *)[controller valueForKey:@"disableFormatting"]).state = NSControlStateValueOn;
    DFRequest *configuration = [controller requestForOperation:DFConfigureCard];
    XCTAssertTrue(configuration.disableFormatting);
    XCTAssertFalse(configuration.randomUID);
    ((NSButton *)[controller valueForKey:@"randomUID"]).state = NSControlStateValueOn;
    XCTAssertTrue([controller requestForOperation:DFConfigureCard].randomUID);
    ((NSTextField *)[controller valueForKey:@"filesAid"]).stringValue = @"123456";
    ((NSTextField *)[controller valueForKey:@"fileCapacity"]).stringValue = @"16777215";
    [(NSPopUpButton *)[controller valueForKey:@"filesReadRight"] selectItemAtIndex:14];
    [(NSPopUpButton *)[controller valueForKey:@"filesWriteRight"] selectItemAtIndex:15];
    [(NSPopUpButton *)[controller valueForKey:@"filesReadWriteRight"] selectItemAtIndex:3];
    [(NSPopUpButton *)[controller valueForKey:@"filesChangeRight"] selectItemAtIndex:4];
    DFRequest *create = [controller requestForOperation:DFCreateFile];
    XCTAssertNotNil(create);
    XCTAssertEqual(create.fileSize, 0xFFFFFFu);
    XCTAssertEqual(create.readKey, 14);
    XCTAssertEqual(create.writeKey, 15);
    XCTAssertEqual(create.readWriteKey, 3);
    XCTAssertEqual(create.changeKey, 4);
    XCTAssertFalse(create.authenticate);
    [controller selectionChanged:[controller valueForKey:@"filesReader"]];
    [[controller valueForKey:@"filesReaderSlot"] selectItemAtIndex:5];
    [[controller valueForKey:@"filesKeyNumber"] selectItemAtIndex:0];
    DFRequest *delete = [controller requestForOperation:DFDeleteFile];
    XCTAssertTrue(delete.authenticate);
    XCTAssertTrue(delete.useInternalKey);
    XCTAssertEqual(delete.readerKeyNumber, 5);
    XCTAssertEqual(delete.authenticationKeyNumber, 0);
    ((NSTextField *)[controller valueForKey:@"fileCapacity"]).stringValue = @"0";
    XCTAssertNil([controller requestForOperation:DFCreateFile]);
    XCTAssertNotNil([controller requestForOperation:DFDeleteFile]);
    [controller selectionChanged:[controller valueForKey:@"filesAES"]];
    XCTAssertNil([controller requestForOperation:DFCreateFile]);
}

- (void)testReadOnlyOperationDispatchUpdatesMenusAndDoesNotMutateCard {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    ConnectionTestReader *reader = [ConnectionTestReader new];
    reader.testConnected = YES;
    reader.response = [DFResult new];
    reader.response.txSpeed = 1;
    reader.response.rxSpeed = 2;
    [controller setValue:reader forKey:@"reader"];
    [controller setValue:@YES forKey:@"connected"];
    [controller updateInterface];
    NSButton *button = [NSButton new];
    button.title = @"Get baud rates";
    button.tag = DFGetSpeed;
    [controller performOperation:button];
    XCTAssertTrue([[controller valueForKey:@"busy"] boolValue]);
    NSPredicate *idle = [NSPredicate predicateWithBlock:^BOOL(id object, NSDictionary *bindings) {
        return ![[object valueForKey:@"busy"] boolValue];
    }];
    [self waitForExpectations:@[[[XCTNSPredicateExpectation alloc] initWithPredicate:idle object:controller]] timeout:3];
    XCTAssertEqualObjects(reader.operations, (@[@(DFGetSpeed)]));
    XCTAssertEqual(((NSPopUpButton *)[controller valueForKey:@"transmitSpeed"]).indexOfSelectedItem, 1);
    XCTAssertEqual(((NSPopUpButton *)[controller valueForKey:@"receiveSpeed"]).indexOfSelectedItem, 2);
}

- (void)testChangesRequireConfirmationAndFirmwareCapabilityIsConservative {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    for (NSNumber *operation in @[@(DFFormatCard), @(DFConfigureCard), @(DFConvertToAES), @(DFChangeKey),
        @(DFChangeKeySettings), @(DFDeleteApplication), @(DFDeleteFile), @(DFStoreReaderKey), @(DFSetSpeed),
        @(DFLockReaderKeys), @(DFChangeFileSettings)]) {
        XCTAssertNotNil([controller confirmationForOperation:operation.integerValue request:[self validRequest]]);
    }
    [controller setValue:@YES forKey:@"connected"];
    ((NSTextField *)[controller valueForKey:@"filesAid"]).stringValue = @"123456";
    [controller selectionChanged:[controller valueForKey:@"filesAES"]];
    XCTAssertFalse(((NSButton *)[controller valueForKey:@"changeAccessButton"]).enabled);
    XCTAssertTrue(((NSButton *)[controller valueForKey:@"changeAccessButton"]).hidden);
    DFResult *info = [DFResult new];
    info.firmwareVersion = 0x050051;
    [controller applyResult:info operation:DFOpenReader];
    [controller updateInterface];
    XCTAssertTrue(((NSButton *)[controller valueForKey:@"changeAccessButton"]).enabled);
    [controller selectionChanged:[controller valueForKey:@"filesNoAuth"]];
    XCTAssertFalse(((NSButton *)[controller valueForKey:@"changeAccessButton"]).enabled);
    info.firmwareVersion = 0x030937;
    [controller applyResult:info operation:DFOpenReader];
    [controller selectionChanged:[controller valueForKey:@"filesAES"]];
    XCTAssertFalse(((NSButton *)[controller valueForKey:@"changeAccessButton"]).enabled);
}

- (void)testNewBackendGuardsAndPublicSettingsDoNotRequireAKey {
    DFRequest *request = [self validRequest];
    request.authenticate = NO;
    request.key = [NSData data];
    XCTAssertNil([request validationErrorForOperation:DFGetKeySettings]);
    for (NSNumber *operation in @[@(DFChangeKeySettings), @(DFDeleteApplication), @(DFConfigureCard), @(DFChangeFileSettings)])
        XCTAssertNotNil([request validationErrorForOperation:operation.integerValue]);
    request.authenticate = YES;
    request.key = [NSMutableData dataWithLength:16];
    request.aid = 0;
    XCTAssertNotNil([request validationErrorForOperation:DFCreateFile]);
    request.authenticationKeyNumber = 1;
    XCTAssertNotNil([request validationErrorForOperation:DFGetUID]);
    request.authenticationKeyNumber = 0;
    request.changedKeyNumber = 1;
    XCTAssertNotNil([request validationErrorForOperation:DFChangeKey]);
}

- (void)testContextDependentApplicationLabelAndPICCGuards {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    NSButton *requirement = [controller valueForKey:@"applicationRequirement"];
    XCTAssertEqualObjects(requirement.title,
        @"Creating applications requires authentication with the PICC master key");
    NSTextField *aid = [controller valueForKey:@"applicationAid"];
    [controller setValue:@YES forKey:@"connected"];
    [controller selectionChanged:[controller valueForKey:@"applicationCustomAid"]];
    aid.stringValue = @"123456";
    [controller updateInterface];
    XCTAssertEqualObjects(requirement.title,
        @"Creating or deleting files requires authentication with the application master key");
    XCTAssertFalse(((NSButton *)[controller valueForKey:@"createApplicationButton"]).enabled);
    DFResult *settings = [DFResult new];
    settings.keySettings = 0x0F;
    settings.maximumKeys = 1;
    [controller applyResult:settings operation:DFGetKeySettings];
    [controller updateInterface];
    XCTAssertTrue(((NSButton *)[controller valueForKey:@"createApplicationButton"]).enabled);
    aid.stringValue = @"000000";
    [controller updateInterface];
    XCTAssertTrue([requirement.title containsString:@"PICC"]);
    XCTAssertFalse(((NSButton *)[controller valueForKey:@"createApplicationButton"]).enabled);
    aid.stringValue = @"123456";
    aid.stringValue = @"000000";
    [controller updateInterface];
    XCTAssertTrue([requirement.title containsString:@"PICC"]);
    XCTAssertTrue(aid.enabled);
}

- (void)testNoAuthenticationAndCommunicationRulesKeepInputsAvailable {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    [controller setValue:@YES forKey:@"connected"];
    [controller selectionChanged:[controller valueForKey:@"applicationCustomAid"]];
    ((NSTextField *)[controller valueForKey:@"applicationAid"]).stringValue = @"123456";
    [controller updateInterface];
    XCTAssertFalse(((NSButton *)[controller valueForKey:@"deleteApplicationButton"]).enabled);
    XCTAssertFalse(((NSButton *)[controller valueForKey:@"setApplicationSettingsButton"]).enabled);
    [controller selectionChanged:[controller valueForKey:@"applicationAES"]];
    XCTAssertTrue(((NSButton *)[controller valueForKey:@"deleteApplicationButton"]).enabled);
    XCTAssertFalse(((NSButton *)[controller valueForKey:@"setApplicationSettingsButton"]).enabled);
    DFResult *settings = [DFResult new];
    settings.keySettings = 0x0F;
    settings.maximumKeys = 1;
    [controller applyResult:settings operation:DFGetKeySettings];
    [controller updateInterface];
    XCTAssertTrue(((NSButton *)[controller valueForKey:@"setApplicationSettingsButton"]).enabled);
    XCTAssertFalse(((NSButton *)[controller valueForKey:@"changeKeyButton"]).enabled);
    [controller selectionChanged:[controller valueForKey:@"keysAES"]];
    XCTAssertTrue(((NSButton *)[controller valueForKey:@"changeKeyButton"]).enabled);
    NSPopUpButton *mode = [controller valueForKey:@"communicationMode"];
    [mode selectItemAtIndex:2];
    [controller communicationChanged:mode];
    XCTAssertEqual(((NSButton *)[controller valueForKey:@"filesAES"]).state, NSControlStateValueOn);
    [controller selectionChanged:[controller valueForKey:@"filesReader"]];
    [mode selectItemAtIndex:1];
    [controller communicationChanged:mode];
    XCTAssertEqual(((NSButton *)[controller valueForKey:@"filesReader"]).state, NSControlStateValueOn);
    [controller selectionChanged:[controller valueForKey:@"filesNoAuth"]];
    XCTAssertEqual(mode.indexOfSelectedItem, 0);
    XCTAssertFalse(((NSButton *)[controller valueForKey:@"changeAccessButton"]).enabled);
    for (NSView *view in [controller allFormViews]) {
        if ([view.identifier isEqualToString:@"TxtAesKeyFiles"] ||
            [view.identifier isEqualToString:@"TxtReaderKeyNoFiles"]) {
            XCTAssertTrue(((NSControl *)view).enabled);
        }
    }
    [controller setValue:@YES forKey:@"busy"];
    [controller updateInterface];
    for (NSButton *button in [controller valueForKey:@"hardwareButtons"]) XCTAssertFalse(button.enabled);
}

- (void)testKeyGeneratorsUseWholeBytesAndPreserveZipNames {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    NSUInteger generators = 0;
    for (NSView *view in [controller allFormViews]) {
        if (![view isKindOfClass:NSButton.class] || ((NSButton *)view).action != @selector(fillKey:)) continue;
        NSButton *button = (NSButton *)view;
        NSMapTable<NSButton *, NSTextField *> *fields = [controller valueForKey:@"keyGeneratorFields"];
        NSTextField *field = [fields objectForKey:button];
        for (NSView *sibling in field ? @[] : button.superview.subviews) {
            if ([sibling isKindOfClass:NSTextField.class] && ((NSTextField *)sibling).editable) {
                field = (NSTextField *)sibling;
                break;
            }
        }
        XCTAssertNotNil(field);
        field.stringValue = @"invalid";
        [controller fillKey:button];
        XCTAssertEqual(field.stringValue.length, 32u);
        XCTAssertEqual([DESFireReader hexData:field.stringValue].length, 16u);
        if (button.tag == 0) XCTAssertEqualObjects(field.stringValue, @"00000000000000000000000000000000");
        if (button.tag == 1) XCTAssertEqualObjects(field.stringValue, @"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        if (button.tag == 2) {
            XCTAssertEqualObjects(button.title, @"\u2684");
            XCTAssertEqualObjects(button.accessibilityLabel, [button.identifier isEqual:@"NewKeyRandom"] ?
                @"Generate random replacement AES key" : @"Generate random AES key");
        }
        generators++;
    }
    XCTAssertEqual(generators, 18u);
}

- (void)testFileTransfersUseActualLengthAndCardCapacityRatherThanCreateCapacity {
    FileTransferTestReader *reader = [FileTransferTestReader new];
    reader.capacity = 128;
    DFRequest *request = [self validRequest];
    request.fileSize = 1;
    request.offset = 42;
    request.data = [NSData dataWithBytes:"A\0B" length:3];
    DFResult *result = [reader transferFile:request writing:YES];
    XCTAssertTrue(result.success);
    XCTAssertEqual(request.offset, 0);
    XCTAssertEqual(request.length, 3);
    XCTAssertEqualObjects(reader.writtenData, request.data);
    XCTAssertEqualObjects(reader.operations, (@[@(DFGetFileSize), @(DFWriteFile)]));
    [reader.operations removeAllObjects];
    result = [reader transferFile:request writing:NO];
    XCTAssertTrue(result.success);
    XCTAssertEqual(request.length, 128);
    XCTAssertEqual(result.data.length, 128u);
    XCTAssertEqualObjects(reader.operations, (@[@(DFGetFileSize), @(DFReadFile)]));
}

- (void)testFileTransferBoundariesAndFailuresNeverReturnPartialSuccess {
    FileTransferTestReader *reader = [FileTransferTestReader new];
    reader.capacity = 2;
    DFRequest *request = [self validRequest];
    request.data = [NSMutableData dataWithLength:3];
    XCTAssertFalse([reader transferFile:request writing:YES].success);
    XCTAssertEqualObjects(reader.operations, (@[@(DFGetFileSize)]));
    for (NSNumber *length in @[@0, @65536]) {
        [reader.operations removeAllObjects];
        request.data = [NSMutableData dataWithLength:length.unsignedIntegerValue];
        XCTAssertFalse([reader transferFile:request writing:YES].success);
        XCTAssertEqual(reader.operations.count, 0u);
    }
    for (NSNumber *capacity in @[@0, @65536]) {
        [reader.operations removeAllObjects];
        reader.capacity = capacity.unsignedIntValue;
        XCTAssertFalse([reader transferFile:request writing:NO].success);
        XCTAssertEqualObjects(reader.operations, (@[@(DFGetFileSize)]));
    }
    reader.capacity = UINT16_MAX;
    XCTAssertEqual([reader transferFile:request writing:NO].data.length, (NSUInteger)UINT16_MAX);
    request.data = [NSMutableData dataWithLength:UINT16_MAX];
    XCTAssertTrue([reader transferFile:request writing:YES].success);
    reader.capacity = 128;
    reader.sizeFails = YES;
    [reader.operations removeAllObjects];
    XCTAssertFalse([reader transferFile:request writing:NO].success);
    XCTAssertEqualObjects(reader.operations, (@[@(DFGetFileSize)]));
    reader.sizeFails = NO;
    reader.transferFails = YES;
    XCTAssertFalse([reader transferFile:request writing:NO].success);
    reader.transferFails = NO;
    reader.shortRead = YES;
    XCTAssertFalse([reader transferFile:request writing:NO].success);
}

- (void)testFileRequestMapsAuthenticationAndModesWithoutUsingCreateCapacity {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    ((NSTextField *)[controller valueForKey:@"filesAid"]).stringValue = @"123ABC";
    ((NSTextField *)[controller valueForKey:@"fileCapacity"]).stringValue = @"invalid";
    [(NSPopUpButton *)[controller valueForKey:@"filesID"] selectItemAtIndex:31];
    [(NSPopUpButton *)[controller valueForKey:@"filesKeyNumber"] selectItemAtIndex:3];
    [(NSPopUpButton *)[controller valueForKey:@"filesReaderSlot"] selectItemAtIndex:7];
    NSPopUpButton *mode = [controller valueForKey:@"communicationMode"];
    [mode selectItemAtIndex:2];
    [controller selectionChanged:[controller valueForKey:@"filesReader"]];
    DFRequest *request = [controller fileRequest];
    XCTAssertNotNil(request);
    XCTAssertEqual(request.aid, 0x123ABCu);
    XCTAssertEqual(request.fileID, 31);
    XCTAssertEqual(request.authenticationKeyNumber, 3);
    XCTAssertEqual(request.readerKeyNumber, 7);
    XCTAssertTrue(request.authenticate);
    XCTAssertTrue(request.useInternalKey);
    XCTAssertEqual(request.communicationMode, 3);
    XCTAssertEqual(request.fileSize, 0u);
    [controller selectionChanged:[controller valueForKey:@"filesNoAuth"]];
    request = [controller fileRequest];
    XCTAssertFalse(request.authenticate);
    XCTAssertEqual(request.communicationMode, 0);
}

- (void)testDumpButtonReadsTheCardAndRendersAlignedHexASCII {
    XCTAssertEqualObjects([ViewController commandNameForOperation:DFCreateApplication], @"Create Application");
    XCTAssertEqualObjects([ViewController commandNameForOperation:DFCreateFile], @"Create File");
    XCTAssertEqualObjects([ViewController commandNameForOperation:DFDeleteApplication], @"Delete Application");
    XCTAssertEqualObjects([ViewController commandNameForOperation:DFDeleteFile], @"Delete File");
    XCTAssertEqualObjects([ViewController commandNameForOperation:DFGetFileSettings], @"Get File Settings");
    const uint8_t bytes[] = {0, 0x20, 0x41, 0x7E, 0x7F, 0xFF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0x42};
    NSString *dump = [ViewController hexASCIIDump:[NSData dataWithBytes:bytes length:sizeof(bytes)]];
    XCTAssertTrue([dump containsString:@"00000000  00 20 41 7E 7F FF 01 02  03 04 05 06 07 08 09 0A"]);
    XCTAssertTrue([dump containsString:@"|. A~.... ........|"]);
    XCTAssertTrue([dump containsString:@"00000010  42 "]);
    NSArray<NSString *> *lines = [dump componentsSeparatedByString:@"\n"];
    XCTAssertEqual([lines[1] rangeOfString:@"|"].location, [lines[2] rangeOfString:@"|"].location);
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    FileTransferTestReader *reader = [FileTransferTestReader new];
    reader.capacity = 17;
    [controller setValue:reader forKey:@"reader"];
    [controller setValue:@YES forKey:@"connected"];
    ((NSTextField *)[controller valueForKey:@"filesAid"]).stringValue = @"123456";
    [controller updateInterface];
    for (NSString *key in @[@"readFileButton", @"writeFileButton", @"dumpFileButton"])
        XCTAssertTrue(((NSButton *)[controller valueForKey:key]).enabled);
    [controller dumpFile:nil];
    XCTAssertFalse(((NSButton *)[controller valueForKey:@"dumpFileButton"]).enabled);
    NSPredicate *idle = [NSPredicate predicateWithBlock:^BOOL(id object, NSDictionary *bindings) {
        return ![[object valueForKey:@"busy"] boolValue];
    }];
    [self waitForExpectations:@[[[XCTNSPredicateExpectation alloc] initWithPredicate:idle object:controller]] timeout:3];
    XCTAssertEqualObjects(reader.operations, (@[@(DFGetFileSize), @(DFReadFile)]));
    NSTextView *output = [controller valueForKey:@"outputView"];
    XCTAssertTrue([output.string containsString:@"00000010  00"]);
    XCTAssertTrue(((NSButton *)[controller valueForKey:@"dumpFileButton"]).enabled);
}

- (void)testWriteLogsHexASCIIAsInputAfterAuthentication {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    FileTransferTestReader *reader = [FileTransferTestReader new];
    reader.capacity = 16;
    [controller setValue:reader forKey:@"reader"];
    [controller setValue:@YES forKey:@"connected"];
    [controller setValue:@YES forKey:@"busy"];
    DFRequest *request = [self validRequest];
    request.data = [@"12345678ABCDEFGH" dataUsingEncoding:NSASCIIStringEncoding];
    [controller executeFileRequest:request writing:YES saveURL:nil];
    NSPredicate *idle = [NSPredicate predicateWithBlock:^BOOL(id object, NSDictionary *bindings) {
        return ![[object valueForKey:@"busy"] boolValue];
    }];
    [self waitForExpectations:@[[[XCTNSPredicateExpectation alloc] initWithPredicate:idle object:controller]] timeout:3];
    NSTextView *output = [controller valueForKey:@"outputView"];
    NSRange key = [output.string rangeOfString:@"→ Authenticate with Key"];
    NSRange header = [output.string rangeOfString:@"→ Offset"];
    XCTAssertNotEqual(key.location, NSNotFound);
    XCTAssertNotEqual(header.location, NSNotFound);
    XCTAssertLessThan(key.location, header.location);
    XCTAssertTrue([output.string containsString:@"→ 00000000  31 32 33 34 35 36 37 38  41 42 43 44 45 46 47 48"]);
    XCTAssertTrue([output.string containsString:@"|12345678 ABCDEFGH|"]);
    XCTAssertEqualObjects(reader.writtenData, request.data);
}

- (void)testInputWidthsFitFullKeysAndSixDigitApplicationIDs {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    XCTAssertEqualObjects(window.window.frameAutosaveName, @"DESFireMainWindow");
    [controller.view layoutSubtreeIfNeeded];
    NSTabView *tabs = [controller valueForKey:@"tabs"];
    [tabs selectTabViewItemAtIndex:3];
    [controller.view layoutSubtreeIfNeeded];
    NSTextField *keysAid = [controller valueForKey:@"keysAid"];
    XCTAssertFalse(keysAid.hiddenOrHasHiddenAncestor);
    XCTAssertTrue(NSContainsRect(keysAid.superview.bounds, keysAid.frame));
    for (NSView *view in [controller allFormViews]) {
        if (![view isKindOfClass:NSTextField.class]) continue;
        NSTextField *field = (NSTextField *)view;
        if (!field.editable) continue;
        if (field.stringValue.length == 32) {
            CGFloat textWidth = [field.stringValue sizeWithAttributes:@{NSFontAttributeName:field.font}].width;
            XCTAssertGreaterThanOrEqual(field.frame.size.width, textWidth + 12);
            XCTAssertLessThanOrEqual(field.frame.size.width, textWidth + 36);
        }
        if (field.stringValue.length == 6 || [field.identifier isEqualToString:@"EdtPwdReader"]) {
            NSString *sample = field.stringValue.length == 6 ? @"FFFFFF" : @"WWWWWWWW";
            CGFloat textWidth = [sample sizeWithAttributes:@{NSFontAttributeName:field.font}].width;
            XCTAssertGreaterThanOrEqual(field.frame.size.width, textWidth + 12);
            XCTAssertLessThanOrEqual(field.frame.size.width, textWidth + 30);
        }
    }
}

- (void)testReadSavesBinaryDataAndFailedReadPreservesExistingFile {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    FileTransferTestReader *reader = [FileTransferTestReader new];
    reader.capacity = 3;
    reader.readData = [NSData dataWithBytes:"A\0B" length:3];
    [controller setValue:reader forKey:@"reader"];
    [controller setValue:@YES forKey:@"connected"];
    NSURL *url = [[NSURL fileURLWithPath:NSTemporaryDirectory() isDirectory:YES]
        URLByAppendingPathComponent:NSUUID.UUID.UUIDString];
    NSPredicate *idle = [NSPredicate predicateWithBlock:^BOOL(id object, NSDictionary *bindings) {
        return ![[object valueForKey:@"busy"] boolValue];
    }];
    [controller setValue:@YES forKey:@"busy"];
    [controller performFileRequest:[self validRequest] writing:NO saveURL:url];
    [self waitForExpectations:@[[[XCTNSPredicateExpectation alloc] initWithPredicate:idle object:controller]] timeout:3];
    XCTAssertEqualObjects([NSData dataWithContentsOfURL:url], reader.readData);
    reader.transferFails = YES;
    reader.readData = [NSData dataWithBytes:"XYZ" length:3];
    [controller setValue:@YES forKey:@"busy"];
    [controller performFileRequest:[self validRequest] writing:NO saveURL:url];
    [self waitForExpectations:@[[[XCTNSPredicateExpectation alloc] initWithPredicate:idle object:controller]] timeout:3];
    XCTAssertEqualObjects([NSData dataWithContentsOfURL:url], [NSData dataWithBytes:"A\0B" length:3]);
    NSError *error = nil;
    XCTAssertTrue([NSFileManager.defaultManager removeItemAtURL:url error:&error], @"%@", error);
}

- (void)testConnectionStateComesFromReaderAndNeverCallsCardOperations {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    ConnectionTestReader *reader = [ConnectionTestReader new];
    reader.failOpening = YES;
    [controller setValue:reader forKey:@"reader"];
    NSButton *connect = [controller valueForKey:@"connectButton"];
    NSButton *disconnect = [controller valueForKey:@"disconnectButton"];
    [connect performClick:nil];
    XCTAssertFalse(connect.enabled);
    NSPredicate *idle = [NSPredicate predicateWithBlock:^BOOL(id object, NSDictionary *bindings) {
        return ![[object valueForKey:@"busy"] boolValue];
    }];
    [self waitForExpectations:@[[[XCTNSPredicateExpectation alloc] initWithPredicate:idle object:controller]] timeout:3];
    XCTAssertTrue(connect.enabled);
    XCTAssertFalse(disconnect.enabled);
    reader.failOpening = NO;
    [connect performClick:nil];
    [self waitForExpectations:@[[[XCTNSPredicateExpectation alloc] initWithPredicate:idle object:controller]] timeout:3];
    XCTAssertFalse(connect.enabled);
    XCTAssertTrue(disconnect.enabled);
    [disconnect performClick:nil];
    [self waitForExpectations:@[[[XCTNSPredicateExpectation alloc] initWithPredicate:idle object:controller]] timeout:3];
    XCTAssertTrue(connect.enabled);
    XCTAssertFalse(disconnect.enabled);
    XCTAssertEqualObjects(reader.operations, (@[@(DFOpenReader), @(DFOpenReader), @(DFCloseReader)]));
}

- (void)testHelpAndOutputGrowWithoutAmbiguousFormLayout {
    NSWindowController *window = [self guiWindow];
    ViewController *controller = (ViewController *)window.contentViewController;
    NSTabView *tabs = [controller valueForKey:@"tabs"];
    NSTextView *output = [controller valueForKey:@"outputView"];
    for (NSTabViewItem *tab in tabs.tabViewItems) {
        [tabs selectTabViewItem:tab];
        [window.window setContentSize:NSMakeSize(1000, 740)];
        [controller.view layoutSubtreeIfNeeded];
        NSScrollView *help = nil;
        if ([tab.identifier isEqual:@"automation"])
            help = ((NSTextView *)[controller valueForKey:@"scriptView"]).enclosingScrollView;
        for (NSView *view in tab.view.subviews)
            if ([view isKindOfClass:NSScrollView.class]) help = (NSScrollView *)view;
        XCTAssertNotNil(help);
        NSRect oldHelp = help.frame;
        NSRect oldOutput = output.enclosingScrollView.frame;
        [window.window setContentSize:NSMakeSize(1200, 940)];
        [controller.view layoutSubtreeIfNeeded];
        XCTAssertEqualWithAccuracy(help.frame.size.width - oldHelp.size.width, 200, 2, @"%@", tab.label);
        XCTAssertEqualWithAccuracy(output.enclosingScrollView.frame.size.width - oldOutput.size.width, 200, 2);
        XCTAssertEqualWithAccuracy(output.enclosingScrollView.frame.size.height - oldOutput.size.height, 200, 2);
        XCTAssertEqualWithAccuracy(output.enclosingScrollView.frame.origin.y, 12, 2);
        for (NSView *view in [controller allFormViews]) {
            if ([view isKindOfClass:NSControl.class] && ![view isKindOfClass:NSScroller.class])
                XCTAssertFalse(view.hasAmbiguousLayout, @"%@ %@", tab.label, view.identifier);
        }
    }
}

@end
