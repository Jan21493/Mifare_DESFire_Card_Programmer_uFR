#import <XCTest/XCTest.h>

@interface NFC_Mifare_DESFire_ToolUITests : XCTestCase
@end

@implementation NFC_Mifare_DESFire_ToolUITests

- (void)setUp {
    [super setUp];
    self.continueAfterFailure = NO;
    [[XCUIApplication new] launch];
}

- (void)testZipTabsAndOfflineControls {
    XCUIApplication *app = [XCUIApplication new];
    XCTAssertTrue([app.buttons[@"BtnConnectReader"] waitForExistenceWithTimeout:10]);
    XCTAssertTrue(app.buttons[@"BtnConnectReader"].enabled);
    XCTAssertFalse(app.buttons[@"BtnDisconnectReader"].enabled);
    XCTAssertFalse(app.buttons[@"BtnStoreAesKeyIntoReader"].enabled);
    XCTAssertTrue(app.textFields[@"EdtPwdReader"].exists);
    for (NSString *tab in @[@"Card", @"Applications", @"App Keys", @"Files", @"Reader"]) {
        XCUIElement *element = app.tabs[tab];
        XCTAssertTrue(element.exists);
        [[element coordinateWithNormalizedOffset:CGVectorMake(0.5, 0.5)] click];
        XCTAssertEqual([element.value integerValue], 1);
        if ([tab isEqualToString:@"App Keys"]) {
            XCUIElement *aid = app.textFields[@"TxtAidAppKeys"];
            XCTAssertTrue(aid.exists);
            XCTAssertTrue(aid.hittable);
            [aid click];
            [aid typeKey:@"a" modifierFlags:XCUIKeyModifierCommand];
            [aid typeText:@"123ABC"];
            XCTAssertEqualObjects(aid.value, @"123ABC");
        }
        XCTAttachment *image = [XCTAttachment attachmentWithScreenshot:app.windows.firstMatch.screenshot];
        image.name = tab;
        image.lifetime = XCTAttachmentLifetimeKeepAlways;
        [self addAttachment:image];
    }
    XCUIElement *applications = app.tabs[@"Applications"];
    [[applications coordinateWithNormalizedOffset:CGVectorMake(0.5, 0.5)] click];
    XCTAssertTrue(app.checkBoxes[@"ChkBxAuthMasterKeyApp"].exists);
    XCTAssertFalse(app.buttons[@"BtnCreateApp"].enabled);
}

- (void)testAutomationTabCanEditOffline {
    XCUIApplication *app = [XCUIApplication new];
    XCUIElement *tab = app.tabs[@"Automation"];
    XCTAssertTrue([tab waitForExistenceWithTimeout:10]);
    [[tab coordinateWithNormalizedOffset:CGVectorMake(0.5, 0.5)] click];
    for (NSString *name in @[@"Play", @"Save", @"Load", @"Clear"])
        XCTAssertTrue(app.buttons[[@"Script" stringByAppendingString:name]].enabled);
    XCTAssertFalse(app.buttons[@"ScriptStop"].enabled);
    XCUIElement *commands = app.textViews[@"ScriptCommands"];
    XCTAssertTrue(commands.exists);
    XCTAssertTrue(commands.hittable);
    [commands click];
    [commands typeKey:@"a" modifierFlags:XCUIKeyModifierCommand];
    [commands typeText:@"# Editable commands\nGetFreeMemory"];
    XCTAssertEqualObjects(commands.value, @"# Editable commands\nGetFreeMemory");
    // Offline preflight must not try to open a reader implicitly.
    [app.buttons[@"ScriptPlay"] click];
    XCTAssertTrue(app.buttons[@"ScriptPlay"].enabled);
    XCTAssertFalse(app.buttons[@"ScriptStop"].enabled);
    XCTAssertEqualObjects(commands.value, @"# Editable commands\nGetFreeMemory");
    XCTAttachment *image = [XCTAttachment attachmentWithScreenshot:app.windows.firstMatch.screenshot];
    image.name = @"Automation";
    image.lifetime = XCTAttachmentLifetimeKeepAlways;
    [self addAttachment:image];
    XCUIElement *reader = app.tabs[@"Reader"];
    [[reader coordinateWithNormalizedOffset:CGVectorMake(0.5, 0.5)] click];
    XCTAssertTrue(app.buttons[@"BtnConnectReader"].enabled);
    XCTAssertFalse(app.buttons[@"BtnDisconnectReader"].enabled);
}

@end
