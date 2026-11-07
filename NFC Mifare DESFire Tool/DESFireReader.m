#import "DESFireReader.h"
#include "uFCoder.h"

NSString *const DFCommandMark = @"\u25B6 ";
NSString *const DFInputMark = @"\u2192 ";
NSString *const DFOutputMark = @"\u2190 ";
NSString *const DFNoteMark = @"\u2022 ";
NSString *const DFWarningMark = @"\u26A0 ";

NSString *DFMarkLines(NSString *text, NSString *mark) {
    NSArray<NSString *> *marks = @[DFCommandMark, DFInputMark, DFOutputMark, DFNoteMark, DFWarningMark];
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    for (NSString *line in [text componentsSeparatedByString:@"\n"]) {
        if (!line.length) continue;
        BOOL marked = NO;
        for (NSString *existing in marks) marked = marked || [line hasPrefix:existing];
        [lines addObject:marked ? line : [mark stringByAppendingString:line]];
    }
    return [lines componentsJoinedByString:@"\n"];
}

static NSString *DFHex(const uint8_t *bytes, NSUInteger length, BOOL lowercase) {
    NSMutableString *hex = [NSMutableString stringWithCapacity:length * 2];
    for (NSUInteger i = 0; i < length; i++) [hex appendFormat:lowercase ? @"%02x" : @"%02X", bytes[i]];
    return hex;
}

static NSString *DFJoin(NSArray<NSString *> *lines) {
    NSMutableArray<NSString *> *filled = [NSMutableArray array];
    for (NSString *line in lines) if (line.length) [filled addObject:line];
    return [filled componentsJoinedByString:@"\n"];
}

static NSString *DFCommunicationName(uint8_t mode) {
    return mode == 0 ? @"plain" : mode == 1 ? @"MAC" : mode == 3 ? @"encrypted" : [NSString stringWithFormat:@"code %u", mode];
}

static NSString *DFAccessName(uint8_t key) {
    return key == 14 ? @"free" : key == 15 ? @"denied" : [NSString stringWithFormat:@"key %u", key];
}

static NSString *DFSpeedName(uint8_t speed) {
    const unsigned rates[] = {106, 212, 424, 848};
    return speed < 4 ? [NSString stringWithFormat:@"%u kbps", rates[speed]] : [NSString stringWithFormat:@"code %u", speed];
}

static NSString *DFKeyCount(uint8_t count) {
    return [NSString stringWithFormat:@"%u key%@", count, count == 1 ? @"" : @"s"];
}

@implementation DFRequest
- (instancetype)init {
    if ((self = [super init])) {
        _key = [NSData data];
        _replacementKey = [NSData data];
        _oldKey = [NSData data];
        _data = [NSData data];
        _password = [NSData data];
        _authenticate = YES;
        _maximumKeys = 1;
        _keySettings = 0x0F;
    }
    return self;
}

- (NSString *)validationErrorForOperation:(DFOperation)operation {
    if (operation < DFOpenReader || operation > DFGetFileSettings) return @"Unknown operation.";
    BOOL usesAID = operation == DFGetUID || operation == DFGetFileSize || operation == DFChangeFileSettings ||
        operation == DFGetFileSettings ||
        (operation >= DFCreateApplication && operation <= DFChangeKey);
    if (usesAID && self.aid > 0xFFFFFF) return @"AID must be in the range 000000 to FFFFFF.";
    if ((operation == DFCreateApplication || operation == DFDeleteApplication) && self.aid == 0)
        return @"AID 000000 is reserved for the card level.";
    BOOL optionalAuthentication = operation == DFCreateApplication || operation == DFCreateFile ||
        operation == DFDeleteFile || operation == DFReadFile || operation == DFWriteFile ||
        operation == DFGetFileSize || operation == DFGetFileSettings || operation == DFGetKeySettings;
    BOOL usesDES = operation == DFFormatCard && self.formatKeyType == DFMasterKeyDES;
    if (operation == DFFormatCard) {
        if (self.formatKeyType != DFMasterKeyAES && self.formatKeyType != DFMasterKeyDES)
            return @"Invalid card master key type.";
    }
    BOOL usesKey = operation == DFGetUID || operation == DFDeleteApplication ||
        (operation >= DFChangeKeySettings && operation <= DFRandomUID && !usesDES) ||
        operation == DFConfigureCard || operation == DFChangeFileSettings ||
        (optionalAuthentication && self.authenticate);
    if (!self.authenticate && (operation == DFDeleteApplication || operation == DFChangeKeySettings ||
        operation == DFChangeKey || operation == DFFormatCard || operation == DFRandomUID ||
        operation == DFConfigureCard || operation == DFChangeFileSettings))
        return @"This operation requires authentication.";
    if ((usesKey && self.useInternalKey) || operation == DFStoreReaderKey) {
        if (self.readerKeyNumber > 15) return @"Reader key slot must be in the range 0 to 15.";
    }
    if ((usesKey && !self.useInternalKey) || operation == DFStoreReaderKey) {
        if (self.key.length != 16) return @"AES key must contain exactly 16 bytes, 32 hexadecimal digits.";
    }
    if ((operation == DFGetUID || operation == DFReadFile || operation == DFWriteFile ||
         operation == DFGetFileSize || operation == DFChangeKey) &&
        self.authenticationKeyNumber > 13) return @"Authentication key number must be in the range 0 to 13.";
    if (operation == DFCreateApplication && (self.maximumKeys < 1 || self.maximumKeys > 14))
        return @"An application has 1 to 14 keys.";
    if (operation == DFCreateApplication || operation == DFChangeKeySettings) {
        if (!self.aid && (self.keySettings & 0xF0)) return @"PICC key settings must keep the reserved upper nibble zero.";
        uint8_t changeKey = self.keySettings >> 4;
        if (operation == DFCreateApplication && changeKey > 0 && changeKey < 14 && changeKey >= self.maximumKeys)
            return @"The key selected for key-change authentication must exist in the new application.";
    }
    if ((operation >= DFCreateFile && operation <= DFWriteFile) || operation == DFGetFileSize ||
        operation == DFChangeFileSettings || operation == DFGetFileSettings) {
        if (self.fileID > 31) return @"File number must be in the range 0 to 31.";
        if (!self.aid) return @"The PICC master application cannot contain data files.";
    }
    if ((operation == DFGetUID || operation == DFChangeKey) && !self.aid && self.authenticationKeyNumber != 0)
        return @"The PICC master application has key 0 only.";
    if (operation == DFChangeKey && !self.aid && self.changedKeyNumber != 0)
        return @"The PICC master application has key 0 only.";
    if (operation == DFCreateFile || operation == DFChangeFileSettings) {
        if (operation == DFCreateFile &&
            (!self.fileSize || self.fileSize > 0xFFFFFF)) return @"File capacity must be in the range 1 to 16777215 bytes.";
        if (self.readKey > 15 || self.writeKey > 15 || self.readWriteKey > 15 || self.changeKey > 15)
            return @"Access rights must be in the range 0 to 15.";
    }
    if (operation == DFCreateFile || operation == DFReadFile || operation == DFWriteFile || operation == DFChangeFileSettings) {
        if (self.communicationMode != 0 && self.communicationMode != 1 && self.communicationMode != 3)
            return @"Invalid communication mode.";
        if ((operation == DFReadFile || operation == DFWriteFile) && !self.authenticate && self.communicationMode != 0)
            return @"MAC or encrypted communication requires authentication.";
    }
    if (operation == DFReadFile || operation == DFWriteFile) {
        if (!self.length) return @"Transfer length must be in the range 1 to 65535 bytes.";
        if (operation == DFWriteFile && self.data.length != self.length)
            return @"Data length does not match the transfer length.";
    }
    if (operation == DFChangeKey) {
        if (self.changedKeyNumber > 13) return @"Key number to change must be in the range 0 to 13.";
        if (self.replacementKey.length != 16) return @"New AES key must contain exactly 16 bytes.";
        if (self.changedKeyNumber != self.authenticationKeyNumber && self.oldKey.length != 16)
            return @"Old AES key must contain exactly 16 bytes when a different key is changed.";
    }
    if (operation == DFLockReaderKeys || operation == DFUnlockReaderKeys) {
        if (self.password.length != 8) return @"Password must contain exactly 8 ASCII characters.";
        const uint8_t *bytes = self.password.bytes;
        for (NSUInteger i = 0; i < 8; i++) {
            if (bytes[i] < 0x20 || bytes[i] > 0x7E) return @"Password must contain printable ASCII characters only.";
        }
    }
    if (operation == DFSetSpeed && (self.txSpeed > 3 || self.rxSpeed > 3))
        return @"Invalid RF baud rate.";
    if (operation == DFConfigureCard && !self.randomUID && !self.disableFormatting)
        return @"Select at least one card option to activate. Activated options cannot be reset.";
    return nil;
}

- (NSString *)keyDescriptionForOperation:(DFOperation)operation showKeys:(BOOL)showKeys {
    NSString *(^keyText)(NSData *) = ^NSString *(NSData *data) {
        return showKeys ? DFHex(data.bytes, data.length, NO) : @"* hidden *";
    };
    NSString *nullDES = keyText([NSMutableData dataWithLength:8]);
    NSString *source = self.useInternalKey ? [NSString stringWithFormat:@"Key from reader in slot %u", self.readerKeyNumber] :
        [NSString stringWithFormat:@"Key %@", keyText(self.key)];
    NSString *(^role)(uint32_t, uint8_t) = ^NSString *(uint32_t aid, uint8_t number) {
        if (!aid) return @"PICC master key (key 0)";
        return [NSString stringWithFormat:@"%@ (key %u)",
            number ? @"application key" : @"application master key", number];
    };
    NSString *accessText = [NSString stringWithFormat:@"Access read %@, write %@, read and write %@, change %@",
        DFAccessName(self.readKey), DFAccessName(self.writeKey), DFAccessName(self.readWriteKey), DFAccessName(self.changeKey)];
    switch (operation) {
        case DFOpenReader: case DFCloseReader: case DFGetSpeed: case DFGetFileSize:
            return @"";
        case DFFreeMemory:
            return @"No authentication used";
        case DFStoreReaderKey:
            return [NSString stringWithFormat:@"Key %@ stored in reader slot %u", keyText(self.key), self.readerKeyNumber];
        case DFLockReaderKeys: case DFUnlockReaderKeys: {
            NSString *password = [[NSString alloc] initWithData:self.password encoding:NSASCIIStringEncoding] ?: @"";
            return [NSString stringWithFormat:@"Password %@", showKeys ? password : @"* hidden *"];
        }
        case DFSetSpeed:
            return [NSString stringWithFormat:@"Transmit rate %@, receive rate %@", DFSpeedName(self.txSpeed), DFSpeedName(self.rxSpeed)];
        case DFConvertToAES:
            return [NSString stringWithFormat:@"Authenticate with DES null key %@ as PICC master key (key 0)\nNew AES PICC master key %@",
                nullDES, keyText([NSMutableData dataWithLength:16])];
        case DFInspectMasterKey: {
            BOOL keyAvailable = self.useInternalKey || self.key.length == 16;
            BOOL nullKey = !self.useInternalKey && [self.key isEqualToData:[NSMutableData dataWithLength:16]];
            NSString *keys = !keyAvailable || nullKey ? @"AES null key" : [source stringByAppendingString:@" and the AES null key"];
            return [NSString stringWithFormat:@"No authentication used for card type, version, key settings and applications\nAuthenticate with %@ as PICC master key (key 0) to check the real UID", keys];
        }
        default:
            break;
    }
    BOOL optionalAuthentication = operation == DFCreateApplication || operation == DFCreateFile ||
        operation == DFDeleteFile || operation == DFReadFile || operation == DFWriteFile || operation == DFGetKeySettings ||
        operation == DFGetFileSettings;
    BOOL cardMaster = operation == DFCreateApplication || operation == DFDeleteApplication ||
        operation == DFFormatCard || operation == DFRandomUID || operation == DFConfigureCard;
    BOOL selectedKey = operation == DFGetUID || operation == DFReadFile || operation == DFWriteFile || operation == DFChangeKey;
    NSString *keyLine;
    if (optionalAuthentication && !self.authenticate) keyLine = @"No authentication used";
    else if (operation == DFFormatCard && self.formatKeyType == DFMasterKeyDES)
        keyLine = [NSString stringWithFormat:@"Authenticate with DES null key %@ as PICC master key (key 0)", nullDES];
    else if (operation == DFChangeFileSettings)
        keyLine = [NSString stringWithFormat:@"Authenticate with %@ for file settings", source];
    else keyLine = [NSString stringWithFormat:@"Authenticate with %@ as %@", source,
        role(cardMaster ? 0 : self.aid, selectedKey ? self.authenticationKeyNumber : 0)];
    NSMutableArray<NSString *> *lines = [NSMutableArray arrayWithObject:keyLine];
    switch (operation) {
        case DFCreateApplication:
            [lines addObject:[NSString stringWithFormat:@"Number of keys: %@", DFKeyCount(self.maximumKeys)]];
            [lines addObject:[NSString stringWithFormat:@"Key settings %@ (%02X)",
                [DESFireReader keySettingsText:self.keySettings maximumKeys:0 picc:NO], self.keySettings]];
            break;
        case DFDeleteApplication: break;
        case DFCreateFile:
            [lines addObject:[NSString stringWithFormat:@"Capacity %u bytes, communication %@",
                self.fileSize, DFCommunicationName(self.communicationMode)]];
            [lines addObject:accessText];
            break;
        case DFDeleteFile: case DFGetFileSettings:
            break;
        case DFReadFile:
            [lines addObject:[NSString stringWithFormat:@"Communication %@", DFCommunicationName(self.communicationMode)]];
            break;
        case DFWriteFile:
            [lines addObject:[NSString stringWithFormat:@"Communication %@, %lu bytes",
                DFCommunicationName(self.communicationMode), (unsigned long)self.data.length]];
            break;
        case DFGetKeySettings:
            break;
        case DFChangeKeySettings:
            [lines addObject:[NSString stringWithFormat:@"New key settings %@ (%02X)",
                [DESFireReader keySettingsText:self.keySettings maximumKeys:0 picc:!self.aid], self.keySettings]];
            break;
        case DFChangeKey:
            [lines addObject:[NSString stringWithFormat:@"New key %u %@", self.changedKeyNumber, keyText(self.replacementKey)]];
            if (self.changedKeyNumber != self.authenticationKeyNumber)
                [lines addObject:[NSString stringWithFormat:@"Old key %u %@", self.changedKeyNumber, keyText(self.oldKey)]];
            break;
        case DFConfigureCard:
            [lines addObject:[NSString stringWithFormat:@"Random UID %@, formatting %@",
                self.randomUID ? @"will be activated" : @"unchanged", self.disableFormatting ? @"will be disabled" : @"unchanged"]];
            break;
        case DFChangeFileSettings:
            [lines addObject:[NSString stringWithFormat:@"Communication %@", DFCommunicationName(self.communicationMode)]];
            [lines addObject:accessText];
            break;
        default:
            break;
    }
    return DFJoin(lines);
}
@end

@implementation DFResult
- (instancetype)init {
    if ((self = [super init])) {
        _data = [NSData data];
        _message = @"";
    }
    return self;
}
- (BOOL)success {
    return self.status == UFR_OK && (!self.hasCardStatus || self.cardStatus == CARD_OPERATION_OK);
}
- (NSString *)statusText {
    NSString *time = self.executionTime ? [NSString stringWithFormat:@", %u ms", self.executionTime] : @"";
    if (self.success)
        return [NSString stringWithFormat:@"Status OK (%u%@)", self.hasCardStatus ? self.cardStatus : 0, time];
    NSString *reader = [NSString stringWithFormat:@"Reader %@ (%u)", [DESFireReader statusName:self.status], self.status];
    // After a reader error the card status is not meaningful unless it is a real card status code.
    BOOL cardCode = self.cardStatus >= 3000 && self.cardStatus <= 3999;
    if (!self.hasCardStatus || (self.status != UFR_OK && !cardCode)) return reader;
    return [reader stringByAppendingFormat:@"\nStatus %@ (%u%@)",
        [DESFireReader statusName:self.cardStatus], self.cardStatus, time];
}
@end

@interface DESFireReader ()
@property (readwrite) BOOL connected;
@property uint32_t firmwareVersion;
@end

@implementation DESFireReader
+ (NSString *)statusName:(uint32_t)status {
    const char *text = UFR_Status2String(status);
    // The SDK returns "[0x.. (..)] NAME" in a shared buffer; copy and drop the bracket prefix.
    NSString *name = text ? [NSString stringWithUTF8String:text] : @"";
    NSRange bracket = [name rangeOfString:@"] "];
    if (bracket.location != NSNotFound) name = [name substringFromIndex:NSMaxRange(bracket)];
    name = [name stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    return name.length ? name : @"UNKNOWN_STATUS";
}

+ (NSString *)keySettingsText:(uint8_t)settings maximumKeys:(uint8_t)maximumKeys picc:(BOOL)picc {
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    [parts addObject:(settings & 0x01) ? @"master key changeable" : @"master key frozen"];
    [parts addObject:(settings & 0x02) ? @"free listing" : @"listing needs master key"];
    [parts addObject:(settings & 0x04) ? (picc ? @"free creation of applications; deletion still needs master authentication" : @"free create and delete of files") :
        (picc ? @"creation of applications needs PICC master key" : @"create and delete of files needs master key")];
    [parts addObject:(settings & 0x08) ? @"settings changeable" : @"settings frozen"];
    if (!picc) {
        uint8_t change = settings >> 4;
        [parts addObject:change == 0 ? @"keys changed with master key" : change == 0x0E ? @"keys changed with the same key" :
            change == 0x0F ? @"application keys except key 0 frozen" : [NSString stringWithFormat:@"keys changed with key %u", change]];
    }
    return [parts componentsJoinedByString:@", "];
}

+ (NSString *)cardTypeName:(uint8_t)cardType {
    switch (cardType) {
        case DL_MIFARE_DESFIRE: return @"MIFARE DESFire";
        case DL_MIFARE_DESFIRE_EV1_2K: return @"MIFARE DESFire EV1 2K";
        case DL_MIFARE_DESFIRE_EV1_4K: return @"MIFARE DESFire EV1 4K";
        case DL_MIFARE_DESFIRE_EV1_8K: return @"MIFARE DESFire EV1 8K";
        case DL_MIFARE_DESFIRE_EV2_2K: return @"MIFARE DESFire EV2 2K";
        case DL_MIFARE_DESFIRE_EV2_4K: return @"MIFARE DESFire EV2 4K";
        case DL_MIFARE_DESFIRE_EV2_8K: return @"MIFARE DESFire EV2 8K";
        case DL_MIFARE_DESFIRE_EV3_2K: return @"MIFARE DESFire EV3 2K";
        case DL_MIFARE_DESFIRE_EV3_4K: return @"MIFARE DESFire EV3 4K";
        case DL_MIFARE_DESFIRE_EV3_8K: return @"MIFARE DESFire EV3 8K";
        case DL_MIFARE_DESFIRE_LIGHT: return @"MIFARE DESFire Light";
        case DL_NTAG_413_DNA: return @"NTAG 413 DNA";
        case DL_NTAG_424_DNA: return @"NTAG 424 DNA";
        case DL_NTAG_424_DNA_TT: return @"NTAG 424 DNA TagTamper";
        case DL_MIFARE_MINI: return @"MIFARE Mini";
        case DL_MIFARE_CLASSIC_1K: return @"MIFARE Classic 1K";
        case DL_MIFARE_CLASSIC_2K: return @"MIFARE Classic 2K";
        case DL_MIFARE_CLASSIC_4K: return @"MIFARE Classic 4K";
        case DL_GENERIC_ISO14443_4: return @"Generic ISO 14443-4";
        case DL_GENERIC_ISO14443_4_TYPE_B: return @"Generic ISO 14443-4 type B";
        default:
            if ((cardType >= DL_MIFARE_PLUS_S_2K_SL0 && cardType <= DL_MIFARE_PLUS_X_4K_SL0) ||
                (cardType >= DL_MIFARE_PLUS_S_2K_SL1 && cardType <= DL_MIFARE_PLUS_SE_SL3) ||
                cardType == DL_MIFARE_PLUS_EV1_2K_SL0 || cardType == DL_MIFARE_PLUS_EV1_4K_SL0 ||
                (cardType >= DL_MIFARE_PLUS_EV2_2K_SL0 && cardType <= DL_MIFARE_PLUS_EV2_4K_SL3)) return @"MIFARE Plus";
            return @"Unknown card type";
    }
}

static NSString *DFNativeStatusName(uint16_t sw) {
    if ((sw >> 8) != 0x91) return [NSString stringWithFormat:@"SW %04X", sw];
    NSString *name;
    switch (sw & 0xFF) {
        case 0x00: name = @"OPERATION_OK"; break;
        case 0x0C: name = @"NO_CHANGES"; break;
        case 0x0E: name = @"OUT_OF_EEPROM"; break;
        case 0x1C: name = @"ILLEGAL_COMMAND"; break;
        case 0x1E: name = @"INTEGRITY_ERROR"; break;
        case 0x40: name = @"NO_SUCH_KEY"; break;
        case 0x7E: name = @"LENGTH_ERROR"; break;
        case 0x9D: name = @"PERMISSION_DENIED"; break;
        case 0x9E: name = @"PARAMETER_ERROR"; break;
        case 0xA0: name = @"APPLICATION_NOT_FOUND"; break;
        case 0xAE: name = @"AUTHENTICATION_ERROR"; break;
        case 0xBE: name = @"BOUNDARY_ERROR"; break;
        case 0xCA: name = @"COMMAND_ABORTED"; break;
        case 0xDE: name = @"DUPLICATE_ERROR"; break;
        case 0xEE: name = @"MEMORY_ERROR"; break;
        case 0xF0: name = @"FILE_NOT_FOUND"; break;
        default: name = @"UNKNOWN_STATUS"; break;
    }
    return [NSString stringWithFormat:@"%@ (SW %04X)", name, sw];
}

// Native DESFire command in ISO 7816 wrapping; continuation frames (91 AF) are collected.
static UFR_STATUS DFNative(uint8_t command, const uint8_t *data, uint32_t length, NSMutableData *response, uint16_t *sw) {
    [response setLength:0];
    uint8_t buffer[256];
    uint8_t status[2] = {0};
    for (NSUInteger frame = 0; frame < 16; frame++) {
        uint32_t received = sizeof(buffer);
        UFR_STATUS result = APDUTransceive(0x90, command, 0, 0, data, length, buffer, &received, 1, status);
        if (result != UFR_OK) return result;
        *sw = (uint16_t)(status[0] << 8 | status[1]);
        if (received > sizeof(buffer)) received = sizeof(buffer);
        [response appendBytes:buffer length:received];
        if (*sw != 0x91AF) return UFR_OK;
        command = 0xAF;
        data = NULL;
        length = 0;
    }
    return UFR_OK;
}

static UFR_STATUS DFSelectNative(uint32_t aid, uint16_t *sw) {
    uint8_t bytes[3] = {aid & 0xFF, (aid >> 8) & 0xFF, (aid >> 16) & 0xFF};
    return DFNative(0x5A, bytes, sizeof(bytes), [NSMutableData data], sw);
}

static NSString *DFApplicationList(NSData *data) {
    if (!data.length) return @"No applications";
    const uint8_t *bytes = data.bytes;
    NSMutableArray<NSString *> *aids = [NSMutableArray array];
    for (NSUInteger i = 0; i + 2 < data.length; i += 3)
        [aids addObject:[NSString stringWithFormat:@"%06X", bytes[i] | bytes[i + 1] << 8 | bytes[i + 2] << 16]];
    return [NSString stringWithFormat:@"Applications %@", [aids componentsJoinedByString:@", "]];
}

- (uint32_t)factoryConversionStatus {
    return DES_to_AES_key_type();
}

- (DFResult *)verifyFactoryAESKey {
    DFResult *result = [DFResult new];
    uint8_t key[16] = {0}, uid[192] = {0}, length = 0;
    uint16_t card = 0, time = 0;
    result.status = uFR_int_GetDesfireUid_aes_PK(key, 0, 0, uid, &length, &card, &time);
    memset_s(key, sizeof(key), 0, sizeof(key));
    result.hasCardStatus = YES;
    result.cardStatus = card;
    result.executionTime = time;
    if (result.success && length != 7 && length != 11) {
        result.status = UFR_PARAMETERS_ERROR;
        result.message = [NSString stringWithFormat:@"AES check returned an unexpected UID length of %u bytes", length];
    } else {
        result.message = [NSString stringWithFormat:@"AES null key check with protected UID read, AID 000000, Key 0\n%@",
            result.statusText];
    }
    return result;
}

- (DFResult *)convertFactoryCard {
    DFResult *result = [DFResult new];
    NSMutableArray<NSString *> *attempts = [NSMutableArray array];
    for (NSUInteger attempt = 1; attempt <= 10; attempt++) {
        result.status = [self factoryConversionStatus];
        [attempts addObject:[NSString stringWithFormat:@"Attempt %lu %@ (%u)",
            (unsigned long)attempt, [DESFireReader statusName:result.status], result.status]];
        if (result.status == UFR_OK) break;
    }
    result.message = [attempts componentsJoinedByString:@"\n"];
    if (result.success) {
        DFResult *verification = [self verifyFactoryAESKey];
        result.status = verification.status;
        result.hasCardStatus = verification.hasCardStatus;
        result.cardStatus = verification.cardStatus;
        result.executionTime = verification.executionTime;
        result.message = [result.message stringByAppendingFormat:@"\n%@\n%@", verification.message,
            verification.success ?
            @"AES null key confirmed by an authenticated read, the new card master key is 16 zero bytes" :
            [DFWarningMark stringByAppendingString:@"Conversion reported OK, but the AES check failed. The card may already be changed, do not initialize it again automatically."]];
    } else {
        result.message = [result.message stringByAppendingFormat:@"\n%@DES null key could not be converted to the AES null key after 10 attempts",
            DFWarningMark];
    }
    result.statusReported = YES;
    return result;
}

- (void)appendVersionTo:(NSMutableArray<NSString *> *)lines {
    NSMutableData *version = [NSMutableData data];
    uint16_t sw = 0;
    UFR_STATUS status = DFNative(0x60, NULL, 0, version, &sw);
    if (status != UFR_OK || sw != 0x9100 || version.length < 28) {
        [lines addObject:[NSString stringWithFormat:@"%@Version data not available, %@", DFNoteMark,
            status != UFR_OK ? [DESFireReader statusName:status] : DFNativeStatusName(sw)]];
        return;
    }
    const uint8_t *v = version.bytes;
    NSString *family;
    switch (v[3]) {
        case 0x00: family = @"MIFARE DESFire EV0"; break;
        case 0x01: family = @"MIFARE DESFire EV1"; break;
        case 0x12: family = @"MIFARE DESFire EV2"; break;
        case 0x22: family = @"MIFARE DESFire EV2 XL"; break;
        case 0x30: case 0x33: family = @"MIFARE DESFire EV3"; break;
        default: family = v[1] == 0x08 ? @"MIFARE DESFire Light" : @"Unknown DESFire family"; break;
    }
    unsigned storage = 1u << (v[5] >> 1);
    [lines addObject:[NSString stringWithFormat:@"Product %@, vendor %@, storage %@%u bytes", family,
        v[0] == 0x04 ? @"NXP" : [NSString stringWithFormat:@"%02X", v[0]], (v[5] & 1) ? @"more than " : @"", storage]];
    [lines addObject:[NSString stringWithFormat:@"Hardware version %u.%u, software version %u.%u",
        v[3], v[4], v[10], v[11]]];
    BOOL hidden = YES;
    for (NSUInteger i = 14; i < 21; i++) hidden = hidden && v[i] == 0;
    [lines addObject:hidden ? @"UID in version data hidden, random UID is active" :
        [NSString stringWithFormat:@"UID in version data 0x%@", DFHex(v + 14, 7, YES)]];
    [lines addObject:[NSString stringWithFormat:@"Batch number 0x%@, production week %02X, year 20%02X",
        DFHex(v + 21, 5, YES), v[26], v[27]]];
}

- (BOOL)appendPICCSettingsTo:(NSMutableArray<NSString *> *)lines {
    uint16_t sw = 0;
    UFR_STATUS status = DFSelectNative(0, &sw);
    if (status != UFR_OK || sw != 0x9100) {
        [lines addObject:[NSString stringWithFormat:@"%@Card level not selectable, %@", DFNoteMark,
            status != UFR_OK ? [DESFireReader statusName:status] : DFNativeStatusName(sw)]];
        return NO;
    }
    NSMutableData *response = [NSMutableData data];
    status = DFNative(0x45, NULL, 0, response, &sw);
    if (status == UFR_OK && sw == 0x9100 && response.length == 2) {
        const uint8_t *bytes = response.bytes;
        [lines addObject:[NSString stringWithFormat:@"Key settings %@ (%02X), %@",
            [DESFireReader keySettingsText:bytes[0] maximumKeys:bytes[1] picc:YES], bytes[0], DFKeyCount(bytes[1] & 0x0F)]];
    } else {
        [lines addObject:[NSString stringWithFormat:@"%@Key settings not available, %@", DFNoteMark,
            status != UFR_OK ? [DESFireReader statusName:status] : DFNativeStatusName(sw)]];
    }
    status = DFNative(0x6A, NULL, 0, response, &sw);
    if (status == UFR_OK && sw == 0x9100) {
        [lines addObject:DFApplicationList(response)];
        return YES;
    }
    [lines addObject:[NSString stringWithFormat:@"%@Application list without authentication not available, %@", DFNoteMark,
        status != UFR_OK ? [DESFireReader statusName:status] : DFNativeStatusName(sw)]];
    return NO;
}

- (void)appendAuthenticatedInfo:(DFRequest *)request listed:(BOOL)listed to:(NSMutableArray<NSString *> *)lines {
    uint8_t nullKey[16] = {0}, key[16] = {0};
    BOOL external = !request.useInternalKey && request.key.length == 16;
    if (external) [request.key getBytes:key length:16];
    BOOL primary = request.useInternalKey || (external && memcmp(key, nullKey, 16) != 0);
    for (NSUInteger attempt = primary ? 0 : 1; attempt < 2; attempt++) {
        BOOL internal = attempt == 0 && request.useInternalKey;
        uint8_t *used = attempt == 0 ? key : nullKey;
        NSString *source = internal ? [NSString stringWithFormat:@"Key from reader in slot %u", request.readerKeyNumber] :
            [NSString stringWithFormat:@"Key %@", DFHex(used, 16, NO)];
        uint8_t uid[192] = {0}, length = 0;
        uint16_t card = 0, time = 0;
        UFR_STATUS status = internal ?
            uFR_int_GetDesfireUid(request.readerKeyNumber, 0, 0, uid, &length, &card, &time) :
            uFR_int_GetDesfireUid_PK(used, 0, 0, uid, &length, &card, &time);
        if (status != UFR_OK || card != CARD_OPERATION_OK || (length != 7 && length != 11)) {
            NSString *reason = status != UFR_OK ? [DESFireReader statusName:status] : [DESFireReader statusName:card];
            [lines addObject:[NSString stringWithFormat:@"%@ not accepted as AES card master key, %@ (%u)",
                source, reason, status != UFR_OK ? status : card]];
            continue;
        }
        [lines addObject:[NSString stringWithFormat:@"%@ confirmed as AES card master key (AID 000000, Key 0)", source]];
        [lines addObject:[NSString stringWithFormat:@"Real UID 0x%@, length 7 bytes", DFHex(uid, 7, YES)]];
        if (!listed) {
            uint32_t ids[64] = {0};
            uint8_t count = 0;
            status = internal ?
                uFR_int_DesfireGetApplicationIds(request.readerKeyNumber, ids, &count, &card, &time) :
                uFR_int_DesfireGetApplicationIds_PK(used, ids, &count, &card, &time);
            if (status == UFR_OK && card == CARD_OPERATION_OK) {
                NSMutableData *list = [NSMutableData data];
                for (uint8_t i = 0; i < count && i < 64; i++) {
                    uint8_t aid[3] = {ids[i] & 0xFF, (ids[i] >> 8) & 0xFF, (ids[i] >> 16) & 0xFF};
                    [list appendBytes:aid length:3];
                }
                [lines addObject:DFApplicationList(list)];
            }
        }
        break;
    }
    memset_s(key, sizeof(key), 0, sizeof(key));
}

- (DFResult *)cardInfo:(DFRequest *)request {
    DFResult *result = [DFResult new];
    uint8_t cardType = 0;
    result.status = GetDlogicCardType(&cardType);
    if (result.status != UFR_OK) {
        result.message = @"Card type not available, place a card on the reader";
        return result;
    }
    result.cardType = cardType;
    result.hasCardType = YES;
    NSMutableArray<NSString *> *lines = [NSMutableArray arrayWithObject:
        [NSString stringWithFormat:@"Card type %@ (%02X)", [DESFireReader cardTypeName:cardType], cardType]];
    BOOL listed = NO;
    UFR_STATUS iso = SetISO14443_4_Mode();
    if (iso == UFR_OK) {
        [self appendVersionTo:lines];
        listed = [self appendPICCSettingsTo:lines];
        UFR_STATUS deselect = s_block_deselect(100);
        if (deselect != UFR_OK)
            [lines addObject:[NSString stringWithFormat:@"%@ISO 14443-4 deselect failed, %@ (%u)", DFWarningMark,
                [DESFireReader statusName:deselect], deselect]];
    } else {
        [lines addObject:[NSString stringWithFormat:@"%@ISO 14443-4 mode not available, %@ (%u)", DFNoteMark,
            [DESFireReader statusName:iso], iso]];
    }
    uint32_t memory = 0;
    uint16_t card = 0, time = 0;
    UFR_STATUS status = uFR_int_DesfireFreeMem(&memory, &card, &time);
    if (status == UFR_OK && card == CARD_OPERATION_OK) [lines addObject:[NSString stringWithFormat:@"Free memory %u bytes", memory]];
    [self appendAuthenticatedInfo:request listed:listed to:lines];
    result.message = DFJoin(lines);
    return result;
}

+ (NSData *)hexData:(NSString *)text {
    NSString *hex = [[text componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet] componentsJoinedByString:@""];
    if (hex.length % 2) return nil;
    NSMutableData *data = [NSMutableData dataWithCapacity:hex.length / 2];
    for (NSUInteger i = 0; i < hex.length; i += 2) {
        uint32_t byte;
        if (![self parseUnsigned:[hex substringWithRange:NSMakeRange(i, 2)] base:16 maximum:255 value:&byte]) return nil;
        uint8_t b = (uint8_t)byte;
        [data appendBytes:&b length:1];
    }
    return data;
}

+ (BOOL)parseUnsigned:(NSString *)text base:(NSUInteger)base maximum:(uint32_t)maximum value:(uint32_t *)value {
    if (!text.length || (base != 10 && base != 16)) return NO;
    uint32_t result = 0;
    for (NSUInteger i = 0; i < text.length; i++) {
        unichar c = [text characterAtIndex:i];
        uint32_t digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (base == 16 && c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (base == 16 && c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else return NO;
        if (digit >= base || digit > maximum || result > (maximum - digit) / base) return NO;
        result = result * (uint32_t)base + digit;
    }
    *value = result;
    return YES;
}

+ (uint8_t)keySettingsWithAuthentication:(BOOL)authentication frozenSettings:(BOOL)frozenSettings frozenMaster:(BOOL)frozenMaster {
    return (authentication ? 0x00 : 0x06) | (frozenSettings ? 0x00 : 0x08) | (frozenMaster ? 0x00 : 0x01);
}

static NSString *DFAttempt(NSString *name, UFR_STATUS status, uint16_t card) {
    if (status == UFR_OK && card == 0)
        return [name stringByAppendingString:@" not answered, the reader firmware does not send this command"];
    if (status == UFR_OK && card == 0x501)
        return [name stringByAppendingString:@" not executed by the reader firmware, status 1281"];
    NSString *text = [NSString stringWithFormat:@"%@ Reader %@ (%u)", name, [DESFireReader statusName:status], status];
    if (status == UFR_OK || (card >= 3000 && card <= 3999))
        text = [text stringByAppendingFormat:@", status %@ (%u)", [DESFireReader statusName:card], card];
    return text;
}

// Native GetFileSettings without authentication; on FILE_NOT_FOUND the existing file numbers are listed.
- (BOOL)nativeCapacity:(DFRequest *)p size:(uint32_t *)size attempts:(NSMutableArray<NSString *> *)attempts {
    UFR_STATUS status = SetISO14443_4_Mode();
    if (status != UFR_OK) {
        [attempts addObject:DFAttempt(@"Native file settings, ISO 14443-4 mode", status, 0)];
        return NO;
    }
    BOOL found = NO;
    uint16_t sw = 0;
    status = DFSelectNative(p.aid, &sw);
    if (status != UFR_OK || sw != 0x9100) {
        [attempts addObject:status != UFR_OK ? DFAttempt(@"Native select application", status, 0) :
            [NSString stringWithFormat:@"Native select application %@", DFNativeStatusName(sw)]];
    } else {
        NSMutableData *response = [NSMutableData data];
        uint8_t file = p.fileID;
        status = DFNative(0xF5, &file, 1, response, &sw);
        const uint8_t *bytes = response.bytes;
        if (status != UFR_OK) {
            [attempts addObject:DFAttempt(@"Native file settings", status, 0)];
        } else if (sw != 0x9100) {
            [attempts addObject:[NSString stringWithFormat:@"Native file settings %@", DFNativeStatusName(sw)]];
            if (sw == 0x91F0 && DFNative(0x6F, NULL, 0, response, &sw) == UFR_OK && sw == 0x9100) {
                NSMutableArray<NSString *> *files = [NSMutableArray array];
                for (NSUInteger i = 0; i < response.length; i++) [files addObject:[NSString stringWithFormat:@"%u", ((const uint8_t *)response.bytes)[i]]];
                [attempts addObject:files.count ? [NSString stringWithFormat:@"Files in AID %06X are %@", p.aid,
                    [files componentsJoinedByString:@", "]] : [NSString stringWithFormat:@"AID %06X contains no files", p.aid]];
            }
        } else if (response.length < 7) {
            [attempts addObject:[NSString stringWithFormat:@"Native file settings returned %lu bytes only", (unsigned long)response.length]];
        } else if (bytes[0] > 1) {
            [attempts addObject:[NSString stringWithFormat:@"File %u has file type %u, only standard and backup data files are supported", p.fileID, bytes[0]]];
        } else {
            *size = bytes[4] | bytes[5] << 8 | bytes[6] << 16;
            found = YES;
        }
    }
    s_block_deselect(100);
    return found;
}

static NSString *DFFileTypeName(uint8_t type) {
    NSArray<NSString *> *names = @[@"standard data file", @"backup data file", @"value file",
        @"linear record file", @"cyclic record file", @"transaction MAC file"];
    return type < names.count ? names[type] : [NSString stringWithFormat:@"file type %u", type];
}

static NSString *DFFileSettingsText(DFResult *r, int32_t lower, int32_t upper, uint32_t limited,
    uint32_t recordSize, uint32_t maxRecords, uint32_t records) {
    NSString *details;
    if (r.fileType <= 1) details = [NSString stringWithFormat:@"capacity %u bytes", r.fileSize];
    else if (r.fileType == 2) details = [NSString stringWithFormat:@"lower limit %d, upper limit %d, limited credit %u", lower, upper, limited];
    else if (r.fileType <= 4) details = [NSString stringWithFormat:@"record size %u bytes, %u of %u records", recordSize, records, maxRecords];
    else details = nil;
    NSString *type = details ? [NSString stringWithFormat:@"File type %@, %@", DFFileTypeName(r.fileType), details] :
        [@"File type " stringByAppendingString:DFFileTypeName(r.fileType)];
    return [NSString stringWithFormat:@"%@\nCommunication %@\nAccess read %@, write %@, read and write %@, change %@", type,
        DFCommunicationName(r.communicationMode), DFAccessName(r.readKey), DFAccessName(r.writeKey),
        DFAccessName(r.readWriteKey), DFAccessName(r.changeKey)];
}

- (DFResult *)fileSettings:(DFRequest *)p key:(uint8_t *)key {
    DFResult *r = [DFResult new];
    r.hasCardStatus = YES;
    uint8_t type = 0, comm = 0, rk = 0, wk = 0, rwk = 0, ck = 0, lce = 0, tmkt = 0, tmkv = 0;
    int32_t lower = 0, upper = 0;
    uint32_t size = 0, limited = 0, recordSize = 0, maxRecords = 0, records = 0;
    uint16_t card = 0, time = 0;
    // The SDK authenticates with application key 0; the API has no key-number argument.
    UFR_STATUS status = p.authenticate ? (p.useInternalKey ?
        uFR_int_DesfireGetFileSettings_aes(p.readerKeyNumber, p.aid, p.fileID, &type, &comm, &rk, &wk, &rwk, &ck, &size,
            &lower, &upper, &limited, &lce, &recordSize, &maxRecords, &records, &tmkt, &tmkv, &card, &time) :
        uFR_int_DesfireGetFileSettings_aes_PK(key, p.aid, p.fileID, &type, &comm, &rk, &wk, &rwk, &ck, &size,
            &lower, &upper, &limited, &lce, &recordSize, &maxRecords, &records, &tmkt, &tmkv, &card, &time)) :
        uFR_int_DesfireGetFileSettings_no_auth(p.aid, p.fileID, &type, &comm, &rk, &wk, &rwk, &ck, &size,
            &lower, &upper, &limited, &lce, &recordSize, &maxRecords, &records, &tmkt, &tmkv, &card, &time);
    r.status = status;
    r.cardStatus = card;
    r.executionTime = time;
    NSString *note = nil;
    if (!(status == UFR_OK && card == CARD_OPERATION_OK)) {
        NSString *sdk = DFAttempt(@"SDK file settings", status, card);
        // Native fallback without authentication, e.g. for reader firmware that does not send the command.
        NSMutableData *response = [NSMutableData data];
        uint16_t sw = 0;
        UFR_STATUS native = SetISO14443_4_Mode();
        if (native == UFR_OK) native = DFSelectNative(p.aid, &sw);
        if (native == UFR_OK && sw == 0x9100) {
            uint8_t file = p.fileID;
            native = DFNative(0xF5, &file, 1, response, &sw);
        }
        s_block_deselect(100);
        const uint8_t *b = response.bytes;
        if (native != UFR_OK || sw != 0x9100 || response.length < 7) {
            NSString *nativeText = native != UFR_OK ? DFAttempt(@"Native file settings", native, 0) :
                sw != 0x9100 ? [NSString stringWithFormat:@"Native file settings without authentication %@", DFNativeStatusName(sw)] :
                [NSString stringWithFormat:@"Native file settings returned %lu bytes only", (unsigned long)response.length];
            if (status == UFR_OK && card == 0) r.status = UFR_COMMAND_NOT_SUPPORTED;
            r.message = [NSString stringWithFormat:@"%@File settings of AID %06X, file %u could not be read\n%@\n%@",
                DFWarningMark, p.aid, p.fileID, sdk, nativeText];
            r.statusReported = YES;
            return r;
        }
        type = b[0]; comm = b[1] & 3;
        rwk = b[2] >> 4; ck = b[2] & 0x0F; rk = b[3] >> 4; wk = b[3] & 0x0F;
        if (type <= 1) size = b[4] | b[5] << 8 | b[6] << 16;
        else if (type == 2 && response.length >= 17) {
            lower = (int32_t)(b[4] | b[5] << 8 | b[6] << 16 | (uint32_t)b[7] << 24);
            upper = (int32_t)(b[8] | b[9] << 8 | b[10] << 16 | (uint32_t)b[11] << 24);
            limited = b[12] | b[13] << 8 | b[14] << 16 | (uint32_t)b[15] << 24;
        } else if ((type == 3 || type == 4) && response.length >= 13) {
            recordSize = b[4] | b[5] << 8 | b[6] << 16;
            maxRecords = b[7] | b[8] << 8 | b[9] << 16;
            records = b[10] | b[11] << 8 | b[12] << 16;
        }
        r.status = UFR_OK;
        r.cardStatus = CARD_OPERATION_OK;
        r.executionTime = 0;
        note = [NSString stringWithFormat:@"%@%@\n%@Settings read natively without authentication", DFNoteMark, sdk, DFNoteMark];
    }
    r.hasFileSettings = YES;
    r.fileType = type;
    r.communicationMode = comm;
    r.readKey = rk;
    r.writeKey = wk;
    r.readWriteKey = rwk;
    r.changeKey = ck;
    r.fileSize = size;
    r.message = DFJoin(@[DFFileSettingsText(r, lower, upper, limited, recordSize, maxRecords, records), note ?: @""]);
    return r;
}

// Determines the size with 1-byte reads; the card answers BOUNDARY_ERROR beyond the end of the file.
- (BOOL)probedCapacity:(DFRequest *)p size:(uint32_t *)size attempts:(NSMutableArray<NSString *> *)attempts {
    uint16_t offset = p.offset, length = p.length;
    BOOL found = [self probeCapacity:p size:size attempts:attempts];
    p.offset = offset;
    p.length = length;
    return found;
}

- (BOOL)probeCapacity:(DFRequest *)p size:(uint32_t *)size attempts:(NSMutableArray<NSString *> *)attempts {
    DFRequest *probe = p;
    probe.length = 1;
    __block DFResult *last = nil;
    int (^readable)(uint32_t) = ^int(uint32_t offset) {
        probe.offset = (uint16_t)offset;
        last = [self execute:DFReadFile request:probe];
        if (last.success) return 1;
        return last.status == DESFIRE_CARD_BOUNDARY_ERROR || last.cardStatus == DESFIRE_CARD_BOUNDARY_ERROR ? 0 : -1;
    };
    int state = readable(0);
    if (state != 1) {
        [attempts addObject:state == 0 ? @"Read test, the file is empty" : DFAttempt(@"Read test", last.status, last.cardStatus)];
        return NO;
    }
    uint32_t low = 1, high = 0;
    for (uint32_t offset = 1; offset <= UINT16_MAX; offset = offset * 2 > UINT16_MAX && offset < UINT16_MAX ? UINT16_MAX : offset * 2) {
        state = readable(offset);
        if (state < 0) {
            [attempts addObject:DFAttempt(@"Read test", last.status, last.cardStatus)];
            return NO;
        }
        if (!state) { high = offset; break; }
        low = offset + 1;
        if (offset == UINT16_MAX) break;
    }
    if (!high) {
        [attempts addObject:@"Read test, the file exceeds the SDK limit of 65535 bytes"];
        return NO;
    }
    while (low < high) {
        uint32_t middle = low + (high - low) / 2;
        state = readable(middle);
        if (state < 0) {
            [attempts addObject:DFAttempt(@"Read test", last.status, last.cardStatus)];
            return NO;
        }
        if (state) low = middle + 1; else high = middle;
    }
    *size = low;
    return YES;
}

- (DFResult *)fileCapacity:(DFRequest *)p key:(uint8_t *)key {
    DFResult *r = [DFResult new];
    r.hasCardStatus = YES;
    NSMutableArray<NSString *> *attempts = [NSMutableArray array];
    uint32_t size = 0;
    uint16_t card = 0, time = 0;
    // The SDK size queries authenticate key 0 implicitly, unlike file transfers.
    BOOL authenticated = p.authenticate && p.authenticationKeyNumber == 0;
    BOOL supportsSizeQueries = self.firmwareVersion >= DFFileSettingsMinimumFirmware;
    UFR_STATUS status = !supportsSizeQueries ? UFR_COMMAND_NOT_SUPPORTED : authenticated ? (p.useInternalKey ?
        uFR_int_DesfireGetStdFileSize_aes(p.readerKeyNumber, p.aid, p.fileID, &size, &card, &time) :
        uFR_int_DesfireGetStdFileSize_aes_PK(key, p.aid, p.fileID, &size, &card, &time)) :
        uFR_int_DesfireGetStdFileSize_no_auth(p.aid, p.fileID, &size, &card, &time);
    r.status = status;
    r.cardStatus = card;
    r.executionTime = time;
    if (status == UFR_OK && card == CARD_OPERATION_OK) {
        r.fileSize = size;
        r.message = [NSString stringWithFormat:@"File capacity %u bytes", size];
        return r;
    }
    [attempts addObject:supportsSizeQueries ? DFAttempt(@"Size query", status, card) :
        @"SDK size queries skipped: require reader firmware 5.0.76 or newer (connected version older or unknown)"];
    uint8_t type = 0, comm = 0, rk = 0, wk = 0, rwk = 0, ck = 0, lce = 0, tmkt = 0, tmkv = 0;
    int32_t lower = 0, upper = 0;
    uint32_t limited = 0, recordSize = 0, maxRecords = 0, records = 0;
    card = 0;
    status = !supportsSizeQueries ? UFR_COMMAND_NOT_SUPPORTED : authenticated ? (p.useInternalKey ?
        uFR_int_DesfireGetFileSettings_aes(p.readerKeyNumber, p.aid, p.fileID, &type, &comm, &rk, &wk, &rwk, &ck, &size,
            &lower, &upper, &limited, &lce, &recordSize, &maxRecords, &records, &tmkt, &tmkv, &card, &time) :
        uFR_int_DesfireGetFileSettings_aes_PK(key, p.aid, p.fileID, &type, &comm, &rk, &wk, &rwk, &ck, &size,
            &lower, &upper, &limited, &lce, &recordSize, &maxRecords, &records, &tmkt, &tmkv, &card, &time)) :
        uFR_int_DesfireGetFileSettings_no_auth(p.aid, p.fileID, &type, &comm, &rk, &wk, &rwk, &ck, &size,
            &lower, &upper, &limited, &lce, &recordSize, &maxRecords, &records, &tmkt, &tmkv, &card, &time);
    if (status == UFR_OK && card == CARD_OPERATION_OK && type <= 1) {
        r.status = UFR_OK;
        r.cardStatus = card;
        r.executionTime = time;
        r.fileSize = size;
        r.message = [NSString stringWithFormat:@"File capacity %u bytes\n%@Capacity taken from the SDK file settings", size, DFNoteMark];
        return r;
    }
    [attempts addObject:status == UFR_OK && card == CARD_OPERATION_OK ?
        [NSString stringWithFormat:@"File %u has file type %u, only standard and backup data files are supported", p.fileID, type] :
        DFAttempt(@"File settings", status, card)];
    if ([self nativeCapacity:p size:&size attempts:attempts]) {
        r.status = UFR_OK;
        r.cardStatus = CARD_OPERATION_OK;
        r.executionTime = 0;
        r.fileSize = size;
        r.message = [NSString stringWithFormat:@"File capacity %u bytes\n%@Capacity taken from native file settings", size, DFNoteMark];
        return r;
    }
    if ([self probedCapacity:p size:&size attempts:attempts]) {
        r.status = UFR_OK;
        r.cardStatus = CARD_OPERATION_OK;
        r.executionTime = 0;
        r.fileSize = size;
        r.message = [NSString stringWithFormat:@"File capacity %u bytes\n%@Capacity determined by read tests, file settings are not readable", size, DFNoteMark];
        return r;
    }
    if (r.status == UFR_OK && r.cardStatus == CARD_OPERATION_OK) r.status = UFR_PARAMETERS_ERROR;
    r.message = [NSString stringWithFormat:@"%@File capacity of AID %06X, file %u could not be determined\n%@",
        DFWarningMark, p.aid, p.fileID, [attempts componentsJoinedByString:@"\n"]];
    r.statusReported = YES;
    return r;
}

- (DFResult *)transferFile:(DFRequest *)request writing:(BOOL)writing {
    DFResult *(^failure)(NSString *) = ^DFResult *(NSString *message) {
        DFResult *result = [DFResult new];
        result.status = UFR_PARAMETERS_ERROR;
        result.message = [DFWarningMark stringByAppendingString:message];
        result.statusReported = YES;
        return result;
    };
    if (writing && (!request.data.length || request.data.length > UINT16_MAX))
        return failure(@"Select a file containing 1 to 65535 bytes, no card data was written");
    request.offset = 0;
    request.length = writing ? (uint16_t)request.data.length : 1;
    DFOperation operation = writing ? DFWriteFile : DFReadFile;
    NSString *validation = [request validationErrorForOperation:operation];
    if (validation) return failure(validation);
    DFResult *settings = [self execute:DFGetFileSize request:request];
    if (!settings.success) return settings;
    NSString *capacity = [NSString stringWithFormat:@"File capacity %u bytes", settings.fileSize];
    if (!settings.fileSize) return failure(@"The card file reports a capacity of 0 bytes, transfer cancelled");
    if (writing && request.data.length > settings.fileSize)
        return failure([NSString stringWithFormat:
            @"The selected file contains %lu bytes, but the card file holds %u bytes only, no data was written",
            (unsigned long)request.data.length, settings.fileSize]);
    if (!writing && settings.fileSize > UINT16_MAX)
        return failure(@"The card file exceeds the SDK limit of 65535 bytes per transfer, no partial dump was returned");
    if (!writing) request.length = (uint16_t)settings.fileSize;
    DFResult *result = [self execute:operation request:request];
    if (result.success && !writing && result.data.length != request.length)
        return failure(@"The reader returned an unexpected data length, no output file was saved");
    result.message = DFJoin(@[capacity, result.message]);
    return result;
}

- (NSString *)readerInfo:(NSString *)library {
    NSMutableArray<NSString *> *lines = [NSMutableArray arrayWithObject:[NSString stringWithFormat:@"Library %@ ARM64", library]];
    uint32_t type = 0;
    NSString *typeName = nil;
    const char *description = GetReaderDescription();
    if (description) {
        for (NSString *line in [[NSString stringWithUTF8String:description] componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]) {
            NSRange marker = [line rangeOfString:@"ReaderType:"];
            if (marker.location == NSNotFound) continue;
            NSArray<NSString *> *parts = [line componentsSeparatedByString:@" : "];
            if (parts.count >= 2) typeName = [parts.lastObject stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        }
    }
    if (GetReaderType(&type) == UFR_OK)
        [lines addObject:typeName.length ? [NSString stringWithFormat:@"Reader type %@, code %08X", typeName, type] :
            [NSString stringWithFormat:@"Reader type code %08X", type]];
    uint8_t serial[9] = {0};
    if (GetReaderSerialDescription(serial) == UFR_OK) {
        NSString *text = [[NSString alloc] initWithBytes:serial length:strnlen((const char *)serial, 8) encoding:NSASCIIStringEncoding];
        if (text.length) [lines addObject:[NSString stringWithFormat:@"Serial number %@", text]];
    }
    uint8_t major = 0, minor = 0, build = 0;
    if (GetReaderHardwareVersion(&major, &minor) == UFR_OK)
        [lines addObject:[NSString stringWithFormat:@"Hardware type %u, version %u", major, minor]];
    UFR_STATUS firmware = GetReaderFirmwareVersion(&major, &minor);
    if (firmware == UFR_OK) firmware = GetBuildNumber(&build);
    self.firmwareVersion = firmware == UFR_OK ? ((uint32_t)major << 16) | ((uint32_t)minor << 8) | build : 0;
    [lines addObject:firmware == UFR_OK ? [NSString stringWithFormat:@"Firmware version %u.%u.%u", major, minor, build] :
        [NSString stringWithFormat:@"%@Firmware version not available, %@ (%u)", DFNoteMark, [DESFireReader statusName:firmware], firmware]];
    return DFJoin(lines);
}

- (DFResult *)execute:(DFOperation)operation request:(DFRequest *)p {
    DFResult *r = [DFResult new];
    NSString *validation = [p validationErrorForOperation:operation];
    if (validation) {
        r.status = UFR_PARAMETERS_ERROR;
        r.message = [DFWarningMark stringByAppendingString:validation];
        r.statusReported = YES;
        return r;
    }
    if (operation != DFOpenReader && operation != DFCloseReader && !self.connected) {
        r.status = UFR_READER_PORT_NOT_OPENED;
        r.message = [DFWarningMark stringByAppendingString:@"Reader is not connected, select Connect first"];
        r.statusReported = YES;
        return r;
    }
    if (operation == DFInspectMasterKey) return [self cardInfo:p];
    if (operation == DFConvertToAES) return [self convertFactoryCard];
    uint32_t minimumFirmware = operation == DFGetFileSettings ? DFFileSettingsMinimumFirmware :
        operation == DFChangeFileSettings ? DFChangeFileSettingsMinimumFirmware : 0;
    if (minimumFirmware && self.firmwareVersion < minimumFirmware) {
        r.status = UFR_COMMAND_NOT_SUPPORTED;
        r.message = [NSString stringWithFormat:@"%@This operation requires reader firmware 5.0.%u; the connected version is older or unknown",
            DFWarningMark, minimumFirmware & 0xFF];
        r.statusReported = YES;
        return r;
    }
    uint8_t key[16] = {0}, newKey[16] = {0}, oldKey[16] = {0}, desKey[8] = {0};
    if (p.key.length == 16) [p.key getBytes:key length:16];
    if (p.replacementKey.length == 16) [p.replacementKey getBytes:newKey length:16];
    if (p.oldKey.length == 16) [p.oldKey getBytes:oldKey length:16];
    uint16_t card = 0, time = 0;
    uint32_t memory = 0;
    uint8_t settings = 0, maximumKeys = 0, uidLength = 0, uid[192] = {0}, tx = 0, rx = 0;
    NSMutableData *buffer = [NSMutableData dataWithLength:p.length];
    if (operation == DFWriteFile && p.length) memcpy(buffer.mutableBytes, p.data.bytes, p.length);
    r.hasCardStatus = (operation >= DFGetUID && operation <= DFRandomUID) ||
        operation == DFConfigureCard || operation == DFChangeFileSettings;
    if (operation == DFGetFileSettings) {
        DFResult *settings = [self fileSettings:p key:key];
        memset_s(key, sizeof(key), 0, sizeof(key));
        if (!settings.statusReported) settings.message = DFJoin(@[settings.message, settings.statusText]);
        return settings;
    }
    if (operation == DFGetFileSize) {
        DFResult *capacity = [self fileCapacity:p key:key];
        memset_s(key, sizeof(key), 0, sizeof(key));
        if (!capacity.statusReported) capacity.message = DFJoin(@[capacity.message, capacity.statusText]);
        return capacity;
    }
    // External-key and reader-key variants have identical remaining arguments.
#define AUTH_CALL(name, ...) (p.useInternalKey ? name(p.readerKeyNumber, __VA_ARGS__) : name##_PK(key, __VA_ARGS__))
    switch (operation) {
        case DFOpenReader: {
            if (self.connected) {
                r.message = @"Reader is already connected";
                r.firmwareVersion = self.firmwareVersion;
                break;
            }
            const char *version = GetDllVersionStr();
            NSString *versionString = version ? [NSString stringWithUTF8String:version] : @"";
            if (![versionString isEqualToString:@"6.0.82"]) {
                r.status = UFR_PARAMETERS_ERROR;
                r.message = [NSString stringWithFormat:@"%@Library 6.0.82 expected, loaded %@", DFWarningMark, versionString];
                r.statusReported = YES;
                break;
            }
            r.status = ReaderOpenEx(1, "", 2, NULL);
            self.connected = r.status == UFR_OK;
            if (self.connected) r.message = [self readerInfo:versionString];
            r.firmwareVersion = self.firmwareVersion;
            break;
        }
        case DFCloseReader:
            r.status = self.connected ? ReaderClose() : UFR_OK;
            if (r.status == UFR_OK) {
                self.connected = NO;
                self.firmwareVersion = 0;
                r.message = @"Reader disconnected";
            }
            break;
        case DFGetUID:
            r.status = AUTH_CALL(uFR_int_GetDesfireUid, p.aid, p.authenticationKeyNumber, uid, &uidLength, &card, &time);
            break;
        case DFFreeMemory:
            r.status = uFR_int_DesfireFreeMem(&memory, &card, &time);
            break;
        case DFCreateApplication:
            r.status = p.authenticate ? AUTH_CALL(uFR_int_DesfireCreateAesApplication, p.aid, p.keySettings, p.maximumKeys, &card, &time) :
                uFR_int_DesfireCreateAesApplication_no_auth(p.aid, p.keySettings, p.maximumKeys, &card, &time);
            break;
        case DFDeleteApplication:
            r.status = AUTH_CALL(uFR_int_DesfireDeleteApplication, p.aid, &card, &time);
            break;
        case DFCreateFile:
            r.status = p.authenticate ? AUTH_CALL(uFR_int_DesfireCreateStdDataFile, p.aid, p.fileID, p.fileSize,
                p.readKey, p.writeKey, p.readWriteKey, p.changeKey, p.communicationMode, &card, &time) :
                uFR_int_DesfireCreateStdDataFile_no_auth(p.aid, p.fileID, p.fileSize, p.readKey, p.writeKey,
                p.readWriteKey, p.changeKey, p.communicationMode, &card, &time);
            break;
        case DFDeleteFile:
            r.status = p.authenticate ? AUTH_CALL(uFR_int_DesfireDeleteFile, p.aid, p.fileID, &card, &time) :
                uFR_int_DesfireDeleteFile_no_auth(p.aid, p.fileID, &card, &time);
            break;
        case DFReadFile:
            r.status = p.authenticate ? AUTH_CALL(uFR_int_DesfireReadStdDataFile, p.aid, p.authenticationKeyNumber,
                p.fileID, p.offset, p.length, p.communicationMode, buffer.mutableBytes, &card, &time) :
                uFR_int_DesfireReadStdDataFile_no_auth(p.aid, p.authenticationKeyNumber, p.fileID, p.offset,
                p.length, p.communicationMode, buffer.mutableBytes, &card, &time);
            break;
        case DFWriteFile:
            r.status = p.authenticate ? AUTH_CALL(uFR_int_DesfireWriteStdDataFile, p.aid, p.authenticationKeyNumber,
                p.fileID, p.offset, p.length, p.communicationMode, buffer.mutableBytes, &card, &time) :
                uFR_int_DesfireWriteStdDataFile_no_auth(p.aid, p.authenticationKeyNumber, p.fileID, p.offset,
                p.length, p.communicationMode, buffer.mutableBytes, &card, &time);
            break;
        case DFGetKeySettings:
            r.status = p.authenticate ?
                AUTH_CALL(uFR_int_DesfireGetKeySettings, p.aid, &settings, &maximumKeys, &card, &time) :
                uFR_int_DesfireGetKeySettings_no_auth(p.aid, &settings, &maximumKeys, &card, &time);
            break;
        case DFChangeKeySettings:
            r.status = AUTH_CALL(uFR_int_DesfireChangeKeySettings, p.aid, p.keySettings, &card, &time);
            break;
        case DFChangeKey:
            r.status = AUTH_CALL(uFR_int_DesfireChangeAesKey, p.aid, p.authenticationKeyNumber, newKey,
                p.changedKeyNumber, oldKey, &card, &time);
            break;
        case DFFormatCard:
            r.status = p.formatKeyType == DFMasterKeyDES ?
                uFR_int_DesfireFormatCard_des_PK(desKey, &card, &time) :
                AUTH_CALL(uFR_int_DesfireFormatCard, &card, &time);
            break;
        case DFRandomUID:
            r.status = AUTH_CALL(uFR_int_DesfireSetConfiguration, 1, 0, &card, &time);
            break;
        case DFConfigureCard:
            r.status = AUTH_CALL(uFR_int_DesfireSetConfiguration, p.randomUID, p.disableFormatting, &card, &time);
            break;
        case DFChangeFileSettings:
            r.status = AUTH_CALL(uFR_int_DesfireChangeFileSettings_aes, p.aid, p.fileID,
                p.communicationMode, p.readKey, p.writeKey, p.readWriteKey, p.changeKey, &card, &time);
            break;
        case DFStoreReaderKey:
            r.status = uFR_int_DesfireWriteAesKey(p.readerKeyNumber, key);
            break;
        case DFLockReaderKeys:
            r.status = ReaderKeysLock(p.password.bytes);
            break;
        case DFUnlockReaderKeys:
            r.status = ReaderKeysUnlock(p.password.bytes);
            break;
        case DFGetSpeed:
            r.status = GetSpeedParameters(&tx, &rx);
            break;
        case DFSetSpeed:
            r.status = SetSpeedPermanently(p.txSpeed, p.rxSpeed);
            break;
        case DFConvertToAES: case DFInspectMasterKey: case DFGetFileSize: case DFGetFileSettings:
            break;
    }
#undef AUTH_CALL
    memset_s(key, sizeof(key), 0, sizeof(key));
    memset_s(newKey, sizeof(newKey), 0, sizeof(newKey));
    memset_s(oldKey, sizeof(oldKey), 0, sizeof(oldKey));
    memset_s(desKey, sizeof(desKey), 0, sizeof(desKey));
    r.cardStatus = card;
    r.executionTime = time;
    if (r.statusReported) return r;
    NSMutableArray<NSString *> *lines = [NSMutableArray arrayWithObject:r.message];
    if (r.success) {
        if (operation == DFGetUID) {
            // Legacy firmware includes four trailing bytes; the factory UID is seven bytes.
            if (uidLength != 7 && uidLength != 11) {
                r.status = UFR_PARAMETERS_ERROR;
                r.message = [NSString stringWithFormat:@"%@Unexpected UID length of %u bytes", DFWarningMark, uidLength];
                r.statusReported = YES;
                return r;
            }
            r.data = [NSData dataWithBytes:uid length:7];
            [lines addObject:[NSString stringWithFormat:@"Real UID 0x%@, length 7 bytes", DFHex(uid, 7, YES)]];
        }
        if (operation == DFReadFile) r.data = buffer;
        r.keySettings = settings;
        r.maximumKeys = maximumKeys;
        r.txSpeed = tx;
        r.rxSpeed = rx;
        if (operation == DFFreeMemory) [lines addObject:[NSString stringWithFormat:@"Free memory %u bytes", memory]];
        if (operation == DFGetKeySettings)
            [lines addObject:[NSString stringWithFormat:@"Key settings %@ (%02X), %@%@",
                [DESFireReader keySettingsText:settings maximumKeys:maximumKeys picc:!p.aid], settings,
                DFKeyCount(maximumKeys & 0x0F), (maximumKeys & 0x80) ? @", AES" : @""]];
        if (operation == DFGetSpeed)
            [lines addObject:[NSString stringWithFormat:@"Transmit rate %@, receive rate %@", DFSpeedName(tx), DFSpeedName(rx)]];
        [lines addObject:r.statusText];
    } else {
        [lines addObject:r.statusText];
        if (r.status == UFR_COMMAND_NOT_SUPPORTED)
            [lines addObject:[DFNoteMark stringByAppendingString:
                @"The reader firmware does not support this command, the installed library alone does not guarantee firmware support"]];
        if (card == WRONG_KEY_TYPE)
            [lines addObject:[DFNoteMark stringByAppendingString:
                @"WRONG_KEY_TYPE alone does not prove a wrong key value or key type, use Card info to check the card master key"]];
    }
    r.message = DFJoin(lines);
    return r;
}
@end
