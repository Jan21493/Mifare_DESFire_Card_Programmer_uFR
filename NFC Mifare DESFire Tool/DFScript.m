#import "DFScript.h"
#import <math.h>

@implementation DFScriptCommand
- (instancetype)init {
    if ((self = [super init])) {
        _request = [DFRequest new];
        _ask = YES;
        _seconds = 1;
        _output = @"";
        _name = @"";
    }
    return self;
}
@end

@implementation DFScript

+ (NSArray<NSString *> *)names {
    return @[@"ConnectReader", @"DisconnectReader", @"GetRealUID", @"GetFreeMemory",
        @"CreateApplication", @"DeleteApplication", @"CreateFile", @"DeleteFile",
        @"ReadFile", @"WriteFile", @"GetApplicationSettings", @"SetApplicationSettings",
        @"ChangeAESKey", @"FormatCard", @"EnableRandomUID", @"ConvertCardMasterKeyToAES",
        @"StoreReaderKey", @"LockReaderKeys", @"UnlockReaderKeys", @"GetRFBaudRates",
        @"SetRFBaudRates", @"GetCardInfo", @"GetFileCapacity", @"ConfigureCard", @"ChangeFileSettings", @"GetFileSettings"];
}

+ (BOOL)hasAuthentication:(DFOperation)op {
    return ![@[@(DFOpenReader), @(DFCloseReader), @(DFFreeMemory), @(DFConvertToAES),
        @(DFStoreReaderKey), @(DFLockReaderKeys), @(DFUnlockReaderKeys), @(DFGetSpeed), @(DFSetSpeed)] containsObject:@(op)];
}

+ (NSArray<NSString *> *)fields:(DFOperation)op {
    switch (op) {
        case DFGetUID: return @[@"aid", @"authKey"];
        case DFCreateApplication: return @[@"aid", @"settings", @"keys"];
        case DFDeleteApplication: return @[@"aid"];
        case DFCreateFile: return @[@"aid", @"file", @"size", @"comm", @"readKey", @"writeKey", @"readWriteKey", @"changeKey"];
        case DFDeleteFile: case DFGetFileSize: case DFGetFileSettings: return @[@"aid", @"file"];
        case DFReadFile: case DFWriteFile: return @[@"aid", @"file", @"comm", @"authKey"];
        case DFGetKeySettings: return @[@"aid"];
        case DFChangeKeySettings: return @[@"aid", @"settings"];
        case DFChangeKey: return @[@"aid", @"authKey", @"changedKey", @"newKey", @"oldKey"];
        case DFFormatCard: return @[@"keyType"];
        case DFStoreReaderKey: return @[@"slot", @"key"];
        case DFLockReaderKeys: case DFUnlockReaderKeys: return @[@"password"];
        case DFSetSpeed: return @[@"tx", @"rx"];
        case DFConfigureCard: return @[@"randomUID", @"disableFormatting"];
        case DFChangeFileSettings: return @[@"aid", @"file", @"comm", @"readKey", @"writeKey", @"readWriteKey", @"changeKey"];
        default: return @[];
    }
}

+ (NSDictionary<NSString *, NSString *> *)properties {
    return @{@"aid": @"aid", @"file": @"fileID", @"size": @"fileSize", @"authKey": @"authenticationKeyNumber",
        @"settings": @"keySettings", @"keys": @"maximumKeys", @"changedKey": @"changedKeyNumber",
        @"newKey": @"replacementKey", @"oldKey": @"oldKey", @"key": @"key", @"slot": @"readerKeyNumber",
        @"readKey": @"readKey", @"writeKey": @"writeKey", @"readWriteKey": @"readWriteKey", @"changeKey": @"changeKey",
        @"password": @"password", @"tx": @"txSpeed", @"rx": @"rxSpeed",
        @"randomUID": @"randomUID", @"disableFormatting": @"disableFormatting"};
}

+ (NSString *)quote:(NSString *)s {
    s = [s stringByReplacingOccurrencesOfString:@"\\" withString:@"\\\\"];
    return [NSString stringWithFormat:@"\"%@\"", [s stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""]];
}

+ (NSString *)hex:(NSData *)data {
    NSMutableString *s = [NSMutableString string];
    const uint8_t *b = data.bytes;
    for (NSUInteger i = 0; i < data.length; i++) [s appendFormat:@"%02X", b[i]];
    return s;
}

+ (NSString *)recordOperation:(DFOperation)op request:(DFRequest *)p dump:(BOOL)dump output:(NSURL *)output {
    NSMutableArray<NSString *> *parts = [NSMutableArray arrayWithObject:dump ? @"DumpFile" : [self names][op]];
    for (NSString *field in [self fields:op]) {
        if ([field isEqual:@"oldKey"] && p.changedKeyNumber == p.authenticationKeyNumber) continue;
        NSString *value;
        if ([field isEqual:@"comm"]) value = p.communicationMode == 0 ? @"plain" : p.communicationMode == 1 ? @"mac" : @"enciphered";
        else if ([field isEqual:@"keyType"]) value = p.formatKeyType == DFMasterKeyDES ? @"des" : @"aes";
        else {
            id v = [p valueForKey:[self properties][field]];
            if ([v isKindOfClass:NSData.class])
                value = [field isEqual:@"password"] ? [self quote:[[NSString alloc] initWithData:v encoding:NSASCIIStringEncoding]] : [self hex:v];
            else if ([field isEqual:@"aid"]) value = [NSString stringWithFormat:@"%06X", [v unsignedIntValue]];
            else if ([field isEqual:@"settings"]) value = [NSString stringWithFormat:@"%02X", [v unsignedIntValue]];
            else if ([field isEqual:@"randomUID"] || [field isEqual:@"disableFormatting"]) value = [v boolValue] ? @"yes" : @"no";
            else value = [v description];
        }
        [parts addObject:[NSString stringWithFormat:@"%@=%@", field, value]];
    }
    if ([self hasAuthentication:op]) {
        BOOL auth = p.authenticate;
        [parts addObject:[@"auth=" stringByAppendingString:auth ? (p.useInternalKey ? @"reader" : @"aes") : @"none"]];
        if (auth) [parts addObject:p.useInternalKey ? [NSString stringWithFormat:@"slot=%u", p.readerKeyNumber] :
            [@"key=" stringByAppendingString:[self hex:p.key]]];
    }
    if (op == DFWriteFile) {
        const uint8_t *b = p.data.bytes;
        for (NSUInteger i = 0; i < p.data.length;) {
            NSUInteger start = i;
            BOOL text = b[i] >= 0x20 && b[i] <= 0x7E;
            while (i < p.data.length && (b[i] >= 0x20 && b[i] <= 0x7E) == text) i++;
            NSData *segment = [p.data subdataWithRange:NSMakeRange(start, i - start)];
            [parts addObject:text ? [@"text=" stringByAppendingString:[self quote:[[NSString alloc] initWithData:segment encoding:NSASCIIStringEncoding]]] :
                [@"data=" stringByAppendingString:[self hex:segment]]];
        }
        [parts addObject:@"offset=0"];
    }
    if (op == DFReadFile && !dump) {
        [parts addObject:[@"output=" stringByAppendingString:[self quote:output.path ?: @""]]];
        [parts addObject:@"overwrite=no"];
    }
    if ([@[@(DFCreateApplication), @(DFDeleteApplication), @(DFCreateFile), @(DFDeleteFile), @(DFWriteFile),
        @(DFChangeKeySettings), @(DFChangeKey), @(DFFormatCard), @(DFRandomUID), @(DFConvertToAES),
        @(DFStoreReaderKey), @(DFLockReaderKeys), @(DFUnlockReaderKeys), @(DFSetSpeed),
        @(DFConfigureCard), @(DFChangeFileSettings)] containsObject:@(op)]) [parts addObject:@"ask=yes"];
    return [parts componentsJoinedByString:@" "];
}

// Keep repeated text/data tokens ordered; dictionaries alone would lose write segments.
+ (nullable NSArray<NSArray<NSString *> *> *)tokens:(NSString *)line {
    NSMutableArray *tokens = [NSMutableArray array];
    NSUInteger i = 0;
    NSCharacterSet *space = NSCharacterSet.whitespaceCharacterSet;
    while (i < line.length) {
        while (i < line.length && [space characterIsMember:[line characterAtIndex:i]]) i++;
        if (i == line.length || [line characterAtIndex:i] == '#') break;
        NSUInteger start = i;
        while (i < line.length && ![space characterIsMember:[line characterAtIndex:i]] && [line characterAtIndex:i] != '=') i++;
        NSString *name = [line substringWithRange:NSMakeRange(start, i - start)];
        if (!tokens.count) {
            if (!name.length || (i < line.length && [line characterAtIndex:i] == '=')) return nil;
            [tokens addObject:@[name, @""]];
            continue;
        }
        if (!name.length || i == line.length || [line characterAtIndex:i++] != '=') return nil;
        NSMutableString *value = [NSMutableString string];
        if (i < line.length && [line characterAtIndex:i] == '"') {
            i++;
            BOOL closed = NO;
            while (i < line.length) {
                unichar c = [line characterAtIndex:i++];
                if (c == '"') { closed = YES; break; }
                if (c == '\\') {
                    if (i == line.length) return nil;
                    c = [line characterAtIndex:i++];
                    if (c != '"' && c != '\\') return nil;
                }
                [value appendFormat:@"%C", c];
            }
            if (!closed || (i < line.length && ![space characterIsMember:[line characterAtIndex:i]])) return nil;
        } else {
            start = i;
            while (i < line.length && ![space characterIsMember:[line characterAtIndex:i]]) i++;
            [value appendString:[line substringWithRange:NSMakeRange(start, i - start)]];
        }
        [tokens addObject:@[name, value]];
    }
    return tokens;
}

+ (NSString *)fillCommand:(DFScriptCommand *)c tokens:(NSArray<NSArray<NSString *> *> *)tokens {
    if (c.pause) {
        if (tokens.count > 1) return @"Pause accepts only one optional sec parameter";
        if (tokens.count) {
            NSArray<NSString *> *token = tokens.firstObject;
            if (![token[0] isEqual:@"sec"]) return [@"Unknown parameter " stringByAppendingString:token[0]];
            NSString *value = token[1];
            NSScanner *scanner = [NSScanner scannerWithString:value];
            scanner.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
            scanner.charactersToBeSkipped = nil;
            double seconds = 0;
            if (!value.length || [value rangeOfCharacterFromSet:
                [NSCharacterSet characterSetWithCharactersInString:@"0123456789."].invertedSet].location != NSNotFound ||
                ![scanner scanDouble:&seconds] || !scanner.isAtEnd || !isfinite(seconds) || seconds < 0)
                return @"sec must be a nonnegative number of seconds";
            c.seconds = seconds;
        }
        return nil;
    }
    DFOperation op = c.operation;
    DFRequest *p = c.request;
    NSMutableSet *allowed = [NSMutableSet setWithArray:[self fields:op]];
    [allowed addObject:@"ask"];
    if ([self hasAuthentication:op]) [allowed addObjectsFromArray:@[@"auth", @"slot", @"key"]];
    if (op == DFReadFile && !c.dump) [allowed addObjectsFromArray:@[@"output", @"overwrite"]];
    if (op == DFWriteFile) [allowed addObjectsFromArray:@[@"offset", @"size", @"text", @"data"]];
    if (op == DFCreateFile) [allowed addObject:@"type"];
    NSMutableDictionary<NSString *, NSString *> *values = [NSMutableDictionary dictionary];
    NSMutableData *data = [NSMutableData data];
    for (NSArray<NSString *> *token in tokens) {
        NSString *k = token[0], *v = token[1];
        if (![allowed containsObject:k]) return [@"Unknown parameter " stringByAppendingString:k];
        if (values[k] && ![k isEqual:@"text"] && ![k isEqual:@"data"]) return [@"Duplicate parameter " stringByAppendingString:k];
        values[k] = v;
        if ([k isEqual:@"text"]) {
            for (NSUInteger i = 0; i < v.length; i++) if ([v characterAtIndex:i] < 0x20 || [v characterAtIndex:i] > 0x7E)
                return @"text must contain printable ASCII only; use data for other bytes";
            [data appendData:[v dataUsingEncoding:NSASCIIStringEncoding]];
        } else if ([k isEqual:@"data"]) {
            NSData *segment = [DESFireReader hexData:v];
            if (!segment || !v.length) return @"data must contain complete hexadecimal bytes";
            [data appendData:segment];
        }
        if (data.length > UINT16_MAX) return @"Write data exceeds 65535 bytes";
    }
    for (NSString *required in [self fields:op]) {
        if ([required isEqual:@"oldKey"]) continue;
        if (!values[required]) return [@"Missing parameter " stringByAppendingString:required];
    }
    if (values[@"type"] && ![values[@"type"] isEqual:@"standard"]) return @"Only type=standard can be created";
    for (NSString *k in values) {
        NSString *v = values[k];
        NSString *property = [self properties][k];
        if ([k isEqual:@"size"] && op == DFWriteFile) continue;
        if ([k isEqual:@"key"] || [k isEqual:@"newKey"] || [k isEqual:@"oldKey"]) {
            NSData *key = [DESFireReader hexData:v];
            if (key.length != 16) return [k stringByAppendingString:@" must contain 16 hexadecimal bytes"];
            [p setValue:key forKey:property];
        } else if ([k isEqual:@"password"]) {
            NSData *password = [v dataUsingEncoding:NSASCIIStringEncoding];
            if (!password) return @"Password must be ASCII";
            p.password = password;
        } else if ([k isEqual:@"comm"]) {
            NSUInteger index = [@[@"plain", @"mac", @"enciphered"] indexOfObject:v];
            if (index == NSNotFound) return @"comm must be plain, mac or enciphered";
            p.communicationMode = index == 2 ? 3 : (uint8_t)index;
        } else if ([k isEqual:@"keyType"]) {
            if (![@[@"aes", @"des"] containsObject:v]) return @"keyType must be aes or des";
            p.formatKeyType = [v isEqual:@"des"] ? DFMasterKeyDES : DFMasterKeyAES;
        } else if ([@[@"ask", @"overwrite", @"randomUID", @"disableFormatting"] containsObject:k]) {
            if (![@[@"yes", @"no"] containsObject:v]) return [k stringByAppendingString:@" must be yes or no"];
            BOOL yes = [v isEqual:@"yes"];
            if ([k isEqual:@"ask"]) c.ask = yes;
            else if ([k isEqual:@"overwrite"]) c.overwrite = yes;
            else [p setValue:@(yes) forKey:property];
        } else if (property || [k isEqual:@"offset"]) {
            uint32_t number = 0;
            uint32_t max = [k isEqual:@"aid"] || [k isEqual:@"size"] ? 0xFFFFFF : 255;
            if ([k isEqual:@"slot"]) max = 15;
            if ([k isEqual:@"authKey"] || [k isEqual:@"changedKey"]) max = 13;
            if ([k isEqual:@"offset"]) max = 0;
            if (![DESFireReader parseUnsigned:v base:([k isEqual:@"aid"] || [k isEqual:@"settings"]) ? 16 : 10 maximum:max value:&number])
                return [@"Invalid value for " stringByAppendingString:k];
            if (property) [p setValue:@(number) forKey:property];
        }
    }
    if ([self hasAuthentication:op]) {
        NSString *auth = values[@"auth"];
        if (!auth || ![@[@"none", @"reader", @"aes"] containsObject:auth]) return @"auth must be none, reader or aes";
        p.authenticate = ![auth isEqual:@"none"];
        p.useInternalKey = [auth isEqual:@"reader"];
        if (p.useInternalKey && (!values[@"slot"] || values[@"key"])) return @"Reader authentication requires slot and no key";
        if ([auth isEqual:@"aes"] && (!values[@"key"] || values[@"slot"])) return @"AES authentication requires key and no slot";
        if (!p.authenticate && (values[@"key"] || values[@"slot"])) return @"No authentication cannot specify key or slot";
    }
    if (op == DFReadFile) {
        p.length = 1;
        if (!c.dump) {
            c.output = values[@"output"] ?: @"";
            if (![c.output hasPrefix:@"/"] || [c.output rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location != NSNotFound)
                return @"output must be an absolute file path without control characters";
        }
    }
    if (op == DFWriteFile) {
        if (!data.length) return @"Write requires nonempty text or data";
        if (values[@"size"]) {
            uint32_t size;
            if (![DESFireReader parseUnsigned:values[@"size"] base:10 maximum:UINT16_MAX value:&size] || size < data.length)
                return @"size must be at least the combined data length and at most 65535";
            [data setLength:size];
        }
        p.data = data;
        p.length = (uint16_t)data.length;
    }
    return [p validationErrorForOperation:op];
}

+ (NSArray<DFScriptCommand *> *)parse:(NSString *)script error:(NSString **)error {
    NSMutableArray *commands = [NSMutableArray array];
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    [script enumerateLinesUsingBlock:^(NSString *line, BOOL *stop) { [lines addObject:line]; }];
    for (NSUInteger i = 0; i < lines.count; i++) {
        NSArray *tokens = [self tokens:lines[i]];
        NSString *problem = nil;
        if (!tokens) problem = @"Invalid syntax or quoted string";
        else if (!tokens.count) continue;
        DFScriptCommand *c = [DFScriptCommand new];
        c.line = i + 1;
        c.name = tokens.count ? tokens[0][0] : @"";
        c.dump = [c.name isEqual:@"DumpFile"];
        c.pause = [c.name isEqual:@"Pause"];
        NSUInteger op = c.pause ? DFOpenReader : c.dump ? DFReadFile : [[self names] indexOfObject:c.name];
        if (!problem && op == NSNotFound) problem = [@"Unknown command " stringByAppendingString:c.name];
        if (!problem) {
            c.operation = (DFOperation)op;
            problem = [self fillCommand:c tokens:[tokens subarrayWithRange:NSMakeRange(1, tokens.count - 1)]];
        }
        if (problem) {
            if (error) *error = [NSString stringWithFormat:@"Line %lu - %@", (unsigned long)c.line, problem];
            return nil;
        }
        [commands addObject:c];
    }
    if (!commands.count) {
        if (error) *error = @"Script contains no commands";
        return nil;
    }
    return commands;
}
@end
