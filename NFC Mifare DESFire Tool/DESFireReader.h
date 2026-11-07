#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Output-line marks: command, input parameter, reader output, application note, problem.
FOUNDATION_EXPORT NSString *const DFCommandMark;
FOUNDATION_EXPORT NSString *const DFInputMark;
FOUNDATION_EXPORT NSString *const DFOutputMark;
FOUNDATION_EXPORT NSString *const DFNoteMark;
FOUNDATION_EXPORT NSString *const DFWarningMark;
// Prefixes every nonempty line that does not already carry one of the marks above.
FOUNDATION_EXPORT NSString *DFMarkLines(NSString *text, NSString *mark);

typedef NS_ENUM(NSInteger, DFOperation) {
    DFOpenReader, DFCloseReader, DFGetUID, DFFreeMemory,
    DFCreateApplication, DFDeleteApplication, DFCreateFile, DFDeleteFile,
    DFReadFile, DFWriteFile, DFGetKeySettings, DFChangeKeySettings,
    DFChangeKey, DFFormatCard, DFRandomUID, DFConvertToAES,
    DFStoreReaderKey, DFLockReaderKeys, DFUnlockReaderKeys,
    DFGetSpeed, DFSetSpeed, DFInspectMasterKey, DFGetFileSize,
    DFConfigureCard, DFChangeFileSettings, DFGetFileSettings
};

typedef NS_ENUM(uint8_t, DFMasterKeyType) {
    DFMasterKeyAES, DFMasterKeyDES
};

@interface DFRequest : NSObject
@property uint32_t aid;
@property uint8_t authenticationKeyNumber;
@property BOOL authenticate;
@property BOOL useInternalKey;
@property uint8_t readerKeyNumber;
@property (copy) NSData *key;
@property (copy) NSData *replacementKey;
@property (copy) NSData *oldKey;
@property DFMasterKeyType formatKeyType;
@property uint8_t changedKeyNumber;
@property uint8_t keySettings;
@property uint8_t maximumKeys;
@property uint8_t fileID;
@property uint32_t fileSize;
@property uint16_t offset;
@property uint16_t length;
@property uint8_t communicationMode;
@property uint8_t readKey;
@property uint8_t writeKey;
@property uint8_t readWriteKey;
@property uint8_t changeKey;
@property (copy) NSData *data;
@property (copy) NSData *password;
@property uint8_t txSpeed;
@property uint8_t rxSpeed;
@property BOOL randomUID;
@property BOOL disableFormatting;
- (nullable NSString *)validationErrorForOperation:(DFOperation)operation;
- (NSString *)keyDescriptionForOperation:(DFOperation)operation showKeys:(BOOL)showKeys;
@end

static const uint32_t DFFileSettingsMinimumFirmware = (5u << 16) | 76u;
static const uint32_t DFChangeFileSettingsMinimumFirmware = (5u << 16) | 81u;

@interface DFResult : NSObject
// Packed major.minor.build; zero means the complete version could not be read.
@property uint32_t firmwareVersion;
@property uint32_t status;
@property uint16_t cardStatus;
@property uint16_t executionTime;
@property BOOL hasCardStatus;
@property (copy) NSString *message;
@property (copy) NSData *data;
@property uint8_t keySettings;
@property uint8_t maximumKeys;
@property uint8_t txSpeed;
@property uint8_t rxSpeed;
@property uint32_t fileSize;
@property BOOL hasFileSettings;
@property uint8_t fileType;
@property uint8_t communicationMode;
@property uint8_t readKey;
@property uint8_t writeKey;
@property uint8_t readWriteKey;
@property uint8_t changeKey;
@property uint8_t cardType;
@property BOOL hasCardType;
// YES when the message already describes the status, so no status lines are appended.
@property BOOL statusReported;
@property (readonly) BOOL success;
- (NSString *)statusText;
@end

// Call only on one serial queue: the SDK's single-reader API is not reentrant.
@interface DESFireReader : NSObject
@property (readonly) BOOL connected;
- (DFResult *)execute:(DFOperation)operation request:(DFRequest *)request;
- (DFResult *)transferFile:(DFRequest *)request writing:(BOOL)writing;
+ (nullable NSData *)hexData:(NSString *)text;
+ (BOOL)parseUnsigned:(NSString *)text base:(NSUInteger)base maximum:(uint32_t)maximum value:(uint32_t *)value;
+ (NSString *)statusName:(uint32_t)status;
+ (NSString *)keySettingsText:(uint8_t)settings maximumKeys:(uint8_t)maximumKeys picc:(BOOL)picc;
+ (NSString *)cardTypeName:(uint8_t)cardType;
+ (uint8_t)keySettingsWithAuthentication:(BOOL)authentication frozenSettings:(BOOL)frozenSettings frozenMaster:(BOOL)frozenMaster;
@end

NS_ASSUME_NONNULL_END
