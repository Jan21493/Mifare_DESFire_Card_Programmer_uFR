#import "DESFireReader.h"

NS_ASSUME_NONNULL_BEGIN

@interface DFScriptCommand : NSObject
@property DFOperation operation;
@property DFRequest *request;
@property BOOL dump;
@property BOOL ask;
@property BOOL overwrite;
@property BOOL pause;
@property NSTimeInterval seconds;
@property NSUInteger line;
@property (copy) NSString *output;
@property (copy) NSString *name;
@end

@interface DFScript : NSObject
+ (nullable NSArray<DFScriptCommand *> *)parse:(NSString *)script error:(NSString * _Nullable * _Nullable)error;
+ (NSString *)recordOperation:(DFOperation)operation request:(DFRequest *)request
    dump:(BOOL)dump output:(nullable NSURL *)output;
@end

NS_ASSUME_NONNULL_END
