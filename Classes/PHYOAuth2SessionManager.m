// PHYOAuth2SessionManager.m
//
// Copyright (c) 2014 Phyre Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "PHYOAuth2SessionManager.h"
#import <CocoaLumberjack/DDLog.h>

static const int ddLogLevel = LOG_LEVEL_VERBOSE;

NSString * const kPHYOAuthCodeGrantType                 = @"authorization_code";
NSString * const kPHYOAuthClientCredentialsGrantType    = @"client_credentials";
NSString * const kPHYOAuthPasswordCredentialsGrantType  = @"password";
NSString * const kPHYOAuthRefreshGrantType              = @"refresh_token";

#ifdef _SECURITY_SECITEM_H_
NSString * const kAFOAuth2CredentialServiceName = @"AFOAuthCredentialService";

static NSMutableDictionary * AFKeychainQueryDictionaryWithIdentifier(NSString *identifier) {
    NSMutableDictionary *queryDictionary = [NSMutableDictionary dictionaryWithObjectsAndKeys:(__bridge id)kSecClassGenericPassword, kSecClass, kAFOAuth2CredentialServiceName, kSecAttrService, nil];
    [queryDictionary setValue:identifier forKey:(__bridge id)kSecAttrAccount];
    
    return queryDictionary;
}
#endif

#pragma mark -

@interface PHYOAuth2SessionManager ()

@property (readwrite, nonatomic) NSString *serviceProviderIdentifier;
@property (readwrite, nonatomic) NSString *clientID;
@property (readwrite, nonatomic) NSString *secret;

@end

@implementation PHYOAuth2SessionManager

#pragma mark - Initialization

+ (instancetype)managerWithBaseURL:(NSURL *)url
                          clientID:(NSString *)clientID
                            secret:(NSString *)secret
{
    return [[self alloc] initWithBaseURL:url clientID:clientID secret:secret];
}

- (id)initWithBaseURL:(NSURL *)url
             clientID:(NSString *)clientID
               secret:(NSString *)secret
{
    NSParameterAssert(clientID);
    
    self = [super initWithBaseURL:url];
	if (self) {
        self.serviceProviderIdentifier = [self.baseURL host];
        self.clientID = clientID;
        self.secret = secret;
        
        self.requestSerializer = [AFJSONRequestSerializer serializer];
        self.responseSerializer = [AFJSONResponseSerializer serializer];
	}
	return self;
}


#pragma mark - Authentication

- (NSURLSessionDataTask *)authenticateUsingOAuthWithURLString:(NSString *)URLString
                                                     username:(NSString *)username
                                                     password:(NSString *)password
                                                        scope:(NSString *)scope
                                                      success:(void (^)(NSURLSessionDataTask *task, PHYOAuthCredential *credential))success
                                                      failure:(void (^)(NSURLSessionDataTask *task, NSError *error))failure
{
    return [self authenticateUsingOAuthWithURLString:URLString
                                          parameters:@{
                                                       @"grant_type": kPHYOAuthPasswordCredentialsGrantType,
                                                       @"username": username,
                                                       @"password": password,
                                                       @"scope": scope
                                                       }
                                             success:success
                                             failure:failure];
}

- (NSURLSessionDataTask *)authenticateUsingOAuthWithURLString:(NSString *)URLString
                                                        scope:(NSString *)scope
                                                      success:(void (^)(NSURLSessionDataTask *task, PHYOAuthCredential *credential))success
                                                      failure:(void (^)(NSURLSessionDataTask *task, NSError *error))failure
{
    return [self authenticateUsingOAuthWithURLString:URLString
                                          parameters:@{
                                                       @"grant_type": kPHYOAuthPasswordCredentialsGrantType,
                                                       @"scope": scope
                                                       }
                                             success:success
                                             failure:failure];
}

- (NSURLSessionDataTask *)authenticateUsingOAuthWithURLString:(NSString *)URLString
                                                 refreshToken:(NSString *)refreshToken
                                                      success:(void (^)(NSURLSessionDataTask *task, PHYOAuthCredential *credential))success
                                                      failure:(void (^)(NSURLSessionDataTask *task, NSError *error))failure
{
    return [self authenticateUsingOAuthWithURLString:URLString
                                          parameters:@{
                                                       @"grant_type": kPHYOAuthPasswordCredentialsGrantType,
                                                       @"refresh_token": refreshToken
                                                       }
                                             success:success
                                             failure:failure];
}

- (NSURLSessionDataTask *)authenticateUsingOAuthWithURLString:(NSString *)URLString
                                                         code:(NSString *)code
                                                  redirectURI:(NSString *)uri
                                                      success:(void (^)(NSURLSessionDataTask *task, PHYOAuthCredential *credential))success
                                                      failure:(void (^)(NSURLSessionDataTask *task, NSError *error))failure
{
    return [self authenticateUsingOAuthWithURLString:URLString
                                          parameters:@{
                                                       @"grant_type": kPHYOAuthPasswordCredentialsGrantType,
                                                       @"code": code,
                                                       @"redirect_uri": uri
                                                       }
                                             success:success
                                             failure:failure];
}

- (NSURLSessionDataTask *)authenticateUsingOAuthWithURLString:(NSString *)URLString
                                                   parameters:(NSDictionary *)parameters
                                                      success:(void (^)(NSURLSessionDataTask *task, PHYOAuthCredential *credential))success
                                                      failure:(void (^)(NSURLSessionDataTask *task, NSError *error))failure
{
    NSMutableDictionary *modifiedParameters = [NSMutableDictionary dictionaryWithDictionary:parameters];
    [modifiedParameters addEntriesFromDictionary:@{
                                                   @"client_id": self.clientID,
                                                   @"client_secret": self.secret
                                                   }];
    
    return [self POST:URLString parameters:modifiedParameters success:^(NSURLSessionDataTask *task, id JSON) {
        if (JSON[@"error"]) {
            DDLogError(@"[OAuth2] Failed to authenticate URL (%@). Response: %@", URLString, JSON[@"error"]);
            
            if (failure) {
                // TODO: Resolve the `error` field into a proper NSError object
                // http://tools.ietf.org/html/rfc6749#section-5.2
                failure(task, nil);
            }
            
            return;
        }
        
        NSString *refreshToken = JSON[@"refresh_token"];
        if (refreshToken == nil || [refreshToken isEqual:[NSNull null]]) {
            refreshToken = parameters[@"refresh_token"];
        }
        
        PHYOAuthCredential *credential = [PHYOAuthCredential credentialWithOAuthToken:JSON[@"access_token"]
                                                                          tokenType:JSON[@"token_type"]];
        
        NSDate *expireDate = [NSDate distantFuture];
        id expiresIn = JSON[@"expires_in"];
        if (expiresIn != nil && ![expiresIn isEqual:[NSNull null]]) {
            expireDate = [NSDate dateWithTimeIntervalSinceNow:[expiresIn doubleValue]];
        }
        
        [credential setRefreshToken:refreshToken expiration:expireDate];
        
        [self.requestSerializer phy_setAuthorizationHeaderFieldWithOAuthCredential:credential];
        
        if (success) {
            success(task, credential);
        }
    } failure:^(NSURLSessionDataTask *task, NSError *error) {
        DDLogError(@"[OAuth2] Failed to authenticate URL (%@). Error: %@", URLString, error);
        
        if (failure) {
            failure(task, error);
        }
    }];
}

@end



#pragma mark - AFOAuthCredential

@interface PHYOAuthCredential ()

@property (nonatomic, copy) NSString *accessToken;
@property (nonatomic, copy) NSString *tokenType;
@property (nonatomic, copy) NSString *refreshToken;
@property (nonatomic, strong) NSDate *expiration;

@end

@implementation PHYOAuthCredential

#pragma mark - Initialization

+ (instancetype)credentialWithOAuthToken:(NSString *)token tokenType:(NSString *)type
{
    return [[self alloc] initWithOAuthToken:token tokenType:type];
}

- (id)initWithOAuthToken:(NSString *)token tokenType:(NSString *)type
{
    self = [super init];
    if (!self) {
        return nil;
    }
    
    self.accessToken = token;
    self.tokenType = type;
    
    return self;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"<%@ accessToken:\"%@\" tokenType:\"%@\" refreshToken:\"%@\" expiration:\"%@\">", [self class], self.accessToken, self.tokenType, self.refreshToken, self.expiration];
}

- (void)setRefreshToken:(NSString *)refreshToken expiration:(NSDate *)expiration
{
    NSParameterAssert(expiration);
    
    self.refreshToken = refreshToken;
    self.expiration = expiration;
}

- (BOOL)isExpired
{
    return [self.expiration compare:[NSDate date]] == NSOrderedAscending;
}

#pragma mark Keychain

+ (BOOL)storeCredential:(PHYOAuthCredential *)credential withIdentifier:(NSString *)identifier
{
    return [[self class] storeCredential:credential withIdentifier:identifier withAccessibility:kSecAttrAccessibleAfterFirstUnlock];
}

+ (BOOL)storeCredential:(PHYOAuthCredential *)credential
         withIdentifier:(NSString *)identifier
      withAccessibility:(CFTypeRef)securityAccessibility
{
    NSMutableDictionary *queryDictionary = AFKeychainQueryDictionaryWithIdentifier(identifier);
    
    if (!credential) {
        return [self deleteCredentialWithIdentifier:identifier];
    }
    
    NSMutableDictionary *updateDictionary = [NSMutableDictionary dictionary];
    NSData *data = [NSKeyedArchiver archivedDataWithRootObject:credential];
    [updateDictionary setObject:data forKey:(__bridge id)kSecValueData];
    
    if( securityAccessibility )
        [updateDictionary setObject:(__bridge id)securityAccessibility forKey:(__bridge id)kSecAttrAccessible];
    
    OSStatus status;
    BOOL exists = ([self retrieveCredentialWithIdentifier:identifier] != nil);
    
    if (exists) {
        status = SecItemUpdate((__bridge CFDictionaryRef)queryDictionary, (__bridge CFDictionaryRef)updateDictionary);
    } else {
        [queryDictionary addEntriesFromDictionary:updateDictionary];
        status = SecItemAdd((__bridge CFDictionaryRef)queryDictionary, NULL);
    }
    
    if (status != errSecSuccess) {
        DDLogError(@"Unable to %@ credential with identifier \"%@\" (Error %li)", exists ? @"update" : @"add", identifier, (long int)status);
    }
    
    return (status == errSecSuccess);
}

+ (BOOL)deleteCredentialWithIdentifier:(NSString *)identifier
{
    NSMutableDictionary *queryDictionary = AFKeychainQueryDictionaryWithIdentifier(identifier);
    
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)queryDictionary);
    
    if (status != errSecSuccess) {
        DDLogError(@"Unable to delete credential with identifier \"%@\" (Error %li)", identifier, (long int)status);
    }
    
    return (status == errSecSuccess);
}

+ (PHYOAuthCredential *)retrieveCredentialWithIdentifier:(NSString *)identifier
{
    NSMutableDictionary *queryDictionary = AFKeychainQueryDictionaryWithIdentifier(identifier);
    [queryDictionary setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnData];
    [queryDictionary setObject:(__bridge id)kSecMatchLimitOne forKey:(__bridge id)kSecMatchLimit];
    
    CFDataRef result = nil;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)queryDictionary, (CFTypeRef *)&result);
    
    if (status != errSecSuccess) {
        DDLogError(@"Unable to fetch credential with identifier \"%@\" (Error %li)", identifier, (long int)status);
        return nil;
    }
    
    NSData *data = (__bridge_transfer NSData *)result;
    PHYOAuthCredential *credential = [NSKeyedUnarchiver unarchiveObjectWithData:data];
    
    return credential;
}

#pragma mark - NSCoding

- (id)initWithCoder:(NSCoder *)decoder
{
    self = [super init];
    
    self.accessToken = [decoder decodeObjectForKey:@"accessToken"];
    self.tokenType = [decoder decodeObjectForKey:@"tokenType"];
    self.refreshToken = [decoder decodeObjectForKey:@"refreshToken"];
    self.expiration = [decoder decodeObjectForKey:@"expiration"];
    
    return self;
}

- (void)encodeWithCoder:(NSCoder *)encoder
{
    [encoder encodeObject:self.accessToken forKey:@"accessToken"];
    [encoder encodeObject:self.tokenType forKey:@"tokenType"];
    [encoder encodeObject:self.refreshToken forKey:@"refreshToken"];
    [encoder encodeObject:self.expiration forKey:@"expiration"];
}

@end



#pragma mark - AFHTTPRequestSerializer (PHYOAuth)

@implementation AFHTTPRequestSerializer (PHYOAuth)

#pragma mark - Authorization

- (void)phy_setAuthorizationHeaderFieldWithOAuthCredential:(PHYOAuthCredential *)credential
{
    /// OAuth 2 "Access Token Types": http://tools.ietf.org/html/rfc6749#section-7.1
    if ([[credential.tokenType lowercaseString] isEqualToString:@"bearer"]) {
        [self setValue:[NSString stringWithFormat:@"Bearer %@", credential.accessToken] forHTTPHeaderField:@"Authorization"];
    }
}

@end
