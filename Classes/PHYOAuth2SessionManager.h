//
//  PHYOAuth2SessionManager.h
//  Argos
//
//  Created by Matt Ricketson on 5/10/14.
//  Copyright (c) 2014 Argos. All rights reserved.
//
//  Adapted from AFOAuth2Client by Mattt Thompson: https://github.com/AFNetworking/AFOAuth2Client
//

#import <AFNetworking/AFHTTPSessionManager.h>

@class PHYOAuthCredential;

/**
 `PHYOAuth2SessionManager` encapsulates common patterns to authenticate against a resource server conforming to the behavior outlined in the OAuth 2.0 specification.
 
 In your application, it is recommended that you use `PHYOAuth2SessionManager` exclusively to get an authorization token, which is then passed to another `AFHTTPSessionManager` subclass.
 
 @see RFC 6749 The OAuth 2.0 Authorization Framework: http://tools.ietf.org/html/rfc6749
 */
@interface PHYOAuth2SessionManager : AFHTTPSessionManager

///------------------------------------------
/// @name Accessing OAuth 2 Client Properties
///------------------------------------------

/**
 The service provider identifier used to store and retrieve OAuth credentials by `PHYOAuthCredential`. Equivalent to the hostname of the client `baseURL`.
 */
@property (nonatomic, readonly) NSString *serviceProviderIdentifier;

/**
 The client identifier issued by the authorization server, uniquely representing the registration information provided by the client.
 */
@property (nonatomic, readonly) NSString *clientID;

///------------------------------------------------
/// @name Creating and Initializing OAuth 2 Clients
///------------------------------------------------

/**
 Creates and initializes an `PHYOAuth2SessionManager` object with the specified base URL, client identifier, and secret.
 
 @param url The base URL for the HTTP client. This argument must not be `nil`.
 @param clientID The client identifier issued by the authorization server, uniquely representing the registration information provided by the client.
 @param secret The client secret.
 
 @return The newly-initialized OAuth 2 client
 */
+ (instancetype)managerWithBaseURL:(NSURL *)url
                          clientID:(NSString *)clientID
                            secret:(NSString *)secret;

/**
 Initializes an `PHYOAuth2SessionManager` object with the specified base URL, client identifier, and secret.
 
 @param url The base URL for the HTTP client. This argument must not be `nil`.
 @param clientID The client identifier issued by the authorization server, uniquely representing the registration information provided by the client.
 @param secret The client secret.
 
 @return The newly-initialized OAuth 2 client
 */
- (id)initWithBaseURL:(NSURL *)url
             clientID:(NSString *)clientID
               secret:(NSString *)secret;


///---------------------
/// @name Authenticating
///---------------------

/**
 Authenticates against the server using a specified username and password, with a designated scope.
 
 @param path The path to be appended to the HTTP client's base URL and used as the request URL.
 @param username The username used for authentication
 @param password The password used for authentication
 @param scope The authorization scope
 @param success A block object to be executed when the request operation finishes successfully. This block has no return value and takes a single argument: the OAuth credential returned by the server.
 @param failure A block object to be executed when the request operation finishes unsuccessfully, or that finishes successfully, but encountered an error while parsing the response data. This block has no return value and takes a single argument: the error returned from the server.
 */
- (NSURLSessionDataTask *)authenticateUsingOAuthWithURLString:(NSString *)URLString
                                                     username:(NSString *)username
                                                     password:(NSString *)password
                                                        scope:(NSString *)scope
                                                      success:(void (^)(NSURLSessionDataTask *task, PHYOAuthCredential *credential))success
                                                      failure:(void (^)(NSURLSessionDataTask *task, NSError *error))failure;

/**
 Authenticates against the server with a designated scope.
 
 @param path The path to be appended to the HTTP client's base URL and used as the request URL.
 @param scope The authorization scope
 @param success A block object to be executed when the request operation finishes successfully. This block has no return value and takes a single argument: the OAuth credential returned by the server.
 @param failure A block object to be executed when the request operation finishes unsuccessfully, or that finishes successfully, but encountered an error while parsing the response data. This block has no return value and takes a single argument: the error returned from the server.
 */
- (NSURLSessionDataTask *)authenticateUsingOAuthWithURLString:(NSString *)URLString
                                                        scope:(NSString *)scope
                                                      success:(void (^)(NSURLSessionDataTask *task, PHYOAuthCredential *credential))success
                                                      failure:(void (^)(NSURLSessionDataTask *task, NSError *error))failure;

/**
 Authenticates against the server using the specified refresh token.
 
 @param path The path to be appended to the HTTP client's base URL and used as the request URL.
 @param refreshToken The OAuth refresh token
 @param success A block object to be executed when the request operation finishes successfully. This block has no return value and takes a single argument: the OAuth credential returned by the server.
 @param failure A block object to be executed when the request operation finishes unsuccessfully, or that finishes successfully, but encountered an error while parsing the response data. This block has no return value and takes a single argument: the error returned from the server.
 */
- (NSURLSessionDataTask *)authenticateUsingOAuthWithURLString:(NSString *)URLString
                                                 refreshToken:(NSString *)refreshToken
                                                      success:(void (^)(NSURLSessionDataTask *task, PHYOAuthCredential *credential))success
                                                      failure:(void (^)(NSURLSessionDataTask *task, NSError *error))failure;

/**
 Authenticates against the server with an authorization code, redirecting to a specified URI upon successful authentication.
 
 @param path The path to be appended to the HTTP client's base URL and used as the request URL.
 @param code The authorization code
 @param redirectURI The URI to redirect to after successful authentication
 @param success A block object to be executed when the request operation finishes successfully. This block has no return value and takes a single argument: the OAuth credential returned by the server.
 @param failure A block object to be executed when the request operation finishes unsuccessfully, or that finishes successfully, but encountered an error while parsing the response data. This block has no return value and takes a single argument: the error returned from the server.
 */
- (NSURLSessionDataTask *)authenticateUsingOAuthWithURLString:(NSString *)URLString
                                                         code:(NSString *)code
                                                  redirectURI:(NSString *)uri
                                                      success:(void (^)(NSURLSessionDataTask *task, PHYOAuthCredential *credential))success
                                                      failure:(void (^)(NSURLSessionDataTask *task, NSError *error))failure;

/**
 Authenticates against the server with the specified parameters.
 
 @param path The path to be appended to the HTTP client's base URL and used as the request URL.
 @param parameters The parameters to be encoded and set in the request HTTP body.
 @param success A block object to be executed when the request operation finishes successfully. This block has no return value and takes a single argument: the OAuth credential returned by the server.
 @param failure A block object to be executed when the request operation finishes unsuccessfully, or that finishes successfully, but encountered an error while parsing the response data. This block has no return value and takes a single argument: the error returned from the server.
 */
- (NSURLSessionDataTask *)authenticateUsingOAuthWithURLString:(NSString *)URLString
                                                   parameters:(NSDictionary *)parameters
                                                      success:(void (^)(NSURLSessionDataTask *task, PHYOAuthCredential *credential))success
                                                      failure:(void (^)(NSURLSessionDataTask *task, NSError *error))failure;

@end


#pragma mark -

/**
 `PHYOAuthCredential` models the credentials returned from an OAuth server, storing the token type, access & refresh tokens, and whether the token is expired.
 
 OAuth credentials can be stored in the user's keychain, and retrieved on subsequent launches.
 */
@interface PHYOAuthCredential : NSObject <NSCoding>

///--------------------------------------
/// @name Accessing Credential Properties
///--------------------------------------

/**
 The OAuth access token.
 */
@property (nonatomic, copy, readonly) NSString *accessToken;

/**
 The OAuth token type (e.g. "bearer").
 */
@property (nonatomic, copy, readonly) NSString *tokenType;

/**
 The OAuth refresh token.
 */
@property (nonatomic, copy, readonly) NSString *refreshToken;

/**
 Whether the OAuth credentials are expired.
 */
@property (nonatomic, assign, readonly, getter = isExpired) BOOL expired;

///--------------------------------------------
/// @name Creating and Initializing Credentials
///--------------------------------------------

/**
 Create an OAuth credential from a token string, with a specified type.
 
 @param token The OAuth token string.
 @param type The OAuth token type.
 */
+ (instancetype)credentialWithOAuthToken:(NSString *)token tokenType:(NSString *)type;

/**
 Initialize an OAuth credential from a token string, with a specified type.
 
 @param token The OAuth token string.
 @param type The OAuth token type.
 */
- (id)initWithOAuthToken:(NSString *)token tokenType:(NSString *)type;

///----------------------------
/// @name Setting Refresh Token
///----------------------------

/**
 Set the credential refresh token, with a specified expiration.
 
 @param refreshToken The OAuth refresh token.
 @param expiration The expiration of the access token. This must not be `nil`.
 */
- (void)setRefreshToken:(NSString *)refreshToken expiration:(NSDate *)expiration;

///-----------------------------------------
/// @name Storing and Retrieving Credentials
///-----------------------------------------

/**
 Stores the specified OAuth credential for a given web service identifier in the Keychain.
 with the default Keychain Accessibilty of kSecAttrAccessibleWhenUnlocked.
 
 @param credential The OAuth credential to be stored.
 @param identifier The service identifier associated with the specified credential.
 
 @return Whether or not the credential was stored in the keychain.
 */
+ (BOOL)storeCredential:(PHYOAuthCredential *)credential withIdentifier:(NSString *)identifier;

/**
 Stores the specified OAuth token for a given web service identifier in the Keychain.
 
 @param token The OAuth credential to be stored.
 @param identifier The service identifier associated with the specified token.
 @param securityAccessibility The Keychain security accessibility to store the credential with.
 
 @return Whether or not the credential was stored in the keychain.
 */
+ (BOOL)storeCredential:(PHYOAuthCredential *)credential
         withIdentifier:(NSString *)identifier
      withAccessibility:(CFTypeRef)securityAccessibility;

/**
 Retrieves the OAuth credential stored with the specified service identifier from the Keychain.
 
 @param identifier The service identifier associated with the specified credential.
 
 @return The retrieved OAuth credential.
 */
+ (PHYOAuthCredential *)retrieveCredentialWithIdentifier:(NSString *)identifier;

/**
 Deletes the OAuth credential stored with the specified service identifier from the Keychain.
 
 @param identifier The service identifier associated with the specified credential.
 
 @return Whether or not the credential was deleted from the keychain.
 */
+ (BOOL)deleteCredentialWithIdentifier:(NSString *)identifier;

@end


#pragma mark -

/**
 A category on `AFHTTPRequestSerializer` that enables configuration of the HTTP Authorization header based on an OAuth credential.
 */
@interface AFHTTPRequestSerializer (PHYOAuth)

///--------------------
/// @name Authorization
///--------------------

/**
 Sets the HTTP Authorization header according to the specified OAuth credential.
 
 @discussion
 Follows the format specified in "Access Token Types": http://tools.ietf.org/html/rfc6749#section-7.1
 
 @param credential An OAuth credential.
 */
- (void)phy_setAuthorizationHeaderFieldWithOAuthCredential:(PHYOAuthCredential *)credential;

@end


///----------------
/// @name Constants
///----------------

/**
 ## OAuth Grant Types
 
 OAuth 2.0 provides several grant types, covering several different use cases. The following grant type string constants are provided:
 
 `kPHYOAuthCodeGrantType`: "authorization_code"
 `kPHYOAuthClientCredentialsGrantType`: "client_credentials"
 `kPHYOAuthPasswordCredentialsGrantType`: "password"
 `kPHYOAuthRefreshGrantType`: "refresh_token"
 */
extern NSString * const kPHYOAuthCodeGrantType;
extern NSString * const kPHYOAuthClientCredentialsGrantType;
extern NSString * const kPHYOAuthPasswordCredentialsGrantType;
extern NSString * const kPHYOAuthRefreshGrantType;
