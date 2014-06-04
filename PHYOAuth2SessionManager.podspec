Pod::Spec.new do |s|
  s.name             = "PHYOAuth2SessionManager"
  s.version          = "0.2.0"
  s.summary          = "An AFHTTPSessionManager subclass for authenticating via OAuth 2.0"
  s.homepage         = "http://phyreup.com"
  s.license          = 'MIT'
  s.author           = { "Matt Ricketson" => "matt@phyreup.com" }
  s.source           = { :git => "https://github.com/phyre-inc/PHYOAuth2SessionManager.git", :tag => s.version.to_s }
  s.social_media_url = 'https://twitter.com/phyreup'

  s.platform     = :ios, '7.0'
  s.requires_arc = true

  s.source_files = 'Classes'

  s.public_header_files = 'Classes/**/*.h'

  s.dependency 'AFNetworking'
  s.dependency 'CocoaLumberjack'
end
